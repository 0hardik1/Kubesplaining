package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// TestFindPathsContinuesThroughTraversableSink proves a sink marked Traversable
// yields both its own path and the longer chain that runs through it.
func TestFindPathsContinuesThroughTraversableSink(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes["sink:mid"] = &models.EscalationNode{
		ID: "sink:mid", IsSink: true, Traversable: true, Target: models.TargetNamespaceAdmin,
	}
	graph.Nodes["sink:end"] = &models.EscalationNode{
		ID: "sink:end", IsSink: true, Target: models.TargetClusterAdmin,
	}
	addEdge(graph, nodeID(src), "sink:mid", &models.EscalationEdge{Action: "a1"})
	addEdge(graph, "sink:mid", "sink:end", &models.EscalationEdge{Action: "a2"})

	paths := FindPaths(graph, 5)
	if len(paths) != 2 {
		t.Fatalf("want 2 paths (mid and end), got %d", len(paths))
	}
	var deepest int
	for _, p := range paths {
		if len(p.Hops) > deepest {
			deepest = len(p.Hops)
		}
	}
	if deepest != 2 {
		t.Fatalf("want a 2-hop chain through the traversable sink, deepest was %d", deepest)
	}
}

// bindingEdge is a test helper: an edge carrying binding provenance.
func bindingEdge(action, binding string) *models.EscalationEdge {
	return &models.EscalationEdge{Action: action, SourceBinding: binding, SourceRole: "some-role"}
}

// TestAlternateViaParallelBinding is the case that proves this feature is about
// remediation, not chain length. One subject is bound to cluster-admin twice, so
// cutting the first binding leaves the second and the alternate comes back at the
// SAME hop count.
func TestAlternateViaParallelBinding(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "twice", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkClusterAdmin] = &models.EscalationNode{
		ID: sinkClusterAdmin, IsSink: true, Target: models.TargetClusterAdmin,
	}
	addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "admin-a"))
	addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "admin-b"))

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	p := paths[0]
	if len(p.AlternateHops) != 1 {
		t.Fatalf("want a 1-hop alternate via the second binding, got %d hops", len(p.AlternateHops))
	}
	if p.Hops[0].SourceBinding == p.AlternateHops[0].SourceBinding {
		t.Errorf("alternate reuses the cut binding %q", p.Hops[0].SourceBinding)
	}
}

// TestAlternateViaLongerRoute covers the case the research doc framed as O3: the
// only surviving route is a genuinely longer chain through an intermediate.
func TestAlternateViaLongerRoute(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
	mid := models.SubjectRef{Kind: "ServiceAccount", Name: "mid", Namespace: "app"}
	ensureSubjectNode(graph, src)
	ensureSubjectNode(graph, mid)
	graph.Nodes[sinkClusterAdmin] = &models.EscalationNode{
		ID: sinkClusterAdmin, IsSink: true, Target: models.TargetClusterAdmin,
	}
	addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "direct"))
	addEdge(graph, nodeID(src), nodeID(mid), bindingEdge("impersonate", "detour"))
	addEdge(graph, nodeID(mid), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "mid-admin"))

	paths := FindPaths(graph, 5)
	// mid is a non-system subject, so FindPaths seeds it as its own BFS source and it
	// contributes a second, unrelated path. Only the chain rooted at src is under test.
	var p models.EscalationPath
	var found int
	for _, candidate := range paths {
		if candidate.Source.Key() == src.Key() {
			p = candidate
			found++
		}
	}
	if found != 1 {
		t.Fatalf("want exactly 1 path rooted at src, got %d (of %d total)", found, len(paths))
	}
	if len(p.Hops) != 1 {
		t.Fatalf("primary should stay the 1-hop direct route, got %d hops", len(p.Hops))
	}
	if len(p.AlternateHops) != 2 {
		t.Fatalf("want a 2-hop alternate through mid, got %d hops", len(p.AlternateHops))
	}
	if p.AlternateHops[0].Action != "impersonate" {
		t.Errorf("alternate first hop = %q, want impersonate", p.AlternateHops[0].Action)
	}
}

// TestNoAlternateWhenCutClosesEverything is the common case: one route, and cutting
// its binding closes it. The field must stay empty rather than echoing the primary.
func TestNoAlternateWhenCutClosesEverything(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "only", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkClusterAdmin] = &models.EscalationNode{
		ID: sinkClusterAdmin, IsSink: true, Target: models.TargetClusterAdmin,
	}
	addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "the-only-one"))

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	if len(paths[0].AlternateHops) != 0 {
		t.Fatalf("want no alternate, got %d hops", len(paths[0].AlternateHops))
	}
}

// TestSyntheticRootedPathSkipsCutPass proves a chain whose first hop names no
// binding is left alone. There is no binding to model cutting, so claiming an
// alternate would be meaningless.
func TestSyntheticRootedPathSkipsCutPass(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "escaper", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkNodeEscape] = &models.EscalationNode{
		ID: sinkNodeEscape, IsSink: true, Target: models.TargetNodeEscape,
	}
	// No SourceBinding: a pod-escape edge.
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape"})
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape_2"})

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	if len(paths[0].AlternateHops) != 0 {
		t.Fatalf("want no alternate for a synthetic-rooted chain, got %d hops", len(paths[0].AlternateHops))
	}
}
