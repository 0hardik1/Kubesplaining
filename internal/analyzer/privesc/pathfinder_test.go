package privesc

import (
	"encoding/json"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	// mid's edge reuses the binding name "direct" on purpose, and must keep reusing it.
	// The ban is scoped to edges leaving the source because remediation drops the subject
	// from the binding and leaves the binding intact for everyone else. Cutting src's
	// "direct" therefore has to leave mid's alone, so the 2-hop alternate survives. Give
	// this edge a unique name and the source scoping goes untested: a whole-binding ban
	// would then look identical here, while under-reporting alternates in the real graph.
	addEdge(graph, nodeID(mid), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "direct"))

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

// TestAlternatesDeterministicWhenCutKeyCoversTwoSinks guards the one property that
// makes alternatesForSource safe to write with a map.
//
// targetsByCut is a Go map, so `range` visits its cut keys in a random order that
// differs run to run. That is safe only because the buckets partition the target
// set: each targetID is filed under exactly one cutKey, the one named by its OWN
// first hop, so no banned run can overwrite the answer another run produced. If
// that one-to-one property ever breaks, two runs start competing to write the same
// targetID and the output becomes order-dependent, which surfaces downstream as
// e2e goldens flapping intermittently: an expensive failure to trace back here.
//
// The fixture below is the case where such a mistake actually shows up. Cut key
// "bind-a" covers TWO sinks that must receive DIFFERENT answers (cluster-admin gets
// a same-length alternate via the parallel binding "bind-a2"; kube-system-secrets
// gets a longer detour through mid), alongside a sink whose route dies with its cut
// and a synthetic-rooted chain that skips the pass. Tests with a single sink per
// source cannot catch it.
//
// If this test ever flakes, the property has been broken. Restore it. Do NOT add a
// sort to paper over the symptom: needing one means the structure changed.
func TestAlternatesDeterministicWhenCutKeyCoversTwoSinks(t *testing.T) {
	build := func() *models.EscalationGraph {
		graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
		src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
		mid := models.SubjectRef{Kind: "ServiceAccount", Name: "mid", Namespace: "app"}
		other := models.SubjectRef{Kind: "ServiceAccount", Name: "other", Namespace: "app"}
		ensureSubjectNode(graph, src)
		ensureSubjectNode(graph, mid)
		ensureSubjectNode(graph, other)
		for _, sink := range []struct {
			id     string
			target models.EscalationTarget
		}{
			{sinkClusterAdmin, models.TargetClusterAdmin},
			{sinkKubeSystemSecrets, models.TargetKubeSystemSecrets},
			{sinkTokenMint, models.TargetTokenMint},
			{sinkNodeEscape, models.TargetNodeEscape},
		} {
			graph.Nodes[sink.id] = &models.EscalationNode{ID: sink.id, IsSink: true, Target: sink.target}
		}

		// Cut key "bind-a" covers two sinks with different answers.
		addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "bind-a"))
		addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "bind-a2"))
		addEdge(graph, nodeID(src), sinkKubeSystemSecrets, bindingEdge("read_secrets", "bind-a"))
		addEdge(graph, nodeID(src), nodeID(mid), bindingEdge("impersonate", "bind-c"))
		addEdge(graph, nodeID(mid), sinkKubeSystemSecrets, bindingEdge("read_secrets", "mid-secrets"))

		// Cut key "bind-b": the cut closes this route outright.
		addEdge(graph, nodeID(src), sinkTokenMint, bindingEdge("token_mint", "bind-b"))

		// No SourceBinding: the cut pass must skip this chain entirely.
		addEdge(graph, nodeID(other), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape"})
		return graph
	}

	baseline := FindPaths(build(), 5)

	// Pin the fixture's premise before pinning its stability. Without this, the
	// comparison below would pass just as happily against an implementation that
	// populates no alternates at all: stable emptiness is still stable.
	altHops := func(target models.EscalationTarget) int {
		for _, p := range baseline {
			if p.Source.Name == "src" && p.Target == target {
				return len(p.AlternateHops)
			}
		}
		t.Fatalf("no path from src to %s in the fixture", target)
		return 0
	}
	if n := altHops(models.TargetClusterAdmin); n != 1 {
		t.Fatalf("cluster-admin should keep a 1-hop alternate via bind-a2, got %d hops", n)
	}
	if n := altHops(models.TargetKubeSystemSecrets); n != 2 {
		t.Fatalf("kube-system-secrets should get a 2-hop detour through mid, got %d hops", n)
	}
	if n := altHops(models.TargetTokenMint); n != 0 {
		t.Fatalf("token-mint's cut closes its only route, want no alternate, got %d hops", n)
	}

	want, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(FindPaths(build(), 5))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("run %d diverged, so a targetID is reachable from two cut keys\n want %s\n  got %s", i, want, got)
		}
	}
}

// TestAlternateFoundWhenSecondBindingGrantsPodCreate is the end-to-end property: with
// two bindings granting `create pods`, cutting the first must leave a surviving route,
// so the finding warns the operator instead of implying the fix is sufficient.
func TestAlternateFoundWhenSecondBindingGrantsPodCreate(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("team-a", "")},
		{ObjectMeta: objectMeta("team-b", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("deployer", "dev")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: objectMeta("pod-creator-a", "team-a"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
		{
			ObjectMeta: objectMeta("pod-creator-b", "team-b"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: objectMeta("deploy-a", "team-a"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator-a"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
		{
			ObjectMeta: objectMeta("deploy-b", "team-b"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator-b"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
	}

	graph := BuildGraph(snapshot)
	paths := FindPaths(graph, 5)

	deployer := models.SubjectRef{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"}
	var found int
	var p models.EscalationPath
	for _, candidate := range paths {
		if candidate.Source.Key() == deployer.Key() && candidate.Target == models.TargetNodeEscape {
			p = candidate
			found++
		}
	}
	if found != 1 {
		t.Fatalf("want exactly 1 deployer -> node_escape path, got %d (of %d total)", found, len(paths))
	}
	if len(p.AlternateHops) != 1 {
		t.Fatalf("want a 1-hop alternate via the second binding, got %d hops (path=%+v)", len(p.AlternateHops), p)
	}
	if p.AlternateHops[0].SourceBinding == p.Hops[0].SourceBinding {
		t.Errorf("alternate reuses the cut binding %q", p.Hops[0].SourceBinding)
	}
}
