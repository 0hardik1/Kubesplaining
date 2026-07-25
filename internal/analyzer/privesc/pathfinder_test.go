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

// TestAlternateIsMissedWhenTheSurvivingRouteExceedsMaxDepth pins documented
// behaviour, it does not assert a bug is correct. See the doc comments on
// models.Finding.AlternateEscalationPath and models.EscalationPath.AlternateHops:
// alternatesForSource runs on the same maxDepth as the primary search
// (pathfinder.go), so a route that survives the cut but sits just past that
// bound is indistinguishable, from the field alone, from "no such route exists".
func TestAlternateIsMissedWhenTheSurvivingRouteExceedsMaxDepth(t *testing.T) {
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
	build := func() *models.EscalationGraph {
		graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
		mid1 := models.SubjectRef{Kind: "ServiceAccount", Name: "mid1", Namespace: "app"}
		mid2 := models.SubjectRef{Kind: "ServiceAccount", Name: "mid2", Namespace: "app"}
		ensureSubjectNode(graph, src)
		ensureSubjectNode(graph, mid1)
		ensureSubjectNode(graph, mid2)
		graph.Nodes[sinkClusterAdmin] = &models.EscalationNode{
			ID: sinkClusterAdmin, IsSink: true, Target: models.TargetClusterAdmin,
		}
		// The shortest route: 1 hop, cut by removing "direct".
		addEdge(graph, nodeID(src), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "direct"))
		// The route that survives cutting "direct": 3 hops through mid1 and mid2.
		// None of these three edges name "direct", and the ban is scoped to edges
		// leaving src, so this detour is untouched by the cut.
		addEdge(graph, nodeID(src), nodeID(mid1), bindingEdge("impersonate", "detour-1"))
		addEdge(graph, nodeID(mid1), nodeID(mid2), bindingEdge("impersonate", "detour-2"))
		addEdge(graph, nodeID(mid2), sinkClusterAdmin, bindingEdge("bound_to_cluster_admin", "detour-3"))
		return graph
	}
	findSrcPath := func(t *testing.T, paths []models.EscalationPath) models.EscalationPath {
		t.Helper()
		for _, p := range paths {
			if p.Source.Key() == src.Key() {
				return p
			}
		}
		t.Fatalf("no path found rooted at %s", src.Key())
		return models.EscalationPath{}
	}

	// At depth 2, the primary 1-hop route is found and its binding is the one
	// proposed for cutting, but the surviving 3-hop detour needs depth 3 to
	// reach the sink: bfsToSinks drops queue items once len(path) >= maxDepth.
	// The alternate search shares that same bound, so it never gets past mid2.
	shallow := findSrcPath(t, FindPaths(build(), 2))
	if len(shallow.Hops) != 1 {
		t.Fatalf("want the primary to stay the 1-hop direct route, got %d hops", len(shallow.Hops))
	}
	if len(shallow.AlternateHops) != 0 {
		t.Fatalf("want no alternate at depth 2 (the surviving route needs 3 hops), got %d hops", len(shallow.AlternateHops))
	}

	// The same graph, searched deep enough to contain the surviving detour: the
	// alternate is found. Without this half, an implementation that never finds
	// any alternate would also pass the assertion above.
	deep := findSrcPath(t, FindPaths(build(), 3))
	if len(deep.AlternateHops) != 3 {
		t.Fatalf("want the 3-hop alternate once depth allows it, got %d hops", len(deep.AlternateHops))
	}
}

// TestSyntheticRootedPathSkipsCutPass proves a chain whose first hop names no
// binding is left alone. There is no binding to model cutting, so claiming an
// alternate would be meaningless.
//
// The third edge carries a binding on purpose and is what makes this test gate.
// The property under test lives in edgeCut's `edge.SourceBinding == ""` guard, and
// with only the two unstamped edges, deleting that guard left the suite green: both
// edges collapse to the same empty cut key, the ban catches both, no route survives,
// and the assertion below is reached for the wrong reason. With a stamped edge in the
// graph the mutation instead produces an alternate via "pods-crb" plus an
// operator-facing string that reads "Evaluated cut: removing this subject from the
// binding that grants hop 1" with the binding name rendered empty. That guard is what lets
// alternateCutNote promise a populated binding name (see its doc comment in
// content.go), so it needs a test that fails without it.
func TestSyntheticRootedPathSkipsCutPass(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "escaper", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkNodeEscape] = &models.EscalationNode{
		ID: sinkNodeEscape, IsSink: true, Target: models.TargetNodeEscape,
	}
	// No SourceBinding: a pod-escape edge. Inserted first, so BFS reports it as the
	// primary and the chain under test is the synthetic-rooted one.
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape"})
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape_2"})
	// Stamped, and reaching the same sink: a route that WOULD be reported as an
	// alternate if the cut pass ever keyed a cut off the unstamped primary.
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{
		Action:        "pod_create_privileged_escape",
		SourceBinding: "pods-crb",
	})

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	if paths[0].Hops[0].SourceBinding != "" {
		t.Fatalf("fixture regression: the primary must be the unstamped chain, got binding %q on hop 1",
			paths[0].Hops[0].SourceBinding)
	}
	if len(paths[0].AlternateHops) != 0 {
		t.Fatalf("want no alternate for a synthetic-rooted chain, got %d hops (%+v)",
			len(paths[0].AlternateHops), paths[0].AlternateHops)
	}
}

// buildTwoSinkCutKeyGraph builds the fixture TestAlternatesDeterministicWhenCutKeyCoversTwoSinks
// pins for determinism, and TestAlternateHopNeverSharesPrimarysCutBinding reuses for its universal
// invariant sweep: it already contains a same-length parallel-binding alternate (cluster-admin), a
// longer-detour alternate (kube-system-secrets through mid), a cut that closes its only route
// (token-mint), and a synthetic-rooted chain the cut pass must skip (other -> node-escape).
// Extracted to package scope so both tests build the identical graph rather than drifting apart.
func buildTwoSinkCutKeyGraph() *models.EscalationGraph {
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
	build := buildTwoSinkCutKeyGraph
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

	assertFindPathsStable(t, 20, "a targetID is reachable from two cut keys", func() []models.EscalationPath {
		return FindPaths(build(), 5)
	})
}

// assertFindPathsStable runs fn N times and fails at the first run whose
// JSON-marshaled []models.EscalationPath differs from the first call's result,
// quoting both. hint is appended to the failure message so each caller's own
// "why would this diverge" reasoning survives in the test output. Shared by the
// two determinism regressions in this file: one rebuilds the graph on every call
// (catching upstream BuildGraph nondeterminism and cut-key partition bugs), the
// other holds one graph fixed and calls FindPaths repeatedly (catching
// nondeterminism inside FindPaths itself, e.g. the map range at "for targetID,
// chain := range found" feeding an unstable sort).
func assertFindPathsStable(t *testing.T, n int, hint string, run func() []models.EscalationPath) {
	t.Helper()
	want, err := json.Marshal(run())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		got, err := json.Marshal(run())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("run %d diverged: %s\n want %s\n  got %s", i, hint, want, got)
		}
	}
}

// TestFindPathsStableWhenTwoSinksTieOnEveryOtherKey is the "one graph, many
// FindPaths calls" level of the task-12(a) determinism guard: even holding the
// graph fixed, FindPaths itself must return the same result every call.
//
// Two external AWS-IAM-shaped sink nodes reachable from one source at the same hop
// count tie on every key FindPaths' comparator checked before TargetID was added
// as the final tiebreak: same Source, same Target enum (every IAM role node
// carries TargetAWSIAMRole), same TargetNamespace (always empty for this target),
// same hop count. Before the fix, "for targetID, chain := range found" (a map, see
// FindPaths) appended these two paths to the pre-sort slice in a random order each
// call, and sort.Slice's documented instability let that randomness survive into
// the returned order. This is the same shape behind the audit's reproduced 26/4
// AWS IAM role split (see analyzer_test.go's two-IRSA-role fixture), tested here
// one layer down: at FindPaths itself, isolated from BuildGraph and from the
// finding-ID collapse inside Analyze's seen map.
func TestFindPathsStableWhenTwoSinksTieOnEveryOtherKey(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
	ensureSubjectNode(graph, src)

	roleOneARN := "arn:aws:iam::111111111111:role/RoleOne"
	roleTwoARN := "arn:aws:iam::222222222222:role/RoleTwo"
	roleOneID := externalAWSIAMNodeID(roleOneARN)
	roleTwoID := externalAWSIAMNodeID(roleTwoARN)
	graph.Nodes[roleOneID] = &models.EscalationNode{
		ID: roleOneID, IsSink: true, IsExternal: true, Traversable: true,
		Subject: models.SubjectRef{Kind: "User", Name: roleOneARN},
		Target:  models.TargetAWSIAMRole,
	}
	graph.Nodes[roleTwoID] = &models.EscalationNode{
		ID: roleTwoID, IsSink: true, IsExternal: true, Traversable: true,
		Subject: models.SubjectRef{Kind: "User", Name: roleTwoARN},
		Target:  models.TargetAWSIAMRole,
	}
	addEdge(graph, nodeID(src), roleOneID, &models.EscalationEdge{Action: "irsa_assume_role", Permission: roleOneARN})
	addEdge(graph, nodeID(src), roleTwoID, &models.EscalationEdge{Action: "irsa_assume_role", Permission: roleTwoARN})

	// Pin the fixture's premise before pinning its stability: without this, the
	// comparison below would pass just as happily against a fixture with only one
	// path, which cannot tie and so cannot exercise the bug.
	baseline := FindPaths(graph, 5)
	var tied int
	for _, p := range baseline {
		if p.Source.Key() == src.Key() && p.Target == models.TargetAWSIAMRole {
			tied++
		}
	}
	if tied != 2 {
		t.Fatalf("fixture does not tie: want 2 same-source aws_iam_role paths, got %d (%+v)", tied, baseline)
	}

	assertFindPathsStable(t, 20, "two AWS IAM role sinks tie on Source/Target/TargetNamespace/hop-count", func() []models.EscalationPath {
		return FindPaths(graph, 5)
	})
}

// podCreateTwoNamespaceSnapshot builds a snapshot where one ServiceAccount ("deployer",
// living in "dev") is bound by two separate RoleBindings in two different namespaces,
// each to a Role granting `create pods`, with neither target namespace carrying a Pod
// Security Admission enforce label. This is the real-BuildGraph mirror of the e2e shape
// in testdata/e2e/vulnerable/18-privesc-cut-resilient.yaml step 3: cutting either binding
// alone must leave the other standing, so the node-escape finding gains an alternate.
// Shared by TestAlternateFoundWhenSecondBindingGrantsPodCreate and
// TestAlternateHopNeverSharesPrimarysCutBinding.
func podCreateTwoNamespaceSnapshot() models.Snapshot {
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
	return snapshot
}

// TestAlternateFoundWhenSecondBindingGrantsPodCreate is the end-to-end property: with
// two bindings granting `create pods`, cutting the first must leave a surviving route,
// so the finding warns the operator instead of implying the fix is sufficient.
func TestAlternateFoundWhenSecondBindingGrantsPodCreate(t *testing.T) {
	graph := BuildGraph(podCreateTwoNamespaceSnapshot())
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

// TestCorrelationEdgeIsCutWhenOneBindingGrantsBothHalves builds the audit's exact
// shape: a stamped edge (nodes_proxy) and an unstamped correlation edge
// (node_drain_migrate) both reach the SAME sink, and the binding that grants the
// stamped edge is also the sole grantor of both halves behind the correlation edge.
// Cutting it must leave NO alternate, because removing the subject from that one
// binding genuinely closes both routes. Before the fix this produced a 1-hop
// alternate via node_drain_migrate, wrongly telling the operator their correct and
// sufficient fix was insufficient.
func TestCorrelationEdgeIsCutWhenOneBindingGrantsBothHalves(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkNodeEscape] = &models.EscalationNode{
		ID: sinkNodeEscape, IsSink: true, Target: models.TargetNodeEscape,
	}

	addEdge(graph, nodeID(src), sinkNodeEscape, bindingEdge("nodes_proxy", "node-ops-crb"))
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{
		Action:      "node_drain_migrate",
		CutBreakers: []models.BindingRef{{Name: "node-ops-crb"}},
	})

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	if len(paths[0].AlternateHops) != 0 {
		t.Fatalf("want no alternate: node-ops-crb is the sole grantor behind both edges, got %d hops (%+v)",
			len(paths[0].AlternateHops), paths[0].AlternateHops)
	}
}

// TestCSREdgeIsCutWhenOneBindingGrantsBothHalves is the same shape as
// TestCorrelationEdgeIsCutWhenOneBindingGrantsBothHalves, one sink over, and it runs
// through the real BuildGraph rather than a hand-wired graph because the defect it
// guards was in provenance collection, not in the ban predicate: the csr_approve edge
// used to record only THAT a subject held each CSR half, discarding WHICH binding
// granted it, so it reached the cut pass with no CutBreakers and could never be banned.
//
// One ClusterRole grants `impersonate users/groups` (the stamped edge that becomes the
// primary route to system:masters) plus both CSR halves, and exactly one
// ClusterRoleBinding grants it. Cutting that binding removes all three grants, so the
// csr_approve route dies with the primary and there must be NO alternate. Before the
// fix this reported a 1-hop csr_approve alternate, telling the operator their correct
// and sufficient fix was insufficient and offering, as proof, a route the fix closes.
func TestCSREdgeIsCutWhenOneBindingGrantsBothHalves(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("csr-both", "csrgap")},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta: objectMeta("csr-and-impersonate", ""),
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"users", "groups"}, Verbs: []string{"impersonate"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			},
		},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("csr-gap-only-binding", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "csr-and-impersonate"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "csr-both", Namespace: "csrgap"},
			},
		},
	}

	paths := FindPaths(BuildGraph(snapshot), 5)
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "csr-both", Namespace: "csrgap"}
	var p models.EscalationPath
	var found int
	for _, candidate := range paths {
		if candidate.Source.Key() == src.Key() && candidate.Target == models.TargetSystemMasters {
			p = candidate
			found++
		}
	}
	if found != 1 {
		t.Fatalf("want exactly 1 csr-both -> system_masters path, got %d (of %d total)", found, len(paths))
	}
	// Pin the premise: without a csr_approve edge in the graph at all, the assertion
	// below would pass for the wrong reason.
	var sawCSREdge bool
	for _, edge := range BuildGraph(snapshot).Edges {
		if edge.Action == "csr_approve" {
			sawCSREdge = true
			if len(edge.CutBreakers) == 0 {
				t.Errorf("csr_approve edge carries no CutBreakers, so no cut can ever ban it: %+v", *edge)
			}
		}
	}
	if !sawCSREdge {
		t.Fatal("fixture built no csr_approve edge; the cut pass has nothing to skip (fixture regression, not a pass)")
	}
	if len(p.AlternateHops) != 0 {
		t.Fatalf("want no alternate: csr-gap-only-binding is the sole grantor behind both routes, got %d hops (%+v)",
			len(p.AlternateHops), p.AlternateHops)
	}
}

// buildUnstampedAlternateGraph gives TestAlternateHopNeverSharesPrimarysCutBinding the
// case the task brief's second note warns about: an alternate whose own first hop
// carries NO SourceBinding at all. src reaches node_escape two ways: a stamped edge
// ("cut-me") inserted first, which BFS keeps as the shortest/primary route, and an
// unstamped pod_host_escape edge inserted second. The cut-resilient rerun bans only
// "cut-me" (banned is scoped to edges leaving src), so it falls through to the
// unstamped edge. That unstamped alternate must not be flagged: it carries no binding
// to compare against the primary's, and Task 9's CutBreakers-only correlation edges are
// exactly this shape in production.
func buildUnstampedAlternateGraph() *models.EscalationGraph {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "escapee", Namespace: "ops"}
	ensureSubjectNode(graph, src)
	graph.Nodes[sinkNodeEscape] = &models.EscalationNode{ID: sinkNodeEscape, IsSink: true, Target: models.TargetNodeEscape}
	addEdge(graph, nodeID(src), sinkNodeEscape, bindingEdge("nodes_proxy", "cut-me"))
	addEdge(graph, nodeID(src), sinkNodeEscape, &models.EscalationEdge{Action: "pod_host_escape"})
	return graph
}

// TestAlternateHopNeverSharesPrimarysCutBinding is the universal invariant the whole
// cut-resilient feature depends on: for EVERY path FindPaths returns with a non-empty
// alternate, not one hand-picked path, the alternate's first hop must not be the very
// binding the primary's first hop names. That binding is exactly what the printed
// remediation removes the subject from, so an alternate riding it would tell the
// operator their fix is insufficient while showing them, as proof, a route the fix
// actually closes.
//
// Three fixtures, reused from elsewhere in this file rather than invented fresh, cover
// the shapes the task brief calls out by name: buildTwoSinkCutKeyGraph exercises both a
// same-length parallel-binding alternate and a longer detour alternate in one graph;
// buildUnstampedAlternateGraph exercises the legitimate empty-alternate-binding case;
// podCreateTwoNamespaceSnapshot exercises the real BuildGraph builder path (not a
// hand-wired graph) that Step 3 of the task turns into an e2e fixture.
func TestAlternateHopNeverSharesPrimarysCutBinding(t *testing.T) {
	var paths []models.EscalationPath
	paths = append(paths, FindPaths(buildTwoSinkCutKeyGraph(), 5)...)
	paths = append(paths, FindPaths(buildUnstampedAlternateGraph(), 5)...)
	paths = append(paths, FindPaths(BuildGraph(podCreateTwoNamespaceSnapshot()), 5)...)

	checked := assertNoAlternateReusesPrimarysCutBinding(t, paths)
	if checked == 0 {
		t.Fatal("no path in the fixture carried an alternate; the invariant went unchecked (fixture regression, not a pass)")
	}
}

// assertNoAlternateReusesPrimarysCutBinding walks every path in paths and, for each one
// carrying a non-empty AlternateHops, asserts that the alternate's first hop did not
// survive by riding the same binding the primary's first hop names. Returns the number
// of alternate-bearing paths it checked, so a caller can refuse to pass vacuously when a
// fixture regression silently drops every alternate.
//
// An empty AlternateHops[0].SourceBinding is NOT a violation: Task 9's correlation edges
// (CutBreakers) carry no SourceBinding by design, and alternatesForSource can legitimately
// surface an edge like that once the cut removes everything stamped with the cut binding.
// See buildUnstampedAlternateGraph. Hops[0].SourceBinding on the PRIMARY, by contrast, is
// verified non-empty here rather than assumed: alternatesForSource only ever populates
// targetsByCut from a chain whose first edge has binding provenance (edgeCut requires
// SourceBinding != ""), so a primary with an alternate but no first-hop binding would mean
// that guarantee broke upstream, which is worth failing loudly on rather than silently.
func assertNoAlternateReusesPrimarysCutBinding(t *testing.T, paths []models.EscalationPath) int {
	t.Helper()
	var checked int
	for _, p := range paths {
		if len(p.AlternateHops) == 0 {
			continue
		}
		checked++
		primary := p.Hops[0]
		alternate := p.AlternateHops[0]
		if primary.SourceBinding == "" {
			t.Fatalf("path %s -> %s (namespace %q) has an alternate but an unstamped primary first hop (action %q): alternatesForSource should never key a cut off an edge with no binding",
				p.Source.Key(), p.Target, p.TargetNamespace, primary.Action)
		}
		if alternate.SourceBinding == "" {
			// Legitimate: the alternate's first hop names no binding, so the primary's
			// cut (which removes the subject from ONE named binding) cannot have been
			// what left this route standing, nor could it be what closes it.
			continue
		}
		if alternate.SourceBinding == primary.SourceBinding && alternate.BindingNamespace == primary.BindingNamespace {
			t.Errorf("path %s -> %s: alternate hop 1 (%s, binding %q/%q) shares its binding with primary hop 1 (%s): the fix that cuts the primary would ALSO close this alternate",
				p.Source.Key(), p.Target, alternate.Action, alternate.SourceBinding, alternate.BindingNamespace, primary.Action)
		}
	}
	return checked
}
