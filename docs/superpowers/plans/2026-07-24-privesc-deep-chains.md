# Deep-Chain Privilege Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the privesc graph express real 4-to-6 hop escalation chains, score them by how hard they are to walk rather than how long they are, and assert their shape in e2e.

**Architecture:** Five changes to `internal/analyzer/privesc/`, in dependency order. A new `Traversable` flag on graph nodes lets a node be both a sink and an intermediate, which unlocks namespace-admin and control-plane-node continuation. Splitting the overloaded `IsSystem` flag lets kube-system controller ServiceAccounts act as intermediates without becoming BFS sources. A catalog-driven confused-deputy edge family bridges operator-CRD writers to their reconciling controller. Scoring moves from raw hop-count attenuation to a per-edge difficulty model.

**Tech Stack:** Go 1.26, `k8s.io/api` v0.36.x, cobra CLI, kind + kubectl + jq for e2e. All tooling is Hermit-pinned under `bin/`.

## Global Constraints

- **No em dashes** in any output: code comments, docs, commit messages, fixture comments. Use a colon, comma, parentheses, or two sentences.
- **No Claude session links** in commit messages or PR descriptions.
- Rule IDs are a public surface. New ID this plan introduces: `KUBE-CONFUSED-DEPUTY-001`. No others.
- New privesc action slugs this plan introduces: `colocated_sa_token_theft`, `control_plane_pki_theft`, `static_pod_admission_bypass`, `operator_reconcile`. Every one needs a `Techniques[slug]` entry in `internal/report/glossary.go` or the report silently drops its explainer card.
- The collector is the only component that talks to the Kubernetes API. Analyzers consume `models.Snapshot` and make no network calls. This plan adds **no** collector changes.
- Package doc comments head each `package foo` file. Test files sit alongside code as `foo_test.go`, table-driven.
- Build/test commands route through the `Makefile`, which pins `GOCACHE` / `GOMODCACHE` under `.tmp/`. For single-package runs use:
  `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/...`
- Before any commit: `make lint` AND `./bin/golangci-lint run ./...` (the latter is a CI gate `make lint` does not cover).
- Conventional Commits enforced by the `commit-msg` hook. PR title must be 72 characters or fewer.

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `internal/models/escalation.go` | Graph vocabulary | Modify: add `Traversable`, `IsControlPlane` to `EscalationNode`; add `Difficulty` to `EscalationEdge` |
| `internal/models/finding.go` | Finding vocabulary | Modify: add `Difficulty` to `EscalationHop` |
| `internal/analyzer/privesc/pathfinder.go` | BFS | Modify: traversable sinks, control-plane source exclusion |
| `internal/analyzer/privesc/graph.go` | Edge builders | Modify: flag split, namespace-admin edges, control-plane continuation, central difficulty assignment |
| `internal/analyzer/privesc/deputy.go` | Confused-deputy catalog and edges | **Create** |
| `internal/analyzer/privesc/deputy_test.go` | Catalog tests | **Create** |
| `internal/analyzer/privesc/pathfinder_test.go` | BFS tests | **Create** |
| `internal/analyzer/privesc/analyzer.go` | Path to Finding | Modify: difficulty scoring, confused-deputy rule-ID overlay |
| `internal/report/glossary.go` | Educational copy | Modify: four new `Techniques` entries |
| `docs/findings.md` | Authoritative rule catalog | Modify: add `KUBE-CONFUSED-DEPUTY-001` |
| `scripts/kind-e2e.sh` | e2e harness | Modify: new `*.chain` assertion type |
| `testdata/e2e/vulnerable/17-privesc-deep-chains.yaml` | Deep-chain fixture | **Create** |
| `testdata/e2e/expectations/deep-chains.expect` | Rule-ID recall | **Create** |
| `testdata/e2e/expectations/deep-chains.chain` | Chain-shape assertions | **Create** |
| `testdata/e2e/expectations/{full,minimal}-scan.ruleset` | Set-equality goldens | Regenerate |

---

### Task 1: Traversable sinks

Generalize the pathfinder's one-off `IsExternal` exception into a reusable flag. Behavior-preserving: no finding changes.

**Files:**
- Modify: `internal/models/escalation.go:22-32`
- Modify: `internal/analyzer/privesc/pathfinder.go:113-126`
- Modify: `internal/analyzer/privesc/cloud_edges.go` (external node construction)
- Test: `internal/analyzer/privesc/pathfinder_test.go` (create)

**Interfaces:**
- Produces: `models.EscalationNode.Traversable bool`. Set on any sink whose outbound edges BFS should keep following. Consumed by Tasks 3 and 4.

- [ ] **Step 1: Write the failing test**

Create `internal/analyzer/privesc/pathfinder_test.go`:

```go
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestFindPathsContinuesThroughTraversableSink -v`

Expected: FAIL. `Traversable` is not a field on `models.EscalationNode`, so this is a compile error.

- [ ] **Step 3: Add the field**

In `internal/models/escalation.go`, inside `EscalationNode`, after the `IsSink` field:

```go
	// Traversable marks a sink that BFS should keep walking past rather than
	// halting on. A traversable sink still produces its own path finding; it
	// additionally lets longer chains run through it (namespace-admin implying
	// token theft in that namespace, node-root implying control-plane PKI theft,
	// an external cloud identity implying a return route into the cluster).
	Traversable bool `json:"traversable,omitempty"`
```

- [ ] **Step 4: Generalize the pathfinder check**

In `internal/analyzer/privesc/pathfinder.go`, replace the block at lines 117-125 (the comment plus `if !neighbor.IsExternal { continue }`) with:

```go
				// A traversable sink records its own path and is then walked past,
				// so richer chains that route through it are also captured.
				// Non-traversable sinks have no outbound edges by construction.
				if !neighbor.Traversable {
					continue
				}
```

- [ ] **Step 5: Mark external cloud nodes traversable**

In `internal/analyzer/privesc/cloud_edges.go`, find where the external node is constructed with `IsExternal: true, IsSink: true` and add `Traversable: true` to the same literal. Grep for it:

Run: `./bin/rg -n "IsExternal:\s*true" internal/analyzer/privesc/cloud_edges.go`

- [ ] **Step 6: Run the new test and the full package**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... -v 2>&1 | tail -30`

Expected: the new test PASSes and every pre-existing test in the package still passes. The aws-auth chain tests in `cloud_edges_test.go` are the regression guard for Step 5: if they fail, `Traversable` was not set on the external node.

- [ ] **Step 7: Commit**

```bash
git add internal/models/escalation.go internal/analyzer/privesc/pathfinder.go \
        internal/analyzer/privesc/cloud_edges.go internal/analyzer/privesc/pathfinder_test.go
git commit -m "refactor(privesc): generalize traversable-sink BFS handling"
```

---

### Task 2: Split IsSystem into IsSystem and IsControlPlane

`isSystemSubject` conflates two conditions and the resulting flag does two jobs (blocking sources and blocking intermediate hops). Split so kube-system controller ServiceAccounts become traversable intermediates while still never seeding a search.

**Files:**
- Modify: `internal/models/escalation.go` (`EscalationNode`)
- Modify: `internal/analyzer/privesc/graph.go:597-622`
- Modify: `internal/analyzer/privesc/pathfinder.go:24-36`
- Test: `internal/analyzer/privesc/graph_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `models.EscalationNode.IsControlPlane bool`; `isControlPlaneSubject(models.SubjectRef) bool` in `graph.go`. `isSystemSubject` narrows to the `system:` name-prefix test only.

- [ ] **Step 1: Write the failing test**

Append to `internal/analyzer/privesc/graph_test.go`:

```go
// TestControlPlaneSAIsTraversableButNotASource proves a non-system kube-system
// ServiceAccount can serve as a chain intermediate while never seeding a search.
func TestControlPlaneSAIsTraversableButNotASource(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	addSink(graph, sinkClusterAdmin, models.TargetClusterAdmin)

	tenant := models.SubjectRef{Kind: "ServiceAccount", Name: "tenant", Namespace: "app"}
	controller := models.SubjectRef{Kind: "ServiceAccount", Name: "some-controller", Namespace: "kube-system"}
	builtin := models.SubjectRef{Kind: "ServiceAccount", Name: "system:kube-scheduler", Namespace: "kube-system"}
	ensureSubjectNode(graph, tenant)
	ensureSubjectNode(graph, controller)
	ensureSubjectNode(graph, builtin)

	if graph.Nodes[nodeID(controller)].IsSystem {
		t.Fatal("a non-system kube-system SA must not be flagged IsSystem")
	}
	if !graph.Nodes[nodeID(controller)].IsControlPlane {
		t.Fatal("a non-system kube-system SA must be flagged IsControlPlane")
	}
	if !graph.Nodes[nodeID(builtin)].IsSystem {
		t.Fatal("a system: prefixed subject must stay IsSystem")
	}

	addEdge(graph, nodeID(tenant), nodeID(controller), &models.EscalationEdge{Action: "pod_create_token_theft"})
	addEdge(graph, nodeID(controller), sinkClusterAdmin, &models.EscalationEdge{Action: "bound_to_cluster_admin"})

	paths := FindPaths(graph, 5)
	if len(paths) != 1 {
		t.Fatalf("want exactly 1 path (tenant only; the controller must not seed), got %d", len(paths))
	}
	if paths[0].Source.Name != "tenant" {
		t.Fatalf("want source tenant, got %s", paths[0].Source.Name)
	}
	if len(paths[0].Hops) != 2 {
		t.Fatalf("want a 2-hop chain through the controller, got %d", len(paths[0].Hops))
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestControlPlaneSAIsTraversableButNotASource -v`

Expected: FAIL, compile error on the missing `IsControlPlane` field.

- [ ] **Step 3: Add the model field**

In `internal/models/escalation.go`, inside `EscalationNode`, after `IsSystem`:

```go
	// IsControlPlane marks a non-built-in ServiceAccount living in a control-plane
	// namespace (kube-system, kube-public, kube-node-lease). Unlike IsSystem these
	// ARE traversed as chain intermediates, because a co-located controller SA is
	// exactly what a real escalation launders through. They are still never seeded
	// as BFS sources, which would report the control plane escalating to itself.
	IsControlPlane bool `json:"is_control_plane,omitempty"`
```

- [ ] **Step 4: Split the predicate**

In `internal/analyzer/privesc/graph.go`, replace `isSystemSubject` (lines 609-622, including its doc comment) with:

```go
// isSystemSubject flags built-in control-plane identities by name prefix. These are
// never traversed and never seeded: laundering a chain through the control plane's
// own identities is a modeling artifact rather than an attack.
//
// Note: external cloud-IAM nodes carry IDs prefixed "external:aws-iam:" (see
// cloud_edges.go) and never flow through ensureSubjectNode, so isSystemSubject
// is never asked about them.
func isSystemSubject(ref models.SubjectRef) bool {
	return strings.HasPrefix(ref.Name, "system:")
}

// isControlPlaneSubject flags a non-built-in ServiceAccount in a control-plane
// namespace. These are traversable intermediates but not BFS sources; see the
// IsControlPlane doc comment in models.EscalationNode for the reasoning.
func isControlPlaneSubject(ref models.SubjectRef) bool {
	if isSystemSubject(ref) || ref.Kind != "ServiceAccount" {
		return false
	}
	switch ref.Namespace {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}
```

- [ ] **Step 5: Populate the new flag**

In `ensureSubjectNode` (`graph.go:597-607`), extend the node literal:

```go
	graph.Nodes[id] = &models.EscalationNode{
		ID:             id,
		Subject:        ref,
		IsSystem:       isSystemSubject(ref),
		IsControlPlane: isControlPlaneSubject(ref),
	}
```

- [ ] **Step 6: Exclude control-plane subjects from the source set**

In `internal/analyzer/privesc/pathfinder.go`, in the source-selection loop, after the `node.IsSink || node.IsSystem` check add:

```go
		// Control-plane controller SAs are traversable intermediates (see
		// models.EscalationNode.IsControlPlane) but seeding them as sources would
		// report the control plane escalating to itself on every cluster.
		if node.IsControlPlane {
			continue
		}
```

Leave the traversal-side check (`if neighbor.IsSystem { continue }`) untouched. That asymmetry is the whole point of the split.

- [ ] **Step 7: Run the package tests**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... 2>&1 | tail -20`

Expected: PASS. If a pre-existing test breaks, read it before changing it: a kube-system SA that used to terminate a search now traverses, which may legitimately add a path. Confirm the new path is correct before updating the expectation.

- [ ] **Step 8: Run the full suite and the corpus gate**

Run: `make test 2>&1 | tail -20 && make corpus 2>&1 | tail -20`

Expected: both green. `make corpus` is the precision/recall gate; a drop here means the split introduced false positives.

- [ ] **Step 9: Commit**

```bash
git add internal/models/escalation.go internal/analyzer/privesc/graph.go \
        internal/analyzer/privesc/pathfinder.go internal/analyzer/privesc/graph_test.go
git commit -m "feat(privesc): traverse control-plane SAs as chain intermediates"
```

---

### Task 3: Namespace-admin token-theft continuation

Namespace-admin over X implies stealing any ServiceAccount token living in X.

**Files:**
- Modify: `internal/analyzer/privesc/graph.go` (`ensureNamespaceAdminSink`, `BuildGraph`)
- Test: `internal/analyzer/privesc/graph_test.go`

**Interfaces:**
- Consumes: `Traversable` (Task 1).
- Produces: action slug `colocated_sa_token_theft`, technique `KUBE-PRIVESC-010`. Consumed by Task 7 (glossary) and Task 8 (e2e chain assertion).

- [ ] **Step 1: Write the failing test**

Append to `internal/analyzer/privesc/graph_test.go`:

```go
// TestNamespaceAdminReachesColocatedServiceAccounts proves the namespace-admin
// sink is walked past into the ServiceAccounts that live in that namespace.
func TestNamespaceAdminReachesColocatedServiceAccounts(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "powerful", Namespace: "tenant"}},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: metav1.ObjectMeta{Name: "binder", Namespace: "tenant"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"rolebindings"},
			Verbs:     []string{"create"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "binder-rb", Namespace: "tenant"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "binder"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "attacker", Namespace: "tenant"}},
	}}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "powerful-crb"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "powerful", Namespace: "tenant"}},
	}}

	graph := BuildGraph(snapshot)
	paths := FindPaths(graph, 5)

	var found bool
	for _, p := range paths {
		if p.Source.Name != "attacker" || p.Target != models.TargetClusterAdmin {
			continue
		}
		if len(p.Hops) >= 3 && p.Hops[1].Action == "colocated_sa_token_theft" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want attacker -> namespace_admin -> colocated SA -> cluster_admin; paths: %+v", paths)
	}
}
```

Ensure the test file imports `corev1 "k8s.io/api/core/v1"`, `rbacv1 "k8s.io/api/rbac/v1"`, and `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"`.

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestNamespaceAdminReachesColocatedServiceAccounts -v`

Expected: FAIL, "want attacker -> namespace_admin -> ...". The sink is currently terminal.

- [ ] **Step 3: Mark the sink traversable**

In `ensureNamespaceAdminSink` (`graph.go:583-594`), add `Traversable: true` to the node literal.

- [ ] **Step 4: Add the continuation builder**

Add to `graph.go`:

```go
// addNamespaceAdminTokenTheftEdges links each namespace-admin sink onward to every
// ServiceAccount living in that namespace. Namespace-admin over X means the holder
// can create a pod as any SA in X, exec into its pods, or read its token Secret, so
// every co-located identity is effectively theirs. Iteration is over a sorted key
// list so edge order stays deterministic across runs.
func addNamespaceAdminTokenTheftEdges(graph *models.EscalationGraph, subjectsByNs map[string][]models.SubjectRef) {
	sinkIDs := make([]string, 0, len(graph.Nodes))
	for id, node := range graph.Nodes {
		if node.IsSink && node.Target == models.TargetNamespaceAdmin {
			sinkIDs = append(sinkIDs, id)
		}
	}
	sort.Strings(sinkIDs)

	for _, sinkID := range sinkIDs {
		namespace := graph.Nodes[sinkID].TargetNamespace
		for _, target := range subjectsByNs[namespace] {
			ensureSubjectNode(graph, target)
			addEdge(graph, sinkID, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-010",
				Action:      "colocated_sa_token_theft",
				Permission:  "namespace-admin in " + namespace,
				Description: fmt.Sprintf("can steal the token of co-located ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}
}
```

Add `"sort"` to the import block.

- [ ] **Step 5: Call it from BuildGraph**

In `BuildGraph`, immediately after `finalizeCSRApprovals(graph, csrCapabilities)`:

```go
	// Runs after the per-subject loop so every namespace-admin sink that any
	// subject reaches already exists as a node.
	addNamespaceAdminTokenTheftEdges(graph, subjectsByNs)
```

- [ ] **Step 6: Run the tests**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... 2>&1 | tail -20`

Expected: PASS.

- [ ] **Step 7: Check the corpus gate**

Run: `make corpus 2>&1 | tail -20`

Expected: precision and recall still 1.0 on both cases. This edge fans out to every SA in a namespace, so it is the most likely of the new families to over-fire. If precision drops, read the new findings before adjusting: the fix is to narrow the fan-out (for example skip SAs no pod mounts and that hold no bindings), not to loosen the corpus labels.

- [ ] **Step 8: Commit**

```bash
git add internal/analyzer/privesc/graph.go internal/analyzer/privesc/graph_test.go
git commit -m "feat(privesc): chain namespace-admin into co-located SA token theft"
```

---

### Task 4: Control-plane node escape continuation

Node root on a control-plane node yields the cluster CA key and the SA signing key. Gate the continuation on a schedulable control-plane node actually existing in the snapshot.

**Files:**
- Modify: `internal/analyzer/privesc/graph.go` (`BuildGraph`, new helpers)
- Test: `internal/analyzer/privesc/graph_test.go`

**Interfaces:**
- Consumes: `Traversable` (Task 1).
- Produces: `clusterHasSchedulableControlPlaneNode(models.Snapshot) bool`; action slugs `control_plane_pki_theft` (to `sinkSystemMasters`) and `static_pod_admission_bypass` (to `sinkTokenMint`), both technique `KUBE-ESCAPE-CONTROLPLANE-001`. Consumed by Task 7 (glossary) and Task 8.

Note on the technique string: `KUBE-ESCAPE-CONTROLPLANE-001` labels the *edge*, matching how `addPodEscapeEdges` labels its edge `KUBE-ESCAPE`. It is not a new emitted rule ID, so it does not appear in the `*.ruleset` goldens.

- [ ] **Step 1: Write the failing test**

Append to `internal/analyzer/privesc/graph_test.go`:

```go
// TestControlPlaneNodeEscapeContinuation proves node-root continues to system:masters
// only when a schedulable control-plane node exists in the snapshot.
func TestControlPlaneNodeEscapeContinuation(t *testing.T) {
	cpNode := func(taints []corev1.Taint) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "cp-0",
				Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			},
			Spec: corev1.NodeSpec{Taints: taints},
		}
	}

	tests := []struct {
		name  string
		nodes []corev1.Node
		want  bool
	}{
		{"schedulable control plane", []corev1.Node{cpNode(nil)}, true},
		{"tainted control plane", []corev1.Node{cpNode([]corev1.Taint{{
			Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule,
		}})}, false},
		{"workers only", []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "w-0"}}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := models.Snapshot{}
			snapshot.Resources.Nodes = tc.nodes
			snapshot.Resources.Pods = []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "escaper", Namespace: "app"},
				Spec: corev1.PodSpec{
					ServiceAccountName: "escaper-sa",
					HostPID:            true,
				},
			}}

			graph := BuildGraph(snapshot)
			paths := FindPaths(graph, 5)

			var reachedMasters bool
			for _, p := range paths {
				if p.Target == models.TargetSystemMasters {
					reachedMasters = true
				}
			}
			if reachedMasters != tc.want {
				t.Fatalf("system:masters reachable = %v, want %v", reachedMasters, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestControlPlaneNodeEscapeContinuation -v`

Expected: FAIL on the "schedulable control plane" subtest. `node_escape` is terminal today.

- [ ] **Step 3: Write the gate helper**

Add to `graph.go`:

```go
// controlPlaneRoleLabels are the node labels that mark a control-plane node. The
// legacy "master" label is still present on clusters upgraded from pre-1.24.
var controlPlaneRoleLabels = []string{
	"node-role.kubernetes.io/control-plane",
	"node-role.kubernetes.io/master",
}

// clusterHasSchedulableControlPlaneNode reports whether the snapshot contains a
// control-plane node that ordinary workloads can land on, meaning it carries no
// NoSchedule taint for its control-plane role. This gates the node-escape
// continuation: on a properly tainted multi-node cluster an escaping tenant pod
// reaches a worker node, where no cluster PKI lives, so continuing to
// system:masters would be a false positive. Single-node clusters (kind, k3s,
// minikube, many dev clusters) leave the control-plane node schedulable, and
// there node root really is cluster-admin.
func clusterHasSchedulableControlPlaneNode(snapshot models.Snapshot) bool {
	for _, node := range snapshot.Resources.Nodes {
		if !isControlPlaneNode(node) {
			continue
		}
		if !hasControlPlaneNoScheduleTaint(node) {
			return true
		}
	}
	return false
}

// isControlPlaneNode reports whether a node carries a control-plane role label.
func isControlPlaneNode(node corev1.Node) bool {
	for _, label := range controlPlaneRoleLabels {
		if _, ok := node.Labels[label]; ok {
			return true
		}
	}
	return false
}

// hasControlPlaneNoScheduleTaint reports whether a node repels ordinary workloads
// via a NoSchedule (or NoExecute) taint on its control-plane role key.
func hasControlPlaneNoScheduleTaint(node corev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if !slices.Contains(controlPlaneRoleLabels, taint.Key) {
			continue
		}
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Write the continuation builder**

Add to `graph.go`:

```go
// addControlPlaneEscapeEdges makes the node_escape sink traversable and links it
// onward, but only when a schedulable control-plane node exists. Root on such a
// node reads /etc/kubernetes/pki/ca.key (forge an O=system:masters client cert
// offline) and sa.key (forge a token for any ServiceAccount), and can drop a file
// into /etc/kubernetes/manifests to run a static pod that no admission controller
// ever sees.
func addControlPlaneEscapeEdges(graph *models.EscalationGraph, snapshot models.Snapshot) {
	if !clusterHasSchedulableControlPlaneNode(snapshot) {
		return
	}
	node, ok := graph.Nodes[sinkNodeEscape]
	if !ok {
		return
	}
	node.Traversable = true

	addEdge(graph, sinkNodeEscape, sinkSystemMasters, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE-CONTROLPLANE-001",
		Action:      "control_plane_pki_theft",
		Permission:  "root on a schedulable control-plane node",
		Description: "can read /etc/kubernetes/pki/ca.key and forge an O=system:masters client certificate offline",
	})
	addEdge(graph, sinkNodeEscape, sinkTokenMint, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE-CONTROLPLANE-001",
		Action:      "static_pod_admission_bypass",
		Permission:  "write access to /etc/kubernetes/manifests",
		Description: "can read sa.key to forge any ServiceAccount token, and drop static pods that bypass all admission control",
	})
}
```

- [ ] **Step 5: Call it from BuildGraph**

In `BuildGraph`, after the pod-escape loop and before `addCloudEdges(graph, snapshot)`:

```go
	addControlPlaneEscapeEdges(graph, snapshot)
```

Confirm `slices` and `corev1` are already imported in `graph.go`. Both are.

- [ ] **Step 6: Run the tests**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... 2>&1 | tail -20`

Expected: PASS.

- [ ] **Step 7: Run the full suite and corpus**

Run: `make test 2>&1 | tail -10 && make corpus 2>&1 | tail -20`

Expected: green. The corpus snapshots have no Nodes, so the gate returns false and nothing changes there. That is the intended proof the gate is real.

- [ ] **Step 8: Commit**

```bash
git add internal/analyzer/privesc/graph.go internal/analyzer/privesc/graph_test.go
git commit -m "feat(privesc): continue node escape into control-plane PKI theft"
```

---

### Task 5: Confused-deputy edge family

A subject that can write an operator's custom resource borrows that operator's controller identity.

**Files:**
- Create: `internal/analyzer/privesc/deputy.go`
- Create: `internal/analyzer/privesc/deputy_test.go`
- Modify: `internal/analyzer/privesc/graph.go` (`BuildGraph`)
- Modify: `internal/analyzer/privesc/analyzer.go` (`findingFromPath`)
- Modify: `docs/findings.md`

**Interfaces:**
- Consumes: `permissions.EffectiveRule.Grants(targets []permissions.ResourceTarget, verbs ...string) bool`.
- Produces: `addConfusedDeputyEdges(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule)`; action slug `operator_reconcile`; rule ID `KUBE-CONFUSED-DEPUTY-001`.

- [ ] **Step 1: Write the failing test**

Create `internal/analyzer/privesc/deputy_test.go`:

```go
package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fluxSnapshot builds a snapshot where a tenant SA can create Flux Kustomizations.
// installController controls whether the reconciling controller SA actually exists,
// which is the precision gate for the whole edge family.
func fluxSnapshot(installController bool) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "flux-system"}},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: metav1.ObjectMeta{Name: "gitops", Namespace: "tenant"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
			Resources: []string{"kustomizations"},
			Verbs:     []string{"create", "patch"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "gitops-rb", Namespace: "tenant"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "gitops"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev-deployer", Namespace: "tenant"}},
	}}
	if installController {
		snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "kustomize-controller", Namespace: "flux-system"}},
		}
		snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "flux-crb"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "kustomize-controller", Namespace: "flux-system"},
			},
		}}
	}
	return snapshot
}

func TestConfusedDeputyBridgesToControllerSA(t *testing.T) {
	graph := BuildGraph(fluxSnapshot(true))
	paths := FindPaths(graph, 5)

	var found bool
	for _, p := range paths {
		if p.Source.Name == "dev-deployer" && p.Target == models.TargetClusterAdmin &&
			len(p.Hops) >= 2 && p.Hops[0].Action == "operator_reconcile" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want dev-deployer -> kustomize-controller -> cluster_admin; paths: %+v", paths)
	}
}

// TestConfusedDeputyRequiresInstalledController is the precision gate: a stray RBAC
// grant on a CRD that no operator serves must produce nothing.
func TestConfusedDeputyRequiresInstalledController(t *testing.T) {
	graph := BuildGraph(fluxSnapshot(false))
	for _, edge := range graph.Edges {
		if edge.Action == "operator_reconcile" {
			t.Fatalf("emitted an operator_reconcile edge with no controller SA installed: %+v", edge)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestConfusedDeputy -v`

Expected: the first test FAILs, the second PASSes vacuously.

- [ ] **Step 3: Write the catalog and builder**

Create `internal/analyzer/privesc/deputy.go`:

```go
// Package privesc: confused-deputy edges. A subject that cannot escalate directly
// may still be able to write a custom resource that a privileged controller then
// reconciles on its behalf. The controller is the deputy: it holds the permissions,
// the attacker supplies the instructions.
package privesc

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// operatorEntry maps one attacker-writable custom resource to the controller
// ServiceAccount that reconciles it.
type operatorEntry struct {
	group     string
	resources []string
	saName    string
	saNS      string
	// gains describes, in one clause, what the reconciler will do on the
	// attacker's behalf. Used verbatim in the edge description.
	gains string
}

// operatorCatalog lists controllers whose custom resources are attacker-steerable:
// the CR names a source of manifests, a script, a file path, or a target identity
// that the controller then acts on with its own (usually cluster-wide) permissions.
//
// Kept RBAC-only on purpose: a grant on these (group, resource) pairs is visible in
// permissions.Aggregate without collecting CRDs or the custom resources themselves.
// The precision gate is addConfusedDeputyEdges requiring the controller SA to exist.
var operatorCatalog = []operatorEntry{
	{group: "kustomize.toolkit.fluxcd.io", resources: []string{"kustomizations"}, saNS: "flux-system", saName: "kustomize-controller",
		gains: "applies arbitrary manifests from an attacker-controlled source"},
	{group: "helm.toolkit.fluxcd.io", resources: []string{"helmreleases"}, saNS: "flux-system", saName: "helm-controller",
		gains: "installs an attacker-authored Helm chart"},
	{group: "source.toolkit.fluxcd.io", resources: []string{"gitrepositories", "ocirepositories"}, saNS: "flux-system", saName: "source-controller",
		gains: "fetches an attacker-controlled manifest source"},
	{group: "argoproj.io", resources: []string{"applications", "applicationsets"}, saNS: "argocd", saName: "argocd-application-controller",
		gains: "syncs an attacker-controlled Git repository into the cluster"},
	{group: "argoproj.io", resources: []string{"workflows"}, saNS: "argo", saName: "argo-workflow-controller",
		gains: "runs an attacker-authored workflow pod, optionally under a chosen ServiceAccount"},
	{group: "cert-manager.io", resources: []string{"certificates"}, saNS: "cert-manager", saName: "cert-manager",
		gains: "issues a certificate with an attacker-chosen subject and writes it to a Secret"},
	{group: "external-secrets.io", resources: []string{"externalsecrets"}, saNS: "external-secrets", saName: "external-secrets",
		gains: "materializes an attacker-chosen external secret into a Kubernetes Secret"},
	{group: "velero.io", resources: []string{"restores"}, saNS: "velero", saName: "velero",
		gains: "restores attacker-selected objects, including RBAC, from a backup"},
	{group: "tekton.dev", resources: []string{"pipelineruns"}, saNS: "tekton-pipelines", saName: "tekton-pipelines-controller",
		gains: "runs an attacker-authored pipeline step"},
	{group: "monitoring.coreos.com", resources: []string{"servicemonitors"}, saNS: "monitoring", saName: "prometheus-operator",
		gains: "scrapes an attacker-chosen bearerTokenFile, exfiltrating a mounted ServiceAccount token (GHSA-cxh2-4639-vmc5)"},
}

// deputyVerbs are the write verbs that let a subject steer a reconciler.
var deputyVerbs = []string{"create", "update", "patch"}

// addConfusedDeputyEdges emits an operator_reconcile bridge from a subject that can
// write a catalogued custom resource to the controller ServiceAccount that reconciles
// it. The controller supplies its own outbound edges, which is where the escalation
// actually lands, so this bridge only ever lengthens an existing chain.
//
// The edge is emitted only when the controller SA exists as a node in the graph,
// meaning the operator is genuinely installed. A stray Role granting verbs on a CRD
// that nothing serves produces no edge.
func addConfusedDeputyEdges(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule) {
	for _, entry := range operatorCatalog {
		controller := models.SubjectRef{Kind: "ServiceAccount", Name: entry.saName, Namespace: entry.saNS}
		if controller.Key() == subject.Key() {
			continue
		}
		if _, installed := graph.Nodes[nodeID(controller)]; !installed {
			continue
		}

		targets := make([]permissions.ResourceTarget, 0, len(entry.resources))
		for _, resource := range entry.resources {
			targets = append(targets, permissions.ResourceTarget{Group: entry.group, Resource: resource})
		}

		for _, rule := range rules {
			if !rule.Grants(targets, deputyVerbs...) {
				continue
			}
			addEdge(graph, nodeID(subject), nodeID(controller), &models.EscalationEdge{
				Technique:   "KUBE-CONFUSED-DEPUTY-001",
				Action:      "operator_reconcile",
				Permission:  fmt.Sprintf("write %s.%s", entry.resources[0], entry.group),
				Description: fmt.Sprintf("can steer %s/%s, which %s", entry.saNS, entry.saName, entry.gains),
			})
			break // one bridge per (subject, controller) is enough
		}
	}
}
```

- [ ] **Step 4: Call it from BuildGraph**

The controller SA node must already exist when the bridge is evaluated, and SA nodes are created lazily during the per-subject loop. So call this in a second pass. In `BuildGraph`, right after `addNamespaceAdminTokenTheftEdges(graph, subjectsByNs)` from Task 3:

```go
	// Second pass: bridges need every controller SA node to already exist, which is
	// only guaranteed once the per-subject loop above has run.
	for _, perms := range effective {
		addConfusedDeputyEdges(graph, perms.Subject, perms.Rules)
	}
```

Note: a controller SA that holds no RBAC at all never appears in `permissions.Aggregate` and so has no node. Ensure such SAs still get nodes by confirming `serviceAccountsByNamespace` feeds `ensureSubjectNode`. If the second test fails for the wrong reason (no node for an installed-but-powerless controller), add a loop in `BuildGraph` before the second pass that calls `ensureSubjectNode` for every SA in `subjectsByNs`.

- [ ] **Step 5: Overlay the rule ID**

In `internal/analyzer/privesc/analyzer.go`, inside `findingFromPath`, immediately after `severity, score, ruleID := targetScoring(...)`:

```go
	// Confused-deputy chains get their own rule ID so operators can triage the
	// "a controller acted on my behalf" class separately from direct RBAC paths.
	// This is a technique overlay on the first hop, not a distinct sink: the chain
	// still terminates at whatever the controller itself reaches.
	if firstAction(path.Hops) == "operator_reconcile" {
		ruleID = "KUBE-CONFUSED-DEPUTY-001"
	}
```

Confirm the `id` construction below it uses `ruleID`, so the overlay flows into the finding ID. It does (`analyzer.go:83`).

- [ ] **Step 6: Run the tests**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... -v 2>&1 | tail -30`

Expected: both new tests PASS, package green.

- [ ] **Step 7: Document the rule**

In `docs/findings.md`, add a row to the privesc catalog table for `KUBE-CONFUSED-DEPUTY-001`: severity High, detection "subject holds create/update/patch on a catalogued operator custom resource AND that operator's controller ServiceAccount exists in the cluster", remediation "scope the tenant's CR write access, or run the reconciler with impersonation so it acts as the requester rather than as itself", owning file `internal/analyzer/privesc/deputy.go`.

- [ ] **Step 8: Run full suite plus corpus**

Run: `make test 2>&1 | tail -10 && make corpus 2>&1 | tail -20 && make lint && ./bin/golangci-lint run ./...`

Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add internal/analyzer/privesc/deputy.go internal/analyzer/privesc/deputy_test.go \
        internal/analyzer/privesc/graph.go internal/analyzer/privesc/analyzer.go docs/findings.md
git commit -m "feat(privesc): add confused-deputy operator-reconcile edges"
```

---

### Task 6: Weakest-hop difficulty scoring

Replace hop-count attenuation with a per-edge difficulty model, so a long chain of trivial grants outranks a short chain that needs a race.

**Files:**
- Modify: `internal/models/escalation.go` (`EscalationEdge`)
- Modify: `internal/models/finding.go:297` (`EscalationHop`)
- Modify: `internal/analyzer/privesc/graph.go` (`addEdge`, new difficulty table)
- Modify: `internal/analyzer/privesc/pathfinder.go` (`buildPath`)
- Modify: `internal/analyzer/privesc/analyzer.go` (`targetScoring`)
- Test: `internal/analyzer/privesc/analyzer_test.go`

**Interfaces:**
- Produces: `models.EscalationEdge.Difficulty string`, `models.EscalationHop.Difficulty string`, values `"easy" | "moderate" | "hard"`. `targetScoring(target models.EscalationTarget, hops []models.EscalationHop) (models.Severity, float64, string)`. Note the **signature change** from the previous `hops int`.

- [ ] **Step 1: Write the failing test**

Append to `internal/analyzer/privesc/analyzer_test.go`:

```go
// TestDifficultyScoringPrefersEasyLongChains proves a long chain of trivial hops
// outranks a short chain that needs attacker-controlled infrastructure.
func TestDifficultyScoringPrefersEasyLongChains(t *testing.T) {
	easyHop := models.EscalationHop{Action: "impersonate", Difficulty: "easy"}
	hardHop := models.EscalationHop{Action: "node_drain_migrate", Difficulty: "hard"}

	longEasy := []models.EscalationHop{easyHop, easyHop, easyHop, easyHop, easyHop}
	shortHard := []models.EscalationHop{hardHop, hardHop}

	_, longScore, _ := targetScoring(models.TargetClusterAdmin, longEasy)
	shortSeverity, shortScore, _ := targetScoring(models.TargetClusterAdmin, shortHard)

	if longScore <= shortScore {
		t.Fatalf("5 easy hops (%.2f) should outrank 2 hard hops (%.2f)", longScore, shortScore)
	}
	if shortSeverity != models.SeverityHigh {
		t.Fatalf("a chain containing a hard hop should downgrade from critical to high, got %s", shortSeverity)
	}
}

// TestDifficultyScoringKeepsEasyChainsCritical proves length alone no longer
// downgrades severity.
func TestDifficultyScoringKeepsEasyChainsCritical(t *testing.T) {
	easyHop := models.EscalationHop{Action: "impersonate", Difficulty: "easy"}
	hops := []models.EscalationHop{easyHop, easyHop, easyHop, easyHop}

	severity, _, _ := targetScoring(models.TargetClusterAdmin, hops)
	if severity != models.SeverityCritical {
		t.Fatalf("a 4-hop all-easy chain to cluster-admin should stay critical, got %s", severity)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/ -run TestDifficultyScoring -v`

Expected: FAIL, compile error (`Difficulty` undefined, and `targetScoring` takes an int).

- [ ] **Step 3: Add the model fields**

In `internal/models/escalation.go`, inside `EscalationEdge`:

```go
	// Difficulty rates how much has to go right for an attacker to walk this edge:
	// "easy" (an RBAC grant is sufficient), "moderate" (needs a workload to exist or
	// be schedulable), "hard" (needs attacker-controlled infrastructure or a race).
	// Path scoring sums these rather than penalizing raw hop count, so a long chain
	// of trivial grants outranks a short chain that needs a race window.
	Difficulty string `json:"difficulty,omitempty"`
```

In `internal/models/finding.go`, inside `EscalationHop`, after `Technique`:

```go
	// Difficulty is carried through from the enabling edge so report consumers and
	// the scorer can reason about the weakest link without re-walking the graph.
	Difficulty string `json:"difficulty,omitempty"`
```

- [ ] **Step 4: Assign difficulty centrally**

In `internal/analyzer/privesc/graph.go`, add:

```go
// Difficulty ratings for path scoring. See models.EscalationEdge.Difficulty.
const (
	difficultyEasy     = "easy"
	difficultyModerate = "moderate"
	difficultyHard     = "hard"
)

// actionDifficulty rates each edge action. Anything absent defaults to moderate,
// which is the safe middle: a new edge never silently scores as trivial.
var actionDifficulty = map[string]string{
	// Pure RBAC: holding the grant is the whole exploit.
	"wildcard_permission":        difficultyEasy,
	"bound_to_cluster_admin":     difficultyEasy,
	"modify_role_binding":        difficultyEasy,
	"bind_or_escalate":           difficultyEasy,
	"impersonate":                difficultyEasy,
	"impersonate_system_masters": difficultyEasy,
	"impersonate_serviceaccount": difficultyEasy,
	"read_secrets":               difficultyEasy,
	"token_request":              difficultyEasy,
	"mint_arbitrary_token":       difficultyEasy,
	"secret_mint_token":          difficultyEasy,
	"csr_approve":                difficultyEasy,
	"operator_reconcile":         difficultyEasy,
	"colocated_sa_token_theft":   difficultyEasy,

	// Needs a workload to exist, be created, or land somewhere specific.
	"pod_create_token_theft":       difficultyModerate,
	"pod_exec":                     difficultyModerate,
	"ephemeral_container_inject":   difficultyModerate,
	"pod_create_privileged_escape": difficultyModerate,
	"pod_host_escape":              difficultyModerate,
	"nodes_proxy":                  difficultyModerate,
	"irsa_assume_role":             difficultyModerate,
	"aws_auth_admin":               difficultyModerate,
	"control_plane_pki_theft":      difficultyModerate,
	"static_pod_admission_bypass":  difficultyModerate,

	// Needs attacker-controlled infrastructure or a timing window.
	"node_drain_migrate":    difficultyHard,
	"imds_node_role_pivot":  difficultyHard,
}

// difficultyForAction returns the rating for an action, defaulting to moderate.
func difficultyForAction(action string) string {
	if d, ok := actionDifficulty[action]; ok {
		return d
	}
	return difficultyModerate
}
```

Then extend `addEdge` (`graph.go:625-629`) so every edge is rated in one place:

```go
func addEdge(graph *models.EscalationGraph, from, to string, edge *models.EscalationEdge) {
	edge.From = from
	edge.To = to
	if edge.Difficulty == "" {
		edge.Difficulty = difficultyForAction(edge.Action)
	}
	graph.Edges = append(graph.Edges, edge)
}
```

- [ ] **Step 5: Carry difficulty onto the hop**

In `internal/analyzer/privesc/pathfinder.go`, in `buildPath`, add `Difficulty: step.edge.Difficulty,` to the `models.EscalationHop` literal.

- [ ] **Step 6: Rewrite targetScoring**

In `internal/analyzer/privesc/analyzer.go`, change the signature and replace the attenuation block. The `switch target` that picks `base`, `severity`, `ruleID` stays exactly as it is; only the signature and everything after the switch changes:

```go
// difficultyCost is the score penalty each hop contributes, by difficulty rating.
var difficultyCost = map[string]float64{
	"easy":     0.15,
	"moderate": 0.4,
	"hard":     0.9,
}

// targetScoring returns the base severity, score, and rule ID for a target,
// attenuated by how hard the chain is to walk rather than by how long it is.
//
// Each hop costs according to its difficulty, so a five-hop chain of ordinary RBAC
// grants (0.75 total) outranks a two-hop chain that needs a race window (1.8). A
// chain is downgraded one severity bucket when it contains at least one hard hop,
// because that is the step an operator can most realistically bet against. Length
// still matters, but through the summed cost rather than as the primary signal.
func targetScoring(target models.EscalationTarget, hops []models.EscalationHop) (models.Severity, float64, string) {
	var base float64
	var severity models.Severity
	var ruleID string
	switch target {
	// ... unchanged ...
	}

	penalty := 0.0
	hasHardHop := false
	for _, hop := range hops {
		cost, ok := difficultyCost[hop.Difficulty]
		if !ok {
			cost = difficultyCost["moderate"]
		}
		penalty += cost
		if hop.Difficulty == "hard" {
			hasHardHop = true
		}
	}

	score := base - penalty
	if score < 1 {
		score = 1
	}
	if score > 10 {
		score = 10
	}
	if hasHardHop {
		severity = downgrade(severity)
	}
	return severity, score, ruleID
}
```

Update the single call site in `findingFromPath` from `targetScoring(target, len(path.Hops))` to `targetScoring(target, path.Hops)`.

- [ ] **Step 7: Run the package tests**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/analyzer/privesc/... 2>&1 | tail -25`

Expected: the two new tests PASS. Pre-existing tests asserting exact scores or severities WILL fail. That is expected and intended. For each, recompute the expected value by hand from the new formula and update it. Do not weaken an assertion to a range to make it pass.

- [ ] **Step 8: Run the full suite**

Run: `make test 2>&1 | tail -20 && make corpus 2>&1 | tail -20`

Expected: green. The corpus scores recall and precision on rule IDs, not severities, so it should be unaffected. If it moves, investigate before proceeding.

- [ ] **Step 9: Commit**

```bash
git add internal/models/escalation.go internal/models/finding.go \
        internal/analyzer/privesc/graph.go internal/analyzer/privesc/pathfinder.go \
        internal/analyzer/privesc/analyzer.go internal/analyzer/privesc/analyzer_test.go
git commit -m "feat(privesc): score chains by weakest hop instead of length"
```

---

### Task 7: Report copy for the new techniques

Without these entries the report's Background block silently drops the explainer card for every new action. `TechniqueKeyForFinding` already prefers `EscalationPath[0].Action` when it is a known key, so adding map entries is sufficient for path findings.

**Files:**
- Modify: `internal/report/glossary.go`
- Test: `internal/report/glossary_test.go`

**Interfaces:**
- Consumes: action slugs from Tasks 3, 4, 5.

- [ ] **Step 1: Write the failing test**

Append to `internal/report/glossary_test.go`:

```go
// TestNewPrivescActionsHaveTechniqueCopy guards the CLAUDE.md rule that every
// privesc action slug needs a Techniques entry, or the report drops its card.
func TestNewPrivescActionsHaveTechniqueCopy(t *testing.T) {
	for _, action := range []string{
		"colocated_sa_token_theft",
		"control_plane_pki_theft",
		"static_pod_admission_bypass",
		"operator_reconcile",
	} {
		explainer, ok := Techniques[action]
		if !ok {
			t.Errorf("no Techniques entry for action %q", action)
			continue
		}
		if explainer.Title == "" || explainer.Plain == "" {
			t.Errorf("Techniques[%q] must have a Title and Plain body", action)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/report/ -run TestNewPrivescActionsHaveTechniqueCopy -v`

Expected: FAIL with four "no Techniques entry" errors.

- [ ] **Step 3: Add the entries**

Add to the `Techniques` map in `internal/report/glossary.go`, following the existing shape (`Title`, `Plain` as `template.HTML`, `Mitre`, `AttackerSteps`):

```go
	"colocated_sa_token_theft": {
		Title: "Co-located ServiceAccount token theft",
		Plain: template.HTML(`<p>Administrative control over a namespace implies control over every identity inside it. Someone who can create RoleBindings in a namespace can create a pod that mounts any ServiceAccount there, exec into a pod already running as it, or read its token Secret directly.</p><p>This matters when a namespace hosts an identity more powerful than the namespace itself, for example a controller whose ClusterRoleBinding grants cluster-wide permissions. Namespace-admin then becomes a stepping stone rather than a boundary.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "List the ServiceAccounts available in the compromised namespace", Cmd: "kubectl get serviceaccounts -n <ns>"},
			{Note: "Find which of them hold cluster-wide permissions", Cmd: "kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.namespace==\"<ns>\")'"},
			{Note: "Mint a token for the most powerful one", Cmd: "kubectl create token <sa> -n <ns>"},
		},
	},
	"control_plane_pki_theft": {
		Title: "Control-plane PKI theft",
		Plain: template.HTML(`<p>Root on a node is serious anywhere, but root on a <em>control-plane</em> node is game over. The cluster's certificate authority private key sits at <code>/etc/kubernetes/pki/ca.key</code>. With it an attacker signs a client certificate carrying <code>O=system:masters</code> entirely offline, and the API server accepts it because the group short-circuits authorization.</p><p>No RBAC change is involved, so no audit event records the grant. Recovery requires rotating the cluster CA, not merely deleting a binding.</p>`),
		Mitre: "T1552.004 — Unsecured Credentials: Private Keys",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm the node is a control-plane node", Cmd: "ls /etc/kubernetes/pki/ca.key"},
			{Note: "Sign a client certificate as the system:masters group", Cmd: "openssl req -new -key attacker.key -subj '/CN=attacker/O=system:masters' -out attacker.csr && openssl x509 -req -in attacker.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -out attacker.crt"},
			{Note: "Use the forged certificate against the API server", Cmd: "kubectl --client-certificate attacker.crt --client-key attacker.key get secrets -A"},
		},
	},
	"static_pod_admission_bypass": {
		Title: "Static pod and SA signing-key abuse",
		Plain: template.HTML(`<p>The kubelet on a control-plane node runs any manifest dropped into <code>/etc/kubernetes/manifests</code> as a static pod. Static pods never traverse the API server, so no admission webhook, Pod Security Admission label, or policy engine can see or block them.</p><p>The same node holds <code>/etc/kubernetes/pki/sa.key</code>, the key that signs every ServiceAccount token in the cluster. An attacker with it forges a valid token for any ServiceAccount without touching the API.</p>`),
		Mitre: "T1610 — Deploy Container",
		AttackerSteps: []AttackerStep{
			{Note: "Drop a privileged static pod that no admission controller sees", Cmd: "cp attacker-pod.yaml /etc/kubernetes/manifests/"},
			{Note: "Steal the ServiceAccount token signing key", Cmd: "cat /etc/kubernetes/pki/sa.key"},
		},
	},
	"operator_reconcile": {
		Title: "Confused deputy: operator reconciliation",
		Plain: template.HTML(`<p>Operators work by watching custom resources and acting on them with their own, usually cluster-wide, permissions. A tenant who can write one of those custom resources does not need permissions of their own: they write the instruction, and the controller carries it out as itself.</p><p>A GitOps controller pointed at an attacker-controlled repository will apply whatever manifests it finds there, including a ClusterRoleBinding. A monitoring operator told to scrape a chosen <code>bearerTokenFile</code> will read and ship its own mounted token. The permission that matters belongs to the deputy, not the requester.</p>`),
		Mitre: "T1078 — Valid Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Check which operator custom resources you can write", Cmd: "kubectl auth can-i --list | grep -Ei 'fluxcd|argoproj|cert-manager|external-secrets|velero|tekton|monitoring.coreos'"},
			{Note: "Confirm the reconciling controller is more privileged than you are", Cmd: "kubectl auth can-i --list --as=system:serviceaccount:<controller-ns>:<controller-sa>"},
			{Note: "Point the custom resource at an attacker-controlled source and let the controller apply it", Cmd: "kubectl apply -f attacker-kustomization.yaml"},
		},
	},
```

- [ ] **Step 4: Run the test**

Run: `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache go test ./internal/report/... 2>&1 | tail -10`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report/glossary.go internal/report/glossary_test.go
git commit -m "feat(report): add technique copy for deep-chain privesc actions"
```

---

### Task 8: e2e chain-shape assertions and deep-chain fixture

The harness asserts rule-ID recall, rule-ID set equality, and instance-level negatives. None of them covers chain *shape*, so a regression flattening every path to one hop passes today. Add that assertion, then a fixture that exercises the new families.

**Files:**
- Modify: `scripts/kind-e2e.sh`
- Create: `testdata/e2e/vulnerable/17-privesc-deep-chains.yaml`
- Create: `testdata/e2e/expectations/deep-chains.expect`
- Create: `testdata/e2e/expectations/deep-chains.chain`
- Regenerate: `testdata/e2e/expectations/{full,minimal}-scan.ruleset`

**Interfaces:**
- Consumes: action slugs and `KUBE-CONFUSED-DEPUTY-001` from Tasks 3, 4, 5.

- [ ] **Step 1: Write the fixture**

Create `testdata/e2e/vulnerable/17-privesc-deep-chains.yaml`. It must satisfy the repo rule that fixture pods actually reach Running, so any pod here needs a real image and a rollout entry. This fixture deliberately needs no pods: every edge it exercises is RBAC-derived.

```yaml
# Deep-chain privesc fixture. Exercises three edge families that only produce
# findings when chained: the confused-deputy operator bridge, namespace-admin
# continuation into a co-located ServiceAccount, and (via the single-node kind
# control-plane node) the node-escape continuation into control-plane PKI.
#
# No CRDs are installed on purpose. RBAC rules may name resources whose CRD does
# not exist, which is exactly the shape the confused-deputy catalog matches on.
apiVersion: v1
kind: Namespace
metadata:
  name: deepchain-tenant
---
apiVersion: v1
kind: Namespace
metadata:
  name: flux-system
---
# The reconciling controller. Its existence is the precision gate for the
# confused-deputy edge: without this ServiceAccount, no bridge is emitted.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kustomize-controller
  namespace: flux-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: deepchain-flux-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: kustomize-controller
    namespace: flux-system
---
# The tenant. Holds no dangerous Kubernetes verb of its own: its only power is
# writing a Flux Kustomization, which the controller then reconciles as itself.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deepchain-deployer
  namespace: deepchain-tenant
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deepchain-gitops
  namespace: deepchain-tenant
rules:
  - apiGroups: ["kustomize.toolkit.fluxcd.io"]
    resources: ["kustomizations"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deepchain-gitops
  namespace: deepchain-tenant
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deepchain-gitops
subjects:
  - kind: ServiceAccount
    name: deepchain-deployer
    namespace: deepchain-tenant
---
# Namespace-admin continuation: this SA can only bind roles inside its own
# namespace, but that namespace co-hosts a cluster-admin-bound identity.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deepchain-binder
  namespace: deepchain-tenant
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deepchain-binder
  namespace: deepchain-tenant
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deepchain-binder
  namespace: deepchain-tenant
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deepchain-binder
subjects:
  - kind: ServiceAccount
    name: deepchain-binder
    namespace: deepchain-tenant
---
# The co-located high-value identity that makes namespace-admin worth chaining.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deepchain-privileged
  namespace: deepchain-tenant
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: deepchain-privileged
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: deepchain-privileged
    namespace: deepchain-tenant
```

- [ ] **Step 2: Write the recall expectation**

Create `testdata/e2e/expectations/deep-chains.expect`:

```
# Rule IDs the deep-chain shard must produce.
KUBE-CONFUSED-DEPUTY-001
```

- [ ] **Step 3: Write the chain-shape expectations**

Create `testdata/e2e/expectations/deep-chains.chain`:

```
# Chain-shape assertions: <finding-id-prefix> <min-hops> <ordered,hop,actions>
#
# The rule-ID goldens prove WHICH rules fire; these prove the graph still produces
# real multi-hop chains. Without them a regression that flattened every path to a
# single hop would pass every other gate.
#
# The tenant holds no dangerous verb of its own. It reaches cluster-admin only by
# steering the Flux controller, so this asserts the confused-deputy bridge exists
# and is genuinely the first hop.
KUBE-CONFUSED-DEPUTY-001:ServiceAccount/deepchain-tenant/deepchain-deployer 2 operator_reconcile
#
# Namespace-admin must be walked past into the co-located cluster-admin-bound SA.
KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/deepchain-tenant/deepchain-binder 3 modify_role_binding,colocated_sa_token_theft
```

- [ ] **Step 4: Add the assertion handler**

In `scripts/kind-e2e.sh`, after the `*.deny` guard loop (around line 325-340), add a new section. Match the surrounding style: a `step` banner, a loop over the glob, `ok` / failure accounting consistent with the existing handlers.

```bash
# --- chain-shape guards -------------------------------------------------------
# Each *.chain file asserts that a finding exists AND that its escalation chain is
# still deep and correctly ordered. Format, one assertion per non-comment line:
#   <finding-id-prefix> <min-hop-count> <ordered,comma,separated,actions>
# The action list must appear as an ordered subsequence of the finding's hops, so
# inserting a new intermediate hop does not spuriously fail the gate.
step "Asserting escalation-chain shape"
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.chain; do
  [ -e "${f}" ] || continue
  while read -r prefix min_hops actions; do
    case "${prefix}" in ''|'#'*) continue ;; esac

    actual_hops="$(jq -r --arg p "${prefix}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))] | first | .escalation_path | length // 0' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"

    if [ "${actual_hops}" = "null" ] || [ -z "${actual_hops}" ] || [ "${actual_hops}" = "0" ]; then
      fail "chain guard: no finding matching ${prefix}"
      continue
    fi
    if [ "${actual_hops}" -lt "${min_hops}" ]; then
      fail "chain guard: ${prefix} has ${actual_hops} hops, want at least ${min_hops}"
      continue
    fi

    actual_actions="$(jq -r --arg p "${prefix}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))] | first | [.escalation_path[].action] | join(",")' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"

    missing=""
    remaining="${actual_actions}"
    for want in $(printf '%s' "${actions}" | tr ',' ' '); do
      case ",${remaining}," in
        *",${want},"*) remaining="${remaining#*"${want}"}" ;;
        *) missing="${want}" ; break ;;
      esac
    done
    if [ -n "${missing}" ]; then
      fail "chain guard: ${prefix} chain [${actual_actions}] missing ordered action ${missing}"
      continue
    fi
    ok "chain ${prefix}: ${actual_hops} hops [${actual_actions}]"
  done < "${f}"
done
```

Before writing this, read the existing `*.deny` loop and reuse its exact `fail` / `ok` helper names and failure-counter variable. If the script uses a different accounting mechanism (for example appending to a `FAILURES` array), match that instead of the `fail` calls shown here.

- [ ] **Step 5: Run e2e and read the output carefully**

Run: `make e2e 2>&1 | tail -60`

Expected on the FIRST run: the `*.ruleset` set-equality gate FAILS, because `KUBE-CONFUSED-DEPUTY-001` is new and the new fixture may surface other rules. This is the gate working correctly.

Read the diff it prints. For every rule ID that appeared, confirm it is a true positive attributable to the new fixture or the new edge families. Any rule that appeared on a *pre-existing* fixture is a false positive introduced by Tasks 2 through 4 and must be investigated before regenerating the golden.

- [ ] **Step 6: Regenerate the goldens**

Only after Step 5's diff has been reviewed and every new rule ID justified:

```bash
LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-full/findings.json | LC_ALL=C sort -u \
  > testdata/e2e/expectations/full-scan.ruleset
LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-minimal/findings.json | LC_ALL=C sort -u \
  > testdata/e2e/expectations/minimal-scan.ruleset
git diff --stat testdata/e2e/expectations/
```

- [ ] **Step 7: Re-run e2e to green**

Run: `make e2e 2>&1 | tail -40`

Expected: fully green, including the new chain guards, which should print their hop counts and action chains.

- [ ] **Step 8: Verify the chains are genuinely deep**

Run:

```bash
jq -r '[.[] | select(.escalation_path != null)] | group_by(.escalation_path | length)
       | map({hops: (.[0].escalation_path | length), findings: length})' \
  .tmp/e2e-report-full/findings.json
```

Expected: the histogram now shows chains at 4 hops or deeper. Before this work the maximum was 4 with a single instance. If nothing got deeper, the structural changes are not actually composing and that must be investigated rather than accepted.

- [ ] **Step 9: Final gates and commit**

```bash
make test && make lint && ./bin/golangci-lint run ./... && make corpus
git add scripts/kind-e2e.sh testdata/e2e/
git commit -m "test(e2e): assert escalation-chain shape and add deep-chain fixture"
```

---

## Self-Review

**Spec coverage:** Section 1 (traversable sinks) is Task 1. Section 2 (IsSystem split) is Task 2. Section 3 (namespace-admin) is Task 3. Section 4 (control-plane continuation) is Task 4. Section 5 (confused deputy) is Task 5, including the rule-ID overlay and the catalog table transcribed verbatim. Section 6 (weakest-hop scoring) is Task 6. Section 7 (report copy) is Task 7. Section 8 (e2e) is Task 8, covering the new `.chain` assertion type, the fixture, and golden regeneration. The spec's Testing section is distributed across the per-task test steps, with the "synthetic deep chain found end to end" requirement satisfied by Task 1 Step 1 and Task 2 Step 1.

**Type consistency:** `Traversable` (Task 1) is consumed by Tasks 3 and 4. `IsControlPlane` (Task 2) is consumed only by the pathfinder source loop. `Difficulty` is added to `EscalationEdge` and `EscalationHop` in Task 6 and populated centrally in `addEdge` plus `buildPath`, so the four action slugs introduced in Tasks 3 through 5 are rated by the table in Task 6 Step 4. Every one of those four slugs appears in the `actionDifficulty` map and in the Task 7 glossary test. `targetScoring`'s signature change from `hops int` to `hops []models.EscalationHop` is called out explicitly with its single call site.

**Known ordering constraint:** Task 6's difficulty table references action slugs created in Tasks 3, 4, and 5, so Task 6 must not run before them. Tasks 1 and 2 are independent of each other but both precede Tasks 3 and 4.
