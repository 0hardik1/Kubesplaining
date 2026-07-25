# Cut-Resilient Escalation Paths Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every `KUBE-PRIVESC-PATH-*` finding state whether the binding cut it recommends actually closes the route, and carry the surviving route when it does not.

**Architecture:** RBAC-derived graph edges gain provenance (which binding and role granted them). Remediation uses that to cut the binding that enabled hop 1 instead of the first binding it finds. Path search then re-runs once per distinct first-hop binding with that binding's edges banned; any sink still reachable yields an alternate chain stored as an additive field on the finding.

**Tech Stack:** Go 1.26, `k8s.io/{api,apimachinery,client-go}` v0.36.x, cobra CLI. Tests are table-driven Go tests plus a `kind`-based e2e shell harness (`scripts/kind-e2e.sh`) driven by `make e2e`.

**Reference spec:** [`docs/superpowers/specs/2026-07-25-cut-resilient-escalation-paths-design.md`](../specs/2026-07-25-cut-resilient-escalation-paths-design.md)

## Global Constraints

- **No em dashes (—) anywhere.** Code comments, docs, commit messages, fixture comments. Use a colon, comma, parentheses, or two sentences.
- **No new rule IDs.** `testdata/e2e/expectations/full-scan.ruleset` and `minimal-scan.ruleset` must not move. If either moves, something fired that should not have.
- **Rule IDs are a public surface.** Do not rename any existing `KUBE-*` identifier.
- Conventional Commits, enforced by the `commit-msg` hook. PR title must be 72 characters or fewer.
- Never put Claude session links or `Claude-Session:` trailers in commit messages.
- All Go commands must carry the repo-local caches so modules are not re-downloaded:
  `GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache`
- New JSON fields must be `omitempty` so findings without them serialize byte-identically to today.
- Before pushing, run `./bin/golangci-lint run ./...`. `make lint` only runs `gofmt -l` plus `go vet` and will not catch staticcheck findings that fail CI.
- Package doc comments at the top of each `package foo` file describe the package's role. New files follow the same pattern.

---

## File Structure

**Modified:**
- `internal/models/escalation.go`: `EscalationEdge` gains provenance; `EscalationPath` gains `AlternateHops`.
- `internal/models/finding.go`: `EscalationHop` gains provenance; `Finding` gains `AlternateEscalationPath`.
- `internal/analyzer/privesc/graph.go`: stamp provenance at the three builder sites that have it.
- `internal/analyzer/privesc/deputy.go`: stamp provenance on confused-deputy edges.
- `internal/analyzer/privesc/pathfinder.go`: banned-edge predicate, cut-set computation, alternate attachment, dead-guard removal.
- `internal/analyzer/privesc/analyzer.go`: copy alternate onto the finding, add the tag.
- `internal/remediation/rbac.go`: cut the granting binding.
- `internal/report/{evidence_render.go,writers.go,types.go,privesc_paths_section.go}` and `assets/report.html.tmpl`: render the alternate.
- `scripts/kind-e2e.sh`: `.chain` variant column, exactly-one-match hardening.
- `docs/findings.md`, `docs/privesc-research.md`, `PLAN.md`: status.

**Created:**
- `testdata/e2e/vulnerable/18-privesc-cut-resilient.yaml`: RBAC-only kind fixture.
- `testdata/e2e/expectations/cut-resilient.chain`: chain-shape assertions.

---

### Task 1: Edge and hop provenance

**Files:**
- Modify: `internal/models/escalation.go:47-62` (`EscalationEdge`)
- Modify: `internal/models/finding.go:297-313` (`EscalationHop`)
- Modify: `internal/analyzer/privesc/graph.go:166-408` (`addEdgesForRule`), `graph.go:99-116` (`bound_to_cluster_admin`)
- Modify: `internal/analyzer/privesc/deputy.go:67` (`addConfusedDeputyEdges`)
- Modify: `internal/analyzer/privesc/pathfinder.go:146-172` (`buildPath`)
- Test: `internal/analyzer/privesc/graph_test.go`

**Interfaces:**
- Consumes: `permissions.EffectiveRule` (`internal/permissions/aggregate.go:14-27`), which already carries `SourceRole string`, `SourceBinding string`, and `Namespace string` (binding namespace, empty for cluster-scoped).
- Produces: `models.EscalationEdge.SourceBinding/SourceRole/BindingNamespace` and the identical three fields on `models.EscalationHop`. Task 2 reads the hop fields; Task 3 reads the edge fields.

- [ ] **Step 1: Write the failing test**

Add to `internal/analyzer/privesc/graph_test.go`:

```go
// TestBuildGraphStampsEdgeProvenance proves RBAC-derived edges record the binding
// that granted them, and that synthetic edges (pod escape) record nothing. The
// cut-resilient pass keys entirely off this, so an unstamped edge silently opts a
// path out of the alternate-route check.
func TestBuildGraphStampsEdgeProvenance(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "prov-sa", Namespace: "prov"}},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "prov-impersonator"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			}},
		},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "prov-binding"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "prov-impersonator"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "prov-sa", Namespace: "prov"},
			},
		},
	}

	graph := BuildGraph(snapshot)

	var stamped int
	for _, edge := range graph.Edges {
		if edge.From != "subject:ServiceAccount/prov/prov-sa" {
			continue
		}
		stamped++
		if edge.SourceBinding != "prov-binding" {
			t.Errorf("edge %q SourceBinding = %q, want %q", edge.Action, edge.SourceBinding, "prov-binding")
		}
		if edge.SourceRole != "prov-impersonator" {
			t.Errorf("edge %q SourceRole = %q, want %q", edge.Action, edge.SourceRole, "prov-impersonator")
		}
		if edge.BindingNamespace != "" {
			t.Errorf("edge %q BindingNamespace = %q, want empty for a ClusterRoleBinding", edge.Action, edge.BindingNamespace)
		}
	}
	if stamped == 0 {
		t.Fatal("no edges emitted for the impersonating subject; fixture is wrong")
	}
}

// TestBuildGraphStampsClusterAdminBindingProvenance covers the single most common
// privesc path. Two ClusterRoleBindings to cluster-admin for one subject must
// produce two parallel edges carrying different binding names, which is what makes
// a same-length alternate route expressible.
func TestBuildGraphStampsClusterAdminBindingProvenance(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "twice", Namespace: "prov"}},
	}
	subject := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "twice", Namespace: "prov"}}
	adminRef := rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "admin-a"}, RoleRef: adminRef, Subjects: subject},
		{ObjectMeta: metav1.ObjectMeta{Name: "admin-b"}, RoleRef: adminRef, Subjects: subject},
	}

	graph := BuildGraph(snapshot)

	got := map[string]bool{}
	for _, edge := range graph.Edges {
		if edge.Action == "bound_to_cluster_admin" {
			got[edge.SourceBinding] = true
		}
	}
	for _, want := range []string{"admin-a", "admin-b"} {
		if !got[want] {
			t.Errorf("no bound_to_cluster_admin edge stamped with binding %q; got %v", want, got)
		}
	}
}

// TestPodEscapeEdgesCarryNoProvenance pins the negative case: a pod-escape edge
// comes from a workload spec, not a binding, so there is no binding to model
// cutting and the cut-resilient pass must skip it.
func TestPodEscapeEdgesCarryNoProvenance(t *testing.T) {
	privileged := true
	snapshot := models.Snapshot{}
	snapshot.Resources.Pods = []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "escaper", Namespace: "prov"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "prov-sa",
			Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
			}},
		},
	}}

	graph := BuildGraph(snapshot)

	var checked int
	for _, edge := range graph.Edges {
		if edge.To != sinkNodeEscape {
			continue
		}
		checked++
		if edge.SourceBinding != "" || edge.SourceRole != "" {
			t.Errorf("pod-escape edge %q carries provenance %q/%q, want none",
				edge.Action, edge.SourceBinding, edge.SourceRole)
		}
	}
	if checked == 0 {
		t.Fatal("no node-escape edge emitted; fixture is wrong")
	}
}
```

Ensure the file's import block includes `corev1 "k8s.io/api/core/v1"`, `rbacv1 "k8s.io/api/rbac/v1"`, and `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc -run 'TestBuildGraphStamps|TestPodEscapeEdgesCarryNoProvenance' -v
```

Expected: compile failure, `edge.SourceBinding undefined (type *models.EscalationEdge has no field or method SourceBinding)`.

- [ ] **Step 3: Add the model fields**

In `internal/models/escalation.go`, append to the `EscalationEdge` struct (after `Difficulty`):

```go
	// SourceBinding, SourceRole, and BindingNamespace record which (Cluster)RoleBinding
	// and (Cluster)Role granted the RBAC rule that justified this edge. Remediation uses
	// them to cut the binding that actually enabled the hop rather than the first binding
	// listing the subject, and path search uses them to model what removing that binding
	// would do (see pathfinder.go's cut-resilient pass).
	//
	// All three are empty for synthetic edges that no single binding grants: pod escapes,
	// the node-escape continuation, the namespace-admin token-theft fan-out, and cloud
	// identity edges. An empty BindingNamespace on a populated SourceBinding means a
	// ClusterRoleBinding, matching how permissions.Aggregate builds the rule.
	SourceBinding    string `json:"source_binding,omitempty"`
	SourceRole       string `json:"source_role,omitempty"`
	BindingNamespace string `json:"binding_namespace,omitempty"`
```

In `internal/models/finding.go`, append the identical three fields to `EscalationHop` (after `Gains`), with this comment:

```go
	// SourceBinding, SourceRole, and BindingNamespace are carried through from the
	// enabling edge so remediation can cut the right binding without re-walking the
	// graph. See EscalationEdge for the semantics, including what an empty value means.
	SourceBinding    string `json:"source_binding,omitempty"`
	SourceRole       string `json:"source_role,omitempty"`
	BindingNamespace string `json:"binding_namespace,omitempty"`
```

In `internal/models/escalation.go`, add to `EscalationPath` (after `Hops`):

```go
	// AlternateHops is a route to the same Target that survives cutting the binding
	// named by Hops[0]. Non-empty means the obvious remediation is not sufficient on
	// its own. Empty means either that no such route exists, or that Hops[0] is a
	// synthetic edge with no binding to model cutting.
	AlternateHops []EscalationHop `json:"alternate_hops,omitempty"`
```

- [ ] **Step 4: Stamp provenance in `addEdgesForRule`**

In `internal/analyzer/privesc/graph.go`, immediately after `from := nodeID(subject)` and `clusterScope := ...` at the top of `addEdgesForRule` (around line 174), add:

```go
	// add stamps binding provenance from the rule that justified the edge before
	// delegating to addEdge. Every edge in this function derives from exactly one
	// aggregated RBAC rule, so provenance is unambiguous here; builders outside this
	// function stamp it themselves or deliberately leave it empty.
	add := func(to string, edge *models.EscalationEdge) {
		edge.SourceBinding = rule.SourceBinding
		edge.SourceRole = rule.SourceRole
		edge.BindingNamespace = rule.Namespace
		addEdge(graph, from, to, edge)
	}
```

Then replace every `addEdge(graph, from, X, &models.EscalationEdge{...})` call **inside `addEdgesForRule` only** with `add(X, &models.EscalationEdge{...})`. Per the current tree these are at lines 178, 193, 202, 214, 223, 235, 244, 258, 270, 298, 308, 323, 339, 355, 371, and 381. Do not touch `addEdge` calls in other functions.

- [ ] **Step 5: Stamp the cluster-admin binding edges**

In `internal/analyzer/privesc/graph.go`, in the ClusterRoleBinding loop at lines 99-116, add the three fields to the edge literal:

```go
			addEdge(graph, nodeID(ref), sinkClusterAdmin, &models.EscalationEdge{
				Technique:   "KUBE-RBAC-OVERBROAD-001",
				Action:      "bound_to_cluster_admin",
				Permission:  "cluster-admin",
				Description: fmt.Sprintf("bound to cluster-admin via %s", binding.Name),
				// This loop walks ClusterRoleBindings directly and already emits one
				// edge per binding, so two bindings to cluster-admin produce two
				// parallel edges. That is exactly the shape the cut-resilient pass
				// needs to prove that cutting one binding changes nothing.
				SourceBinding: binding.Name,
				SourceRole:    binding.RoleRef.Name,
			})
```

`BindingNamespace` stays unset: these are always ClusterRoleBindings.

- [ ] **Step 6: Stamp the confused-deputy edges**

In `internal/analyzer/privesc/deputy.go`, `addConfusedDeputyEdges` already receives `rules []permissions.EffectiveRule`. Inside the loop where an edge is emitted, set `SourceBinding`, `SourceRole`, and `BindingNamespace` from the `permissions.EffectiveRule` that matched. If the current code does not keep the matching rule in scope at the emission point, capture it when the match is found and thread it to the edge literal.

- [ ] **Step 7: Copy provenance through `buildPath`**

In `internal/analyzer/privesc/pathfinder.go`, in the hop literal inside `buildPath` (line 157), add the three fields:

```go
		hops = append(hops, models.EscalationHop{
			Step:             i + 1,
			Action:           step.edge.Action,
			Technique:        step.edge.Technique,
			Difficulty:       step.edge.Difficulty,
			FromSubject:      current,
			ToSubject:        next,
			Permission:       step.edge.Permission,
			Gains:            step.edge.Description,
			SourceBinding:    step.edge.SourceBinding,
			SourceRole:       step.edge.SourceRole,
			BindingNamespace: step.edge.BindingNamespace,
		})
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc/... ./internal/models/... -v
```

Expected: PASS, including the three new tests and every pre-existing privesc test.

- [ ] **Step 9: Confirm no output drift**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./... 2>&1 | grep -v "^ok\|no test files" || echo "all packages pass"
```

Expected: no failures. This step is purely additive so far, so any failure means a JSON golden somewhere pins the exact hop shape and needs the new `omitempty` fields confirmed absent.

- [ ] **Step 10: Commit**

```bash
git add internal/models/escalation.go internal/models/finding.go \
  internal/analyzer/privesc/graph.go internal/analyzer/privesc/deputy.go \
  internal/analyzer/privesc/pathfinder.go internal/analyzer/privesc/graph_test.go
git commit -m "feat(privesc): record binding provenance on escalation edges

Edges derived from an RBAC rule now carry the (Cluster)RoleBinding and
(Cluster)Role that granted them, threaded through to EscalationHop.

Synthetic edges (pod escape, node-escape continuation, namespace-admin
fan-out, cloud identity) deliberately carry none: no single binding
grants them, so there is nothing to model cutting."
```

---

### Task 2: Cut the binding that actually granted the hop

**Files:**
- Modify: `internal/remediation/rbac.go:357-378` (`ForPrivescPath`), `rbac.go:424-453` (`findBindingForSubject`)
- Test: `internal/remediation/rbac_test.go`

**Interfaces:**
- Consumes: `models.EscalationHop.SourceBinding` / `.BindingNamespace` from Task 1.
- Produces: `findBindingByName(snap models.Snapshot, name, namespace string) *bindingRef` returning nil when no binding matches. `bindingRef` is the existing unexported struct at `rbac.go:414-422`.

- [ ] **Step 1: Write the failing test**

Add to `internal/remediation/rbac_test.go`:

```go
// TestForPrivescPathCutsGrantingBinding is the regression test for a real defect:
// findBindingForSubject returns the FIRST binding listing the subject, which need
// not be the binding that granted the dangerous verb. Editing that binding closes
// nothing. With hop provenance we cut the binding that actually enabled hop 1.
func TestForPrivescPathCutsGrantingBinding(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team"}
	rbacSubject := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "app", Namespace: "team"}}

	snap := models.Snapshot{}
	// Sorted first by collectBindings (ClusterRoleBinding, then name), so this is
	// what the old first-match scan would have picked. It grants nothing dangerous.
	snap.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "aaa-harmless-view"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
			Subjects:   rbacSubject,
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "zzz-dangerous-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   rbacSubject,
		},
	}

	finding := models.Finding{
		RuleID:  "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		Subject: &subject,
		EscalationPath: []models.EscalationHop{{
			Step:          1,
			Action:        "bound_to_cluster_admin",
			SourceBinding: "zzz-dangerous-admin",
			SourceRole:    "cluster-admin",
		}},
	}

	hint := ForPrivescPath(finding, snap)
	if hint == nil {
		t.Fatal("ForPrivescPath returned nil, want a hint")
	}
	if !strings.Contains(hint.RBACDiff, "zzz-dangerous-admin") {
		t.Errorf("diff does not mention the granting binding:\n%s", hint.RBACDiff)
	}
	if strings.Contains(hint.RBACDiff, "aaa-harmless-view") {
		t.Errorf("diff cuts the wrong binding (first match, not the granting one):\n%s", hint.RBACDiff)
	}
}

// TestForPrivescPathFallsBackWithoutProvenance keeps the synthetic-edge path working:
// a pod-escape-rooted chain has no binding to name, so the old scan still applies.
func TestForPrivescPathFallsBackWithoutProvenance(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team"}
	snap := models.Snapshot{}
	snap.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "only-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "app", Namespace: "team"}},
	}}

	finding := models.Finding{
		RuleID:         "KUBE-PRIVESC-PATH-NODE-ESCAPE",
		Subject:        &subject,
		EscalationPath: []models.EscalationHop{{Step: 1, Action: "pod_host_escape"}},
	}

	hint := ForPrivescPath(finding, snap)
	if hint == nil {
		t.Fatal("ForPrivescPath returned nil for a synthetic-rooted chain, want the fallback hint")
	}
	if !strings.Contains(hint.RBACDiff, "only-binding") {
		t.Errorf("fallback did not use the subject scan:\n%s", hint.RBACDiff)
	}
}
```

- [ ] **Step 2: Run the tests to verify the first one fails**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/remediation -run TestForPrivescPath -v
```

Expected: `TestForPrivescPathCutsGrantingBinding` FAILS with the diff mentioning `aaa-harmless-view`. `TestForPrivescPathFallsBackWithoutProvenance` should already PASS.

- [ ] **Step 3: Add the by-name lookup**

In `internal/remediation/rbac.go`, next to `findBindingForSubject`:

```go
// findBindingByName returns the binding a hop's provenance names. Namespace is
// empty for ClusterRoleBindings, matching how permissions.Aggregate records it,
// so the (kind, name) pair is unambiguous. Returns nil when the snapshot has no
// such binding, which happens on a partial snapshot where the collector could not
// list one of the two binding kinds.
func findBindingByName(snap models.Snapshot, name, namespace string) *bindingRef {
	if name == "" {
		return nil
	}
	for _, b := range collectBindings(snap) {
		if b.Name == name && b.Namespace == namespace {
			return &b
		}
	}
	return nil
}
```

- [ ] **Step 4: Prefer provenance in `ForPrivescPath`**

Replace the binding lookup in `ForPrivescPath` (currently `rbac.go:367-369`):

```go
	// Prefer the binding the first hop actually came from. findBindingForSubject
	// returns the first binding listing the subject, which need not be the one that
	// granted the dangerous verb, so cutting it can close nothing. Provenance is
	// empty for synthetic edges (pod escape, token mint), where the subject scan and
	// its advisory-diff fallback remain correct.
	if binding := findBindingByName(snap, firstHop.SourceBinding, firstHop.BindingNamespace); binding != nil {
		return remediationDropSubjectFromBinding(*binding, subject, firstHop)
	}
	if binding := findBindingForSubject(snap, subject); binding != nil {
		return remediationDropSubjectFromBinding(*binding, subject, firstHop)
	}
```

Update the `findBindingForSubject` doc comment (`rbac.go:424-433`) so it no longer claims first-match is good enough. It is now the fallback for synthetic-rooted chains only.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/remediation/... -v
```

Expected: PASS. If any pre-existing golden test fails, inspect the diff: a changed binding name is the intended fix and the golden should be re-baselined. A changed diff *format* is a bug in this task.

- [ ] **Step 6: Commit**

```bash
git add internal/remediation/rbac.go internal/remediation/rbac_test.go
git commit -m "fix(remediation): cut the binding that granted the first hop

ForPrivescPath used findBindingForSubject, which returns the first
binding listing the subject regardless of whether it granted the verb
the hop depends on. A subject in three bindings where only the third
grants impersonate was told to edit the first, closing nothing.

Hop provenance now names the granting binding. The subject scan stays
as the fallback for synthetic-rooted chains, which name no binding."
```

---

### Task 3: The cut-resilient pass

**Files:**
- Modify: `internal/analyzer/privesc/pathfinder.go` (whole file)
- Test: `internal/analyzer/privesc/pathfinder_test.go`

**Interfaces:**
- Consumes: `models.EscalationEdge.SourceBinding` / `.BindingNamespace` (Task 1), `models.EscalationPath.AlternateHops` (Task 1).
- Produces: `FindPaths(graph *models.EscalationGraph, maxDepth int) []models.EscalationPath` keeps its exact signature; returned paths may now have `AlternateHops` populated. `bfsToSinks` gains a fifth parameter `banned func(*models.EscalationEdge) bool` where nil means no edge is banned.

- [ ] **Step 1: Write the failing tests**

Add to `internal/analyzer/privesc/pathfinder_test.go`:

```go
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
	if len(paths) != 1 {
		t.Fatalf("want 1 path to cluster-admin, got %d", len(paths))
	}
	p := paths[0]
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
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc -run 'TestAlternate|TestNoAlternate|TestSyntheticRooted' -v
```

Expected: all four FAIL with `want a 1-hop alternate ... got 0 hops` and similar. They compile, because `AlternateHops` exists from Task 1.

- [ ] **Step 3: Add the banned-edge parameter to `bfsToSinks`**

In `internal/analyzer/privesc/pathfinder.go`, change the signature and add the guard as the first statement of the edge loop:

```go
func bfsToSinks(
	graph *models.EscalationGraph,
	adj map[string][]*models.EscalationEdge,
	sourceID string,
	maxDepth int,
	banned func(*models.EscalationEdge) bool,
) map[string][]pathStep {
```

Inside `for _, edge := range adj[item.nodeID] {`, before anything else:

```go
		if banned != nil && banned(edge) {
			continue
		}
```

Update the existing call at line 52 to pass `nil`.

While here, delete the two dead guards this design supersedes, both unreachable because the `visited` prune already guarantees first arrival is shortest:

- The `seen` map at lines 45 and 54-58. `sources` is unique and `bfsToSinks` returns one chain per target, so the key can never repeat.
- The shorter-chain guard at line 120. Replace with a direct assignment:

```go
			if neighbor.IsSink {
				sinks[edge.To] = nextPath
```

Leave the sort comparator at lines 66-77 alone: its hop-count tiebreak stays as a stability guard.

- [ ] **Step 4: Add the cut-set machinery**

Add to `internal/analyzer/privesc/pathfinder.go`:

```go
// cutKey identifies a (Cluster)RoleBinding whose removal we want to model. An empty
// namespace means a ClusterRoleBinding, matching permissions.EffectiveRule.
type cutKey struct {
	binding   string
	namespace string
}

// edgeCut returns the binding an edge came from. The false return covers synthetic
// edges (pod escape, node-escape continuation, namespace-admin fan-out, cloud
// identity) that no single binding grants, so there is nothing to model cutting.
func edgeCut(edge *models.EscalationEdge) (cutKey, bool) {
	if edge == nil || edge.SourceBinding == "" {
		return cutKey{}, false
	}
	return cutKey{binding: edge.SourceBinding, namespace: edge.BindingNamespace}, true
}

// alternatesForSource returns, per reachable sink, a chain that survives cutting the
// binding named by that sink's own first hop.
//
// Removing a subject from a binding revokes every capability that binding conferred
// on THAT subject and nothing else, so the banned set is scoped to edges leaving the
// source node. Edges elsewhere in the graph are untouched.
//
// One BFS runs per distinct first-hop binding, not one per path, because a single
// banned run reports every sink still reachable. Each path then reads only the run
// for its OWN first hop: a source reaching cluster-admin via binding A and node-escape
// via binding B gets two runs, and reading run A's node-escape result would answer a
// question nobody asked, since cutting A was never the proposed fix for that path.
func alternatesForSource(
	graph *models.EscalationGraph,
	adj map[string][]*models.EscalationEdge,
	sourceID string,
	maxDepth int,
	primary map[string][]pathStep,
) map[string][]pathStep {
	targetsByCut := map[cutKey][]string{}
	for targetID, chain := range primary {
		if len(chain) == 0 {
			continue
		}
		if key, ok := edgeCut(chain[0].edge); ok {
			targetsByCut[key] = append(targetsByCut[key], targetID)
		}
	}
	if len(targetsByCut) == 0 {
		return nil
	}

	alternates := map[string][]pathStep{}
	for key, targetIDs := range targetsByCut {
		banned := func(edge *models.EscalationEdge) bool {
			if edge.From != sourceID {
				return false
			}
			k, ok := edgeCut(edge)
			return ok && k == key
		}
		surviving := bfsToSinks(graph, adj, sourceID, maxDepth, banned)
		for _, targetID := range targetIDs {
			if chain, ok := surviving[targetID]; ok && len(chain) > 0 {
				alternates[targetID] = chain
			}
		}
	}
	return alternates
}
```

Map iteration order does not affect the result: each target belongs to exactly one `cutKey` by construction, so no run can overwrite another's answer.

- [ ] **Step 5: Wire it into `FindPaths`**

In the per-source loop, after `found := bfsToSinks(...)`:

```go
		found := bfsToSinks(graph, adj, sourceID, maxDepth, nil)
		alternates := alternatesForSource(graph, adj, sourceID, maxDepth, found)
		for targetID, chain := range found {
			targetNode := graph.Nodes[targetID]
			path := buildPath(graph, sourceNode.Subject, targetNode.Target, chain)
			path.TargetNamespace = targetNode.TargetNamespace
			if alt, ok := alternates[targetID]; ok {
				path.AlternateHops = buildPath(graph, sourceNode.Subject, targetNode.Target, alt).Hops
			}
			paths = append(paths, path)
		}
```

Update the `FindPaths` doc comment to record that a path may now carry an alternate.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc/... -v
```

Expected: PASS, including the four new tests. `TestFindPathsContinuesThroughTraversableSink` must still pass **unchanged**: its edges carry no `SourceBinding`, so the cut pass skips them and `len(paths)` stays 2.

- [ ] **Step 7: Commit**

```bash
git add internal/analyzer/privesc/pathfinder.go internal/analyzer/privesc/pathfinder_test.go
git commit -m "feat(privesc): find routes that survive the recommended binding cut

Path search now re-runs once per distinct first-hop binding with that
binding's outbound edges banned. Any sink still reachable becomes the
path's AlternateHops, so a finding can say whether the fix it prints
actually closes the route.

Two bindings granting the same capability yield a same-length alternate,
which is the strongest form: cutting one changes nothing.

Also removes two guards the visited prune already made unreachable."
```

---

### Task 4: Surface the alternate on the finding

**Files:**
- Modify: `internal/models/finding.go:38` (add field after `EscalationPath`)
- Modify: `internal/analyzer/privesc/analyzer.go:64-132` (`findingFromPath`)
- Test: `internal/analyzer/privesc/analyzer_test.go`

**Interfaces:**
- Consumes: `models.EscalationPath.AlternateHops` (Task 3).
- Produces: `models.Finding.AlternateEscalationPath []EscalationHop` and the tag `privesc:survives-first-cut`. Task 5 renders both.

- [ ] **Step 1: Write the failing test**

Add to `internal/analyzer/privesc/analyzer_test.go`:

```go
// TestFindingCarriesAlternateAndTag proves the alternate reaches the Finding as an
// additive field plus a filterable tag, rather than as a second Finding. A second
// Finding would collide on the engine dedupe key (RuleID, Subject, Resource) and be
// silently swallowed, since privesc paths to non-namespace sinks carry no Resource.
func TestFindingCarriesAlternateAndTag(t *testing.T) {
	path := models.EscalationPath{
		Source: models.SubjectRef{Kind: "ServiceAccount", Name: "twice", Namespace: "app"},
		Target: models.TargetClusterAdmin,
		Hops: []models.EscalationHop{
			{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "admin-a"},
		},
		AlternateHops: []models.EscalationHop{
			{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "admin-b"},
		},
	}

	finding := findingFromPath(path)

	if len(finding.AlternateEscalationPath) != 1 {
		t.Fatalf("want 1 alternate hop on the finding, got %d", len(finding.AlternateEscalationPath))
	}
	if finding.AlternateEscalationPath[0].SourceBinding != "admin-b" {
		t.Errorf("alternate binding = %q, want admin-b", finding.AlternateEscalationPath[0].SourceBinding)
	}
	var tagged bool
	for _, tag := range finding.Tags {
		if tag == "privesc:survives-first-cut" {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("want the privesc:survives-first-cut tag, got %v", finding.Tags)
	}
}

// TestFindingWithoutAlternateIsUntagged keeps the common case clean: no alternate
// means no field and no tag, so existing JSON output is byte-identical.
func TestFindingWithoutAlternateIsUntagged(t *testing.T) {
	path := models.EscalationPath{
		Source: models.SubjectRef{Kind: "ServiceAccount", Name: "once", Namespace: "app"},
		Target: models.TargetClusterAdmin,
		Hops:   []models.EscalationHop{{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "only"}},
	}

	finding := findingFromPath(path)

	if len(finding.AlternateEscalationPath) != 0 {
		t.Errorf("want no alternate, got %d hops", len(finding.AlternateEscalationPath))
	}
	for _, tag := range finding.Tags {
		if tag == "privesc:survives-first-cut" {
			t.Errorf("finding without an alternate must not carry the tag: %v", finding.Tags)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc -run TestFinding -v
```

Expected: compile failure, `finding.AlternateEscalationPath undefined`.

- [ ] **Step 3: Add the Finding field**

In `internal/models/finding.go`, immediately after `EscalationPath` (line 38):

```go
	// AlternateEscalationPath is a route to the same sink that survives the binding cut
	// this finding's RemediationHint recommends. Non-empty means the printed fix is not
	// sufficient on its own, and the finding also carries the tag
	// "privesc:survives-first-cut". Empty (the common case) means either that no such
	// route exists, or that the chain is synthetic-rooted so no binding cut was modeled.
	AlternateEscalationPath []EscalationHop `json:"alternate_escalation_path,omitempty"`
```

- [ ] **Step 4: Populate it in `findingFromPath`**

In `internal/analyzer/privesc/analyzer.go`, change the tag construction and add the field. Replace `tags := []string{"module:privesc", "target:" + string(target)}` with:

```go
	tags := []string{"module:privesc", "target:" + string(target)}
	if len(path.AlternateHops) > 0 {
		// The recommended fix cuts hop 1's binding, and this path reaches the same
		// sink without it. Tagged so report, exclusions, and CI consumers can filter
		// on it without parsing the chain.
		tags = append(tags, "privesc:survives-first-cut")
	}
```

Add `AlternateEscalationPath: path.AlternateHops,` to the `models.Finding{...}` literal, directly after `EscalationPath: path.Hops,`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/... ./internal/models/... -v
```

Expected: PASS.

- [ ] **Step 6: Verify the corpus is inert**

```bash
make corpus
```

Expected: PASS with no expectation changes. The corpus keys on instance-level finding IDs, which this task does not change. If it fails, a finding ID moved and that is a bug in this task.

- [ ] **Step 7: Commit**

```bash
git add internal/models/finding.go internal/analyzer/privesc/analyzer.go \
  internal/analyzer/privesc/analyzer_test.go
git commit -m "feat(privesc): carry the surviving route on the finding

Adds Finding.AlternateEscalationPath plus a privesc:survives-first-cut
tag. Additive and omitempty, so findings without an alternate serialize
byte-identically across JSON, SARIF, and CSV.

A second Finding would have been wrong: the engine dedupe key is
(RuleID, Subject, Resource) and privesc paths to non-namespace sinks
carry no Resource, so it would collide and be dropped with only a tag
merge surviving."
```

---

### Task 5: Render the alternate in the HTML report

**Files:**
- Modify: `internal/report/evidence_render.go:207-216` (`renderEscalationPath`)
- Modify: `internal/report/writers.go:256-261` (template func map)
- Modify: `internal/report/types.go:473-489` (`PrivescPathCard`)
- Modify: `internal/report/privesc_paths_section.go:66-80` (card construction)
- Modify: `internal/report/assets/report.html.tmpl:2210` (Findings tab), `:2709` (path card)
- Test: `internal/report/evidence_render_test.go`

**Interfaces:**
- Consumes: `models.Finding.AlternateEscalationPath` (Task 4).
- Produces: `renderEscalationPathVariant(hops []models.EscalationHop, variant string) template.HTML` where variant is `"primary"` or `"alternate"`. `renderEscalationPath(hops)` is kept as a wrapper passing `"primary"` so existing callers and tests are untouched. New template func `alternatePathHTML`. `PrivescPathCard` gains `AltHops []models.EscalationHop` and `AltHopCount int`.

- [ ] **Step 1: Write the failing test**

Add to `internal/report/evidence_render_test.go`:

```go
// TestRenderEscalationPathAlternateVariant proves the alternate renders with framing
// copy that leads with the operational point (this route survives the fix) rather
// than with chain length, and that it is visually distinguishable from the primary.
func TestRenderEscalationPathAlternateVariant(t *testing.T) {
	hops := []models.EscalationHop{{
		Step:          1,
		Action:        "bound_to_cluster_admin",
		SourceBinding: "admin-b",
		Gains:         "cluster-admin",
	}}

	out := string(renderEscalationPathVariant(hops, "alternate"))

	for _, want := range []string{"attack-chain-alt", "survives"} {
		if !strings.Contains(out, want) {
			t.Errorf("alternate render missing %q\n---\n%s", want, out)
		}
	}
}

// TestRenderEscalationPathPrimaryUnchanged pins that the default variant still
// produces exactly what the existing renderer did, so no Findings-tab output moves.
func TestRenderEscalationPathPrimaryUnchanged(t *testing.T) {
	hops := []models.EscalationHop{{Step: 1, Action: "impersonate", Gains: "became admin"}}

	if got, want := string(renderEscalationPath(hops)), string(renderEscalationPathVariant(hops, "primary")); got != want {
		t.Errorf("renderEscalationPath diverged from the primary variant\ngot:  %s\nwant: %s", got, want)
	}
	if strings.Contains(string(renderEscalationPath(hops)), "attack-chain-alt") {
		t.Error("primary render must not carry the alternate class")
	}
}

// TestRenderEscalationPathAlternateEmpty keeps the template gate working.
func TestRenderEscalationPathAlternateEmpty(t *testing.T) {
	if got := string(renderEscalationPathVariant(nil, "alternate")); got != "" {
		t.Errorf("want empty string for no hops, got %q", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/report -run TestRenderEscalationPath -v
```

Expected: compile failure, `undefined: renderEscalationPathVariant`.

- [ ] **Step 3: Split the renderer**

In `internal/report/evidence_render.go`, rename `renderEscalationPath` to `renderEscalationPathVariant` with the new second parameter, and add a thin wrapper:

```go
// renderEscalationPath renders the primary chain. Kept as the default entry point so
// existing callers and the escalationPathHTML template func read unchanged.
func renderEscalationPath(hops []models.EscalationHop) template.HTML {
	return renderEscalationPathVariant(hops, "primary")
}
```

In `renderEscalationPathVariant`, when `variant == "alternate"`:
- Use `<ol class="attack-chain attack-chain-alt">` instead of `<ol class="attack-chain">`.
- Emit a lead-in line before the list explaining that this route survives the recommended fix, naming the cut binding from the *primary* chain is not available here, so phrase it generally: "This route reaches the same target without the binding the fix above removes, so applying that fix alone does not close it."

Add the `.attack-chain-alt` styling to the embedded CSS in `assets/report.html.tmpl`, visually subordinate to the primary chain (muted border, same step-card geometry).

- [ ] **Step 4: Register the template func**

In `internal/report/writers.go`, next to `escalationPathHTML`:

```go
		// alternatePathHTML renders Finding.AlternateEscalationPath: a route to the same
		// sink that survives cutting the binding the remediation hint recommends removing.
		// Returns "" for empty input so the template gate suppresses the whole block on
		// the common case where the recommended fix is sufficient.
		"alternatePathHTML": func(hops []models.EscalationHop) template.HTML {
			return renderEscalationPathVariant(hops, "alternate")
		},
```

- [ ] **Step 5: Render it in both tabs**

In `internal/report/types.go`, add to `PrivescPathCard` after `Hops`:

```go
	AltHops     []models.EscalationHop // route surviving the recommended binding cut; empty when the fix suffices
	AltHopCount int
```

In `internal/report/privesc_paths_section.go`, add to the `PrivescPathCard{...}` literal:

```go
				AltHops:     f.AlternateEscalationPath,
				AltHopCount: len(f.AlternateEscalationPath),
```

Card sorting stays keyed on the primary chain, so tab ordering does not move.

In `assets/report.html.tmpl`, after line 2210 in the Findings tab:

```gotemplate
                    {{ if $f.AlternateEscalationPath }}
                      <details class="alt-chain">
                        <summary>This fix does not close the route ({{ len $f.AlternateEscalationPath }} hops)</summary>
                        {{ alternatePathHTML $f.AlternateEscalationPath }}
                      </details>
                    {{ end }}
```

And after line 2709 in the path card:

```gotemplate
            {{ if .AltHops }}<details class="alt-chain"><summary>This fix does not close the route ({{ .AltHopCount }} hops)</summary>{{ alternatePathHTML .AltHops }}</details>{{ end }}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/report/... -v
```

Expected: PASS, including all pre-existing report structure tests. A template parse error surfaces here as a failure in `TestBuildHTMLData` or the writer tests.

- [ ] **Step 7: Eyeball the rendered output**

```bash
make build && ./bin/kubesplaining scan --input-file testdata/snapshots/minimal-risky.json \
  --output-dir .tmp/altcheck --formats html
```

Open `.tmp/altcheck/index.html`. The fixture has no parallel-binding subject, so expect **no** alternate blocks. Confirm the Findings tab and Escalation paths tab render exactly as before. Task 6's fixture is what produces a visible alternate.

- [ ] **Step 8: Commit**

```bash
git add internal/report/
git commit -m "feat(report): render the route that survives the recommended fix

Adds an alternatePathHTML template func and a collapsed disclosure under
the primary chain in both the Findings tab and the Escalation paths tab.
Copy leads with the operational point rather than with chain length.

renderEscalationPath is kept as a primary-variant wrapper so every
existing caller and golden reads unchanged."
```

---

### Task 6: E2E coverage on a local kind cluster

**Files:**
- Create: `testdata/e2e/vulnerable/18-privesc-cut-resilient.yaml`
- Create: `testdata/e2e/expectations/cut-resilient.chain`
- Modify: `scripts/kind-e2e.sh:343-400` (chain assertion block)
- Modify: `testdata/e2e/expectations/deep-chains.chain` (header comment only, documenting the new column)

**Interfaces:**
- Consumes: `Finding.alternate_escalation_path` in `findings.json` (Task 4).
- Produces: `.chain` format `<finding-id-prefix> <min-hop-count> <ordered,comma,separated,actions> [primary|alternate]`, where the fourth column defaults to `primary` when omitted.

This is the gate that matters. The rule-ID goldens stay identical by design, so a regression collapsing alternates back to nothing would pass every other check in the harness. Requires a reachable Docker daemon.

- [ ] **Step 1: Write the fixture**

Create `testdata/e2e/vulnerable/18-privesc-cut-resilient.yaml`:

```yaml
# Cut-resilient privesc fixture. Every other shard proves a path EXISTS; this one
# proves the recommended fix does not always close it.
#
# Two shapes, both RBAC-only:
#
#   1. cutres-parallel is named in two separate cluster-admin ClusterRoleBindings.
#      permissions.Aggregate yields one EffectiveRule per binding and addEdge does
#      not dedupe, so the graph carries two parallel bound_to_cluster_admin edges
#      with different provenance. Cutting the first leaves the second, and the
#      alternate comes back at the SAME hop count.
#
#   2. cutres-detour reaches cluster-admin directly, and also by binding roles
#      inside its own namespace, which co-hosts a cluster-admin-bound identity.
#      Cutting the direct binding leaves the longer namespace-admin route.
#
# Like shard 17 this needs no pods, so it takes no *.rollout entry: every edge
# here is derived from RBAC alone.
apiVersion: v1
kind: Namespace
metadata:
  name: cutres
---
# Shape 1: the same subject, bound to cluster-admin twice.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cutres-parallel
  namespace: cutres
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cutres-parallel-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: cutres-parallel
    namespace: cutres
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cutres-parallel-b
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: cutres-parallel
    namespace: cutres
---
# Shape 2: a direct route plus a longer one through the namespace it can bind in.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cutres-detour
  namespace: cutres
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cutres-detour-direct
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: cutres-detour
    namespace: cutres
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cutres-detour-binder
  namespace: cutres
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cutres-detour-binder
  namespace: cutres
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cutres-detour-binder
subjects:
  - kind: ServiceAccount
    name: cutres-detour
    namespace: cutres
```

- [ ] **Step 2: Extend the `.chain` parser**

In `scripts/kind-e2e.sh`, change the read loop to take a fourth field and select the JSON path accordingly. Replace `while read -r prefix min_hops actions; do` with:

```bash
  while read -r prefix min_hops actions variant; do
    case "${prefix}" in ''|'#'*) continue ;; esac
    chain_checks=$(( chain_checks + 1 ))

    # Fourth column selects which chain to assert against. Omitted means primary, so
    # every pre-existing assertion reads unchanged.
    case "${variant}" in
      ''|primary) path_field="escalation_path" ;;
      alternate)  path_field="alternate_escalation_path" ;;
      *) chain_violations+=("${prefix} has unknown variant ${variant}, want primary or alternate"); continue ;;
    esac
```

Replace both `| first` selectors (currently lines 361 and 375) with an exactly-one-match requirement, so a prefix that grows ambiguous fails loudly instead of silently retargeting:

```bash
    match_count="$(jq -r --arg p "${prefix}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))] | length' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
    if [[ "${match_count}" != "1" ]]; then
      chain_violations+=("${prefix} matched ${match_count} findings, want exactly 1 (make the prefix more specific)")
      continue
    fi

    actual_hops="$(jq -r --arg p "${prefix}" --arg pf "${path_field}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))][0] | (.[$pf] | length) // 0' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
```

and the actions extraction:

```bash
    actual_actions="$(jq -r --arg p "${prefix}" --arg pf "${path_field}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))][0] | [.[$pf][].action] | join(",")' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
```

Update the format comment block above the loop (currently lines 344-352) to document the fourth column. Add the same note to the header comment of `testdata/e2e/expectations/deep-chains.chain`.

- [ ] **Step 3: Write the chain assertions**

Create `testdata/e2e/expectations/cut-resilient.chain`:

```
# Cut-resilience assertions: <finding-id-prefix> <min-hops> <ordered,hop,actions> [primary|alternate]
#
# The *.ruleset goldens prove WHICH rules fire and the other *.chain files prove the
# graph still chains. These prove something neither can: that a path knows whether the
# remediation printed alongside it actually closes the route. A regression that dropped
# alternate-route detection would keep every rule ID identical and pass every other gate.
#
# Shape 1: bound to cluster-admin by two separate ClusterRoleBindings. The primary is a
# single hop, and cutting its binding leaves the parallel one, so the alternate is also
# a single hop. This is the case that shows an alternate is not merely a longer detour.
KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/cutres-parallel 1 bound_to_cluster_admin primary
KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/cutres-parallel 1 bound_to_cluster_admin alternate
#
# Shape 2: a direct binding plus a longer route through the namespace this SA can bind
# roles in, which co-hosts a cluster-admin-bound identity. Cutting the direct binding
# leaves the detour, so the alternate must be strictly deeper than the primary.
KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/cutres-detour 1 bound_to_cluster_admin primary
KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/cutres-detour 2 modify_role_binding,colocated_sa_token_theft alternate
```

- [ ] **Step 4: Run the e2e suite**

```bash
make e2e
```

Expected: PASS, with `ok chain KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/...` lines for all four assertions.

If shape 2's alternate does not match the asserted actions, read what the scan actually produced before changing the implementation:

```bash
jq '.[] | select(.id | startswith("KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/cutres/cutres-detour")) | {id, hops: [.escalation_path[].action], alt: [.alternate_escalation_path[].action]}' \
  .tmp/e2e-report-full/findings.json
```

Then correct the `.chain` assertion to the real chain if the produced chain is legitimate, or fix the fixture if the shape is not what was intended. Do not weaken the assertion to make it pass.

- [ ] **Step 5: Confirm the ruleset goldens did not move**

```bash
LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-full/findings.json | LC_ALL=C sort -u > /tmp/actual-full.ruleset
diff /tmp/actual-full.ruleset testdata/e2e/expectations/full-scan.ruleset && echo "full-scan.ruleset unchanged"
```

Expected: no diff. This work introduces no rule ID, so any movement means the new fixture fired a rule that was not intended, which is a false positive to investigate rather than a golden to regenerate.

If the new shard legitimately makes an existing rule fire that did not before (for example `KUBE-RBAC-OVERBROAD-001` on the new cluster-admin bindings), that is expected and the goldens **do** need regenerating. Regenerate both and state in the commit message which rule IDs were added and why:

```bash
LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-full/findings.json | LC_ALL=C sort -u \
  > testdata/e2e/expectations/full-scan.ruleset
LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-minimal/findings.json | LC_ALL=C sort -u \
  > testdata/e2e/expectations/minimal-scan.ruleset
```

- [ ] **Step 6: Commit**

```bash
git add testdata/e2e/vulnerable/18-privesc-cut-resilient.yaml \
  testdata/e2e/expectations/cut-resilient.chain \
  testdata/e2e/expectations/deep-chains.chain \
  scripts/kind-e2e.sh
git commit -m "test(e2e): gate cut-resilient paths on a kind cluster

New RBAC-only shard covering both alternate shapes: a same-length route
via a parallel cluster-admin binding, and a longer route through the
namespace-admin continuation.

The .chain format gains an optional primary|alternate column, defaulting
to primary so existing assertions read unchanged, so the alternate's
shape is gated rather than just its existence.

Also replaces the '| first' selector, which could silently retarget a
different finding as the set grows, with an exactly-one-match check."
```

---

### Task 7: Documentation and roadmap status

**Files:**
- Modify: `docs/findings.md` (privesc path rule block)
- Modify: `docs/privesc-research.md:518-530` (section O3)
- Modify: `PLAN.md` (privesc section, Next Goal, Completed)
- Modify: `CLAUDE.md` (e2e assertion-types paragraph)

**Interfaces:** None. Documentation only.

- [ ] **Step 1: Update the findings catalog**

In `docs/findings.md`, in the `KUBE-PRIVESC-PATH-*` block, document that these findings may carry `alternate_escalation_path` and the `privesc:survives-first-cut` tag, what a non-empty value means (the recommended binding cut does not close the route), and that an empty value means either no such route or a synthetic-rooted chain where no binding cut was modeled.

- [ ] **Step 2: Flip the O3 status**

In `docs/privesc-research.md`, update section O3 to record that the shortest-path limit is now addressed for the remediation case, that the general "richer route regardless of remediation" case remains open, and correct the section's claim that three mechanisms enforce the limit. The `visited` prune alone does; the other two named guards were unreachable and have been removed.

- [ ] **Step 3: Update PLAN.md**

Add the completed work to the Completed list with the rule IDs touched (none added), and replace the stale Next Goal. Record what the scouting established, since PLAN.md's GKE entry is dated 2026-05-17 and is now known to be wrong on two counts: the external-identity spine is not provider-neutral, and the GKE metadata-server rule's condition is inverted relative to EKS (with Workload Identity on, the metadata server blocks the node SA, so the finding fires when it is off).

- [ ] **Step 4: Document the new assertion type**

In `CLAUDE.md`, the paragraph listing the three e2e assertion types now needs a fourth. Note that `*.chain` files take an optional `primary|alternate` fourth column, and that alternate assertions are the only gate covering cut-resilience because the ruleset goldens stay identical by design.

- [ ] **Step 5: Run the full gate**

```bash
make lint && make test && ./bin/golangci-lint run ./... && make corpus && make e2e
```

Expected: all PASS. `golangci-lint` is the one that catches what `make lint` misses and fails CI.

- [ ] **Step 6: Commit**

```bash
git add docs/ PLAN.md CLAUDE.md
git commit -m "docs(privesc): record cut-resilient paths and correct O3

Section O3 claimed three mechanisms enforced shortest-path-only. The
visited prune alone did; the other two guards were unreachable and are
now removed. The limit is addressed for the remediation case, and the
general richer-route case stays open.

Also replaces PLAN.md's stale Next Goal: the GKE entry predates the
research follow-up and is wrong on the external-identity spine being
provider-neutral and on the metadata-server rule's condition."
```

---

## Self-Review

**Spec coverage.** Design section 1 (edge provenance) is Task 1, including the two non-`addEdgesForRule` sites the spec corrects. Section 2 (cutting the right binding) is Task 2. Section 3 (the cut-resilient pass) is Task 3, including the per-cut-not-per-path run count and the same-length parallel-binding case. Section 4 (finding shape and tag, second field not second finding) is Task 4. Section 5 (report) is Task 5. Section 6 (no scoring change) is covered by omission and is asserted indirectly by the unchanged corpus in Task 4 Step 6. Section 7 housekeeping: the dead-guard removal is Task 3 Step 3 and the `| first` hardening is Task 6 Step 2. The Testing section maps to Tasks 1 through 6 with the kind e2e in Task 6.

**One spec correction found while planning.** The spec's Testing section says `pathfinder_test.go:11-37` will need updating. It will not: that test's edges carry no `SourceBinding`, so the cut pass skips them and `len(paths)` stays 2. Task 3 Step 6 asserts it passes unchanged, which is a stronger outcome. The spec line is stale and Task 7 should not propagate it.

**Type consistency.** `cutKey` and `edgeCut` are defined in Task 3 Step 4 and used only there. `findBindingByName` is defined in Task 2 Step 3 and used in Step 4. `renderEscalationPathVariant` is defined in Task 5 Step 3 and used in Steps 4 and in the Step 1 tests. `AlternateHops` (on `EscalationPath`, Task 1) and `AlternateEscalationPath` (on `Finding`, Task 4) are deliberately different names for the graph-layer and finding-layer fields, mirroring the existing `Hops` / `EscalationPath` split. `bfsToSinks` gains its fifth parameter in Task 3 Step 3, and the only pre-existing caller is updated in the same step.
