package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestForRBACOverbroad covers the wildcard-rule remediation path. The
// generator must produce both a strategic-merge patch body and a unified diff
// that swap the wildcard for the placeholder least-privilege allowlist.
func TestForRBACOverbroad(t *testing.T) {
	t.Parallel()

	finding := models.Finding{
		RuleID: "KUBE-RBAC-OVERBROAD-001",
		Resource: &models.ResourceRef{
			Kind: "RBACRule",
			Name: "admins",
		},
		Evidence: mustMarshal(map[string]any{
			"source_role":      "cluster-admin",
			"source_role_kind": "ClusterRole",
		}),
	}

	hint := ForRBACOverbroad(finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForRBACOverbroad returned nil")
	}
	if hint.Patch == nil {
		t.Fatal("ForRBACOverbroad: Patch is nil")
	}
	if hint.Patch.Type != "strategic" {
		t.Errorf("Patch.Type = %q, want strategic", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "ClusterRole" {
		t.Errorf("Patch.Target.Kind = %q, want ClusterRole", hint.Patch.Target.Kind)
	}
	if !strings.Contains(string(hint.Patch.Body), "\"verbs\":[\"get\",\"list\"]") {
		t.Errorf("Patch.Body should contain placeholder verbs, got %s", string(hint.Patch.Body))
	}
	if hint.RBACDiff == "" {
		t.Fatal("ForRBACOverbroad: RBACDiff is empty")
	}
	if !strings.Contains(hint.RBACDiff, "-  verbs: [\"*\"]") {
		t.Errorf("RBACDiff should remove the wildcard verbs line, got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "+- apiGroups: [\"\"]") {
		t.Errorf("RBACDiff should add the placeholder rule, got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "+# TODO:") {
		t.Errorf("RBACDiff should include a TODO comment, got:\n%s", hint.RBACDiff)
	}
}

// TestForRBACOverbroadRejectsWrongRule ensures the generator is a no-op for
// rule IDs it doesn't know about. A future analyzer rename or copy-paste
// mistake at the call site should silently get nil rather than a confusingly
// shaped hint that points at the wrong rule.
func TestForRBACOverbroadRejectsWrongRule(t *testing.T) {
	t.Parallel()

	finding := models.Finding{RuleID: "KUBE-PRIVESC-005"}
	if hint := ForRBACOverbroad(finding, models.Snapshot{}); hint != nil {
		t.Errorf("ForRBACOverbroad accepted non-wildcard rule, got %+v", hint)
	}
}

// TestForRBACDangerous covers the per-dangerous-rule path. The generator must
// emit a JSON patch whose body removes the offending rule, plus a unified diff
// whose `-` block reconstructs the rule from the finding's evidence.
func TestForRBACDangerous(t *testing.T) {
	t.Parallel()

	finding := models.Finding{
		RuleID: "KUBE-PRIVESC-005",
		Resource: &models.ResourceRef{
			Kind:      "RBACRule",
			Name:      "reader",
			Namespace: "team-a",
		},
		Evidence: mustMarshal(map[string]any{
			"source_role":      "reader",
			"source_role_kind": "Role",
			"namespace":        "team-a",
			"api_groups":       []string{""},
			"resources":        []string{"secrets"},
			"verbs":            []string{"get", "list"},
		}),
	}

	hint := ForRBACDangerous("KUBE-PRIVESC-005", finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForRBACDangerous returned nil")
	}
	if hint.Patch == nil {
		t.Fatal("ForRBACDangerous: Patch is nil")
	}
	if hint.Patch.Type != "json" {
		t.Errorf("Patch.Type = %q, want json", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "Role" {
		t.Errorf("Patch.Target.Kind = %q, want Role", hint.Patch.Target.Kind)
	}
	if hint.Patch.Target.Namespace != "team-a" {
		t.Errorf("Patch.Target.Namespace = %q, want team-a", hint.Patch.Target.Namespace)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit role reader") {
		t.Errorf("Patch.Command should include kubectl edit recipe, got:\n%s", hint.Patch.Command)
	}
	if !strings.Contains(hint.RBACDiff, "-  resources: [\"secrets\"]") {
		t.Errorf("RBACDiff should show the dangerous resources being removed, got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "+rules: []") {
		t.Errorf("RBACDiff should reduce rules to []; got:\n%s", hint.RBACDiff)
	}
}

// TestForRBACDangerousRejectsUnknownRule mirrors the wildcard-side guard:
// callers passing an unrelated rule ID get nil so the call site stays
// idempotent if the rule-ID inventory drifts.
func TestForRBACDangerousRejectsUnknownRule(t *testing.T) {
	t.Parallel()

	cases := []string{"", "KUBE-RBAC-OVERBROAD-001", "KUBE-PODSEC-ROOT-001", "KUBE-PRIVESC-PATH-CLUSTER-ADMIN"}
	for _, rule := range cases {
		t.Run(rule, func(t *testing.T) {
			finding := models.Finding{RuleID: rule}
			if hint := ForRBACDangerous(rule, finding, models.Snapshot{}); hint != nil {
				t.Errorf("ForRBACDangerous(%q) returned non-nil hint: %+v", rule, hint)
			}
		})
	}
}

// TestForPrivescPathDropsSubject covers the binding-cut branch. When the
// subject is reachable through a real (Cluster)RoleBinding, the remediation
// diff must show that subject struck from the binding's subject list while
// leaving the other subjects in place.
func TestForPrivescPathDropsSubject(t *testing.T) {
	t.Parallel()

	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "attacker", Namespace: "default"}
	snap := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "crb-elevated"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "elevated-role"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "attacker", Namespace: "default"},
						{Kind: "ServiceAccount", Name: "innocent", Namespace: "default"},
					},
				},
			},
		},
	}
	finding := models.Finding{
		RuleID:  "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		Subject: &subject,
		EscalationPath: []models.EscalationHop{
			{
				Step:             1,
				Action:           "impersonate",
				FromSubject:      subject,
				ToSubject:        models.SubjectRef{Kind: "User", Name: "admin"},
				Permission:       "users:impersonate",
				SourceBinding:    "crb-elevated",
				BindingNamespace: "",
			},
		},
	}

	hint := ForPrivescPath(finding, snap)
	if hint == nil {
		t.Fatal("ForPrivescPath returned nil")
	}
	if hint.RBACDiff == "" {
		t.Fatal("RBACDiff is empty")
	}
	if !strings.Contains(hint.RBACDiff, "-  name: attacker") {
		t.Errorf("expected attacker subject to be removed (- line); got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "   name: innocent") {
		t.Errorf("expected innocent subject to remain in diff context; got:\n%s", hint.RBACDiff)
	}
	// The attacker's `-- kind` line collapses with the next subject's `- kind`
	// in the LCS walk, but the attacker's name + namespace must always be in
	// the deletion blocks.
	if !strings.Contains(hint.RBACDiff, "-  namespace: default") {
		t.Errorf("expected attacker's namespace line to be deleted; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch == nil || hint.Patch.Command == "" {
		t.Fatal("Patch.Command must be populated with kubectl edit recipe")
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit clusterrolebinding crb-elevated") {
		t.Errorf("Patch.Command should reference the binding, got:\n%s", hint.Patch.Command)
	}
}

// TestForPrivescPathFallback covers the advisory branch. When the chain
// doesn't pass through any (Cluster)RoleBinding we can name (synthetic edges
// like pod_host_escape), the generator emits a comment-only diff telling the
// operator the chain is a workload-layer issue.
func TestForPrivescPathFallback(t *testing.T) {
	t.Parallel()

	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "lonely", Namespace: "default"}
	finding := models.Finding{
		RuleID:  "KUBE-PRIVESC-PATH-NODE-ESCAPE",
		Subject: &subject,
		EscalationPath: []models.EscalationHop{
			{
				Step:        1,
				Action:      "pod_host_escape",
				FromSubject: subject,
				ToSubject:   models.SubjectRef{Kind: "Node", Name: "worker-1"},
				Permission:  "hostPath:/",
			},
		},
	}

	hint := ForPrivescPath(finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForPrivescPath returned nil even for synthetic-edge chain")
	}
	if hint.RBACDiff == "" {
		t.Fatal("advisory RBACDiff is empty")
	}
	if !strings.Contains(hint.RBACDiff, "synthetic edge") {
		t.Errorf("advisory diff should explain the chain is synthetic; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch != nil {
		t.Errorf("Patch should be nil for the advisory branch; got %+v", hint.Patch)
	}
}

// TestForPrivescPathAdvisorySplitsCorrelationFromWorkload covers the other cause of a
// chain with no binding to cut. Correlation edges (two RBAC grants dangerous only when
// held together) reach the advisory branch for the same mechanical reason pod escapes
// do, and used to get the same copy, which told the operator of a node_drain_migrate
// chain to remove hostPath / hostPID / hostNetwork or revoke `serviceaccounts/token`
// create. Neither applies: the enabler is `delete pods` plus node manipulation, both
// RBAC. The workload advice must stay for genuinely synthetic edges, so both branches
// are asserted here, each denying the other's copy.
func TestForPrivescPathAdvisorySplitsCorrelationFromWorkload(t *testing.T) {
	t.Parallel()

	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}
	advisoryFor := func(t *testing.T, hop models.EscalationHop) string {
		t.Helper()
		hint := ForPrivescPath(models.Finding{
			RuleID:         "KUBE-PRIVESC-PATH-NODE-ESCAPE",
			Subject:        &subject,
			EscalationPath: []models.EscalationHop{hop},
		}, models.Snapshot{})
		if hint == nil {
			t.Fatalf("ForPrivescPath returned nil for action %q, want the advisory hint", hop.Action)
		}
		if hint.Patch != nil {
			t.Errorf("Patch should be nil for the advisory branch; got %+v", hint.Patch)
		}
		return hint.RBACDiff
	}

	// Every correlation builder in privesc/graph.go that calls cutBreakers. Adding a
	// fourth there without adding it to correlationRootedActions fails here.
	for _, hop := range []models.EscalationHop{
		{Step: 1, Action: "node_drain_migrate", Permission: "delete pods + node scheduling control"},
		{Step: 1, Action: "secret_mint_token", Permission: "create + get secrets (cluster-wide)"},
		{Step: 1, Action: "csr_approve", Permission: "create certificatesigningrequests + update certificatesigningrequests/approval"},
	} {
		diff := advisoryFor(t, hop)
		if !strings.Contains(diff, "correlation edge") {
			t.Errorf("%s: advisory diff should name the correlation edge; got:\n%s", hop.Action, diff)
		}
		if !strings.Contains(diff, hop.Permission) {
			t.Errorf("%s: advisory diff should name both halves (%q); got:\n%s", hop.Action, hop.Permission, diff)
		}
		for _, banned := range []string{"hostPath", "workload layer", "synthetic edge"} {
			if strings.Contains(diff, banned) {
				t.Errorf("%s: advisory diff still sends an RBAC-rooted chain to the workload layer (%q); got:\n%s",
					hop.Action, banned, diff)
			}
		}
	}

	// The workload copy is still right for a genuinely synthetic edge, and must not
	// have been replaced wholesale.
	escape := advisoryFor(t, models.EscalationHop{Step: 1, Action: "pod_host_escape", Permission: "hostPath:/"})
	if !strings.Contains(escape, "synthetic edge") || !strings.Contains(escape, "hostPath") {
		t.Errorf("pod_host_escape lost the workload-layer advisory; got:\n%s", escape)
	}
	if strings.Contains(escape, "correlation edge") {
		t.Errorf("pod_host_escape got the correlation copy; got:\n%s", escape)
	}
}

// TestForPrivescPathAdvisoryKeepsTheBindingWhenTheSnapshotLacksIt covers the third
// way into the advisory branch: hop 1 DOES name a binding, but findBindingByName
// cannot find it, which happens on a partial snapshot (one binding kind could not be
// listed) or when the object changed between collection and analysis. The hint used to
// claim the chain "does not map to a single (Cluster)RoleBinding" while the finding's
// own prose said "Evaluated cut: removing this subject from the `X` binding". The two
// disagreed about whether a binding was identified, and the prose was the only place
// X appeared.
func TestForPrivescPathAdvisoryKeepsTheBindingWhenTheSnapshotLacksIt(t *testing.T) {
	t.Parallel()

	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team"}
	for _, tc := range []struct {
		name      string
		hop       models.EscalationHop
		wantScope string
	}{
		{
			name:      "cluster-scoped binding",
			hop:       models.EscalationHop{Step: 1, Action: "impersonate", SourceBinding: "crb-vanished"},
			wantScope: "ClusterRoleBinding",
		},
		{
			name:      "namespaced binding",
			hop:       models.EscalationHop{Step: 1, Action: "impersonate", SourceBinding: "rb-vanished", BindingNamespace: "team"},
			wantScope: "RoleBinding in namespace team",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Empty snapshot: the named binding is not there, so the lookup misses.
			hint := ForPrivescPath(models.Finding{
				RuleID:         "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
				Subject:        &subject,
				EscalationPath: []models.EscalationHop{tc.hop},
			}, models.Snapshot{})
			if hint == nil {
				t.Fatal("ForPrivescPath returned nil, want the advisory hint")
			}
			if !strings.Contains(hint.RBACDiff, tc.hop.SourceBinding) {
				t.Errorf("advisory diff drops the binding the prose names (%q); got:\n%s", tc.hop.SourceBinding, hint.RBACDiff)
			}
			if !strings.Contains(hint.RBACDiff, tc.wantScope) {
				t.Errorf("advisory diff should say which kind of binding (%q); got:\n%s", tc.wantScope, hint.RBACDiff)
			}
			if strings.Contains(hint.RBACDiff, "does not map to a single") {
				t.Errorf("advisory diff still denies a binding was identified; got:\n%s", hint.RBACDiff)
			}
			if hint.Patch != nil {
				t.Errorf("Patch should stay nil: there is no object in the snapshot to patch; got %+v", hint.Patch)
			}
		})
	}
}

// TestForPrivescPathCutsGrantingBinding proves ForPrivescPath cuts the binding
// hop 1's own provenance names, not merely some other binding that happens to
// list the subject. The snapshot lists the subject in two ClusterRoleBindings;
// only the one the hop's SourceBinding names (zzz-dangerous-admin) may appear
// in the diff, even though it sorts after the harmless one and would have been
// picked first by a scan over collectBindings.
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

// TestForPrivescPathCoversConfusedDeputy is the regression test for defect (b):
// KUBE-CONFUSED-DEPUTY-001 findings carry hop-1 binding provenance (deputy.go
// stamps SourceBinding/SourceRole/BindingNamespace on every operator_reconcile
// edge), but the RuleID guard only accepted the KUBE-PRIVESC-PATH- prefix, so
// ForPrivescPath returned nil and these findings got no printed fix at all, even
// though the cut-resilient pass can tag them privesc:survives-first-cut. The
// finding must produce a hint cutting hop 1's actual binding, not merely a
// non-nil hint.
func TestForPrivescPathCoversConfusedDeputy(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "gitops-writer", Namespace: "team"}
	snap := models.Snapshot{}
	snap.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "kustomization-writer", Namespace: "team"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "kustomization-editor"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "gitops-writer", Namespace: "team"}},
	}}

	finding := models.Finding{
		RuleID:  "KUBE-CONFUSED-DEPUTY-001",
		Subject: &subject,
		EscalationPath: []models.EscalationHop{{
			Step:             1,
			Action:           "operator_reconcile",
			SourceBinding:    "kustomization-writer",
			SourceRole:       "kustomization-editor",
			BindingNamespace: "team",
		}},
	}

	hint := ForPrivescPath(finding, snap)
	if hint == nil {
		t.Fatal("ForPrivescPath returned nil for a confused-deputy finding, want a hint")
	}
	if !strings.Contains(hint.RBACDiff, "kustomization-writer") {
		t.Errorf("diff does not name hop 1's binding:\n%s", hint.RBACDiff)
	}
	if hint.Patch == nil || !strings.Contains(hint.Patch.Command, "kubectl edit rolebinding kustomization-writer") {
		t.Errorf("Patch.Command should target the confused-deputy binding, got %+v", hint.Patch)
	}
}

// TestForPrivescPathDoesNotInventABindingCutForSyntheticChains is the
// regression test for defect (a). An earlier version of ForPrivescPath, when
// hop 1 carried no binding provenance, fell back to scanning the snapshot for
// the first (Cluster)RoleBinding that happened to list the subject and printed
// a diff cutting it. That binding need not have anything to do with the
// chain: this fixture's hop is pod_host_escape, a workload-level primitive
// (privileged + hostPath, see the e2e fixture testdata/e2e/vulnerable/00-baseline.yaml
// for the real-world shape), and the only binding in the snapshot grants a
// plain `edit` ClusterRole that has nothing to do with escaping to the node.
// Printing "remove the subject from only-binding" told the operator a fix
// closed the chain when it did nothing of the kind, and the cut-resilient
// pass agreed by construction: alternatesForSource only ever models cutting
// the binding a hop's own provenance names (see pathfinder.go's edgeCut), so
// it never simulated cutting only-binding either and never tagged this
// finding privesc:survives-first-cut. The fix and the simulation disagreed.
//
// With no binding provenance, ForPrivescPath must go straight to the
// advisory diff and must never name a binding it did not simulate cutting.
func TestForPrivescPathDoesNotInventABindingCutForSyntheticChains(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team"}
	snap := models.Snapshot{}
	// Kept in the snapshot deliberately: an unrelated binding that lists the
	// subject is exactly what the old subject scan would have matched. Its
	// continued presence is what makes the absence assertion below meaningful.
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
		t.Fatal("ForPrivescPath returned nil for a synthetic-rooted chain, want the advisory hint")
	}
	if strings.Contains(hint.RBACDiff, "only-binding") {
		t.Errorf("diff names a binding cut that was never simulated:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "synthetic edge") {
		t.Errorf("expected the advisory form explaining the chain is synthetic; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch != nil {
		t.Errorf("Patch should be nil for the advisory branch; got %+v", hint.Patch)
	}
}

// TestForPrivescPathSkipsNonPathRule guards the call-site contract: callers
// pass any privesc-analyzer finding through here, but the generator only
// applies to KUBE-PRIVESC-PATH-* findings. Anything else must return nil so
// the call site stays a one-liner that doesn't have to filter rule IDs.
func TestForPrivescPathSkipsNonPathRule(t *testing.T) {
	t.Parallel()

	finding := models.Finding{
		RuleID:  "KUBE-RBAC-OVERBROAD-001",
		Subject: &models.SubjectRef{Kind: "User", Name: "alice"},
		EscalationPath: []models.EscalationHop{
			{Step: 1, Action: "impersonate"},
		},
	}
	if hint := ForPrivescPath(finding, models.Snapshot{}); hint != nil {
		t.Errorf("ForPrivescPath accepted non-PATH rule, got %+v", hint)
	}
}

// TestUnifiedDiffShape is a regression guard for the unified-diff renderer:
// it must produce a single hunk with a stable header and recognisable
// equal / delete / insert markers. Test goldens for the higher-level
// generators above implicitly depend on this shape.
func TestUnifiedDiffShape(t *testing.T) {
	t.Parallel()

	got := unifiedDiff("a/foo", "b/foo", "one\ntwo\nthree\n", "one\nfour\nthree\n")
	want := "--- a/a/foo\n+++ b/b/foo\n@@ -1,3 +1,3 @@\n one\n-two\n+four\n three\n"
	if got != want {
		t.Errorf("unifiedDiff mismatch\n got: %q\nwant: %q", got, want)
	}
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
