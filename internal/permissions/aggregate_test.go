package permissions

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAggregateResolvesRoleBindingToNamespacedRules(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "team-a"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
					},
				},
				// Same role name in another namespace must NOT bleed in.
				{
					ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "team-b"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rb-team-a", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "secret-reader"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "deployer", Namespace: ""}, // namespace omitted; falls back to binding ns
					},
				},
			},
		},
	}

	got := Aggregate(snapshot)

	subj := models.SubjectRef{Kind: "ServiceAccount", Namespace: "team-a", Name: "deployer"}
	perms, ok := got[subj.Key()]
	if !ok {
		t.Fatalf("expected subject %q in aggregate, got keys=%v", subj.Key(), keys(got))
	}
	if len(perms.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(perms.Rules))
	}
	rule := perms.Rules[0]
	if rule.Namespace != "team-a" {
		t.Errorf("rule namespace = %q, want team-a", rule.Namespace)
	}
	if rule.SourceRole != "secret-reader" || rule.SourceBinding != "rb-team-a" {
		t.Errorf("rule provenance wrong: role=%q binding=%q", rule.SourceRole, rule.SourceBinding)
	}
	if len(rule.Resources) != 1 || rule.Resources[0] != "secrets" {
		t.Errorf("rule resources = %v, want [secrets]", rule.Resources)
	}
}

func TestAggregateResolvesClusterRoleBindingClusterScoped(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "crb-admins"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "ops"},
						{Kind: "ServiceAccount", Namespace: "platform", Name: "controller"},
					},
				},
			},
		},
	}

	got := Aggregate(snapshot)

	groupKey := models.SubjectRef{Kind: "Group", Name: "ops"}.Key()
	if _, ok := got[groupKey]; !ok {
		t.Fatalf("expected Group %q in aggregate, got keys=%v", groupKey, keys(got))
	}
	saKey := models.SubjectRef{Kind: "ServiceAccount", Namespace: "platform", Name: "controller"}.Key()
	if _, ok := got[saKey]; !ok {
		t.Fatalf("expected SA %q in aggregate, got keys=%v", saKey, keys(got))
	}

	// Rule tied to a ClusterRoleBinding must have empty namespace (cluster-scoped).
	for _, rule := range got[saKey].Rules {
		if rule.Namespace != "" {
			t.Errorf("ClusterRoleBinding rule should be cluster-scoped, got ns=%q", rule.Namespace)
		}
	}
}

func TestAggregateRoleBindingPointingAtClusterRole(t *testing.T) {
	t.Parallel()

	// RoleBindings can reference ClusterRoles; the rules apply within the binding's namespace.
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "view"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rb-viewer", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
				},
			},
		},
	}

	got := Aggregate(snapshot)

	userKey := models.SubjectRef{Kind: "User", Name: "alice"}.Key()
	perms, ok := got[userKey]
	if !ok {
		t.Fatalf("expected User %q in aggregate", userKey)
	}
	if len(perms.Rules) != 1 || perms.Rules[0].Namespace != "team-a" {
		t.Fatalf("expected one rule scoped to team-a, got %#v", perms.Rules)
	}
}

func TestAggregateMissingRoleProducesNoRules(t *testing.T) {
	t.Parallel()

	// Binding references a Role that does not exist; the subject should still be created
	// but with no rules (silently dropped, never fatal).
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rb-broken", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "ghost"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
				},
			},
		},
	}

	got := Aggregate(snapshot)

	userKey := models.SubjectRef{Kind: "User", Name: "bob"}.Key()
	perms, ok := got[userKey]
	if !ok {
		t.Fatalf("expected User %q to be created even with missing role", userKey)
	}
	if len(perms.Rules) != 0 {
		t.Errorf("missing role should produce no rules, got %#v", perms.Rules)
	}
}

func TestAggregateUnionsRulesAcrossBindings(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "team-a"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "team-a"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "b1", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r1"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa-x", Namespace: "team-a"}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "b2", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r2"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa-x", Namespace: "team-a"}},
				},
			},
		},
	}

	got := Aggregate(snapshot)

	saKey := models.SubjectRef{Kind: "ServiceAccount", Namespace: "team-a", Name: "sa-x"}.Key()
	perms, ok := got[saKey]
	if !ok {
		t.Fatalf("expected SA %q in aggregate", saKey)
	}
	if len(perms.Rules) != 2 {
		t.Fatalf("expected 2 rules unioned across bindings, got %d: %#v", len(perms.Rules), perms.Rules)
	}

	bindings := map[string]bool{}
	for _, r := range perms.Rules {
		bindings[r.SourceBinding] = true
	}
	if !bindings["b1"] || !bindings["b2"] {
		t.Errorf("expected both bindings to contribute rules, got %v", bindings)
	}
}

func TestAggregateRulesAreCopiedNotShared(t *testing.T) {
	t.Parallel()

	// Mutating the returned rule slices must not affect the source Role.
	originalVerbs := []string{"get", "list"}
	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "team-a"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: originalVerbs},
		},
	}
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{role},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
				},
			},
		},
	}

	got := Aggregate(snapshot)
	userKey := models.SubjectRef{Kind: "User", Name: "alice"}.Key()

	got[userKey].Rules[0].Verbs[0] = "MUTATED"
	if originalVerbs[0] != "get" {
		t.Errorf("Aggregate did not deep-copy rule verbs; source mutated to %q", originalVerbs[0])
	}
}

func TestSubjectRefFillsServiceAccountNamespaceFromFallback(t *testing.T) {
	t.Parallel()

	got := SubjectRef(rbacv1.Subject{Kind: "ServiceAccount", Name: "deployer"}, "team-a")
	if got.Namespace != "team-a" {
		t.Errorf("expected fallback namespace team-a, got %q", got.Namespace)
	}
}

func TestSubjectRefPreservesExplicitServiceAccountNamespace(t *testing.T) {
	t.Parallel()

	got := SubjectRef(rbacv1.Subject{Kind: "ServiceAccount", Name: "deployer", Namespace: "explicit"}, "team-a")
	if got.Namespace != "explicit" {
		t.Errorf("expected explicit namespace preserved, got %q", got.Namespace)
	}
}

func TestSubjectRefSkipsNamespaceForUserAndGroup(t *testing.T) {
	t.Parallel()

	cases := []struct{ kind, name string }{
		{"User", "alice"},
		{"Group", "ops"},
	}
	for _, tc := range cases {
		got := SubjectRef(rbacv1.Subject{Kind: tc.kind, Name: tc.name, Namespace: "ignored"}, "team-a")
		if got.Namespace != "" {
			t.Errorf("%s should not carry a namespace, got %q", tc.kind, got.Namespace)
		}
		if got.Name != tc.name || got.Kind != tc.kind {
			t.Errorf("subject identity mangled: %#v", got)
		}
	}
}

func TestAggregateEmptySnapshot(t *testing.T) {
	t.Parallel()

	got := Aggregate(models.Snapshot{})
	if len(got) != 0 {
		t.Errorf("empty snapshot should produce empty aggregate, got %d entries", len(got))
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
