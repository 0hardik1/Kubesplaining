package rbac

import (
	"context"
	"strings"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerFindsSecretAndPodCreationAccess(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1ObjectMeta("reader-pod", "default"),
					Spec: corev1.PodSpec{
						ServiceAccountName: "reader",
					},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1ObjectMeta("reader-role", ""),
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"secrets"},
							Verbs:     []string{"get", "list"},
						},
						{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{"create"},
						},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("reader-role", ""),
					RoleRef: rbacv1.RoleRef{
						Kind: "ClusterRole",
						Name: "reader-role",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "reader",
							Namespace: "default",
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-PRIVESC-005")
	assertRulePresent(t, findings, "KUBE-PRIVESC-001")
}

func TestAnalyzerFlagsClusterAdminBinding(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("admins", ""),
					RoleRef: rbacv1.RoleRef{
						Kind: "ClusterRole",
						Name: "cluster-admin",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind: "User",
							Name: "alice@example.com",
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-RBAC-OVERBROAD-001")
}

func TestDescriptionsQualifyBindingAndRoleByKind(t *testing.T) {
	t.Parallel()

	// Mix of cluster-scoped (CRB → CR) and namespace-scoped (RB → Role) so we exercise both helper branches.
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1ObjectMeta("cr-secrets", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
					},
				},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1ObjectMeta("r-pods", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("crb-secrets", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cr-secrets"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "snoop", Namespace: "team-a"}},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("rb-pods", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r-pods"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "team-a"}},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	requireDescriptionContains(t, findings, "KUBE-PRIVESC-005", "ClusterRoleBinding `crb-secrets`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-005", "ClusterRole `cr-secrets`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-001", "RoleBinding `team-a/rb-pods`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-001", "Role `team-a/r-pods`")
}

func TestFormatHelpersRenderKindAndNamespace(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		kind    string
		ns      string
		objName string
		want    string
	}{
		{"clusterrolebinding", "ClusterRoleBinding", "", "crb-foo", "ClusterRoleBinding `crb-foo`"},
		{"clusterrole", "ClusterRole", "", "cr-foo", "ClusterRole `cr-foo`"},
		{"rolebinding", "RoleBinding", "team-a", "rb-foo", "RoleBinding `team-a/rb-foo`"},
		{"role", "Role", "team-a", "r-foo", "Role `team-a/r-foo`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatBindingRef(tc.kind, tc.ns, tc.objName)
			if got != tc.want {
				t.Errorf("formatBindingRef(%q,%q,%q) = %q, want %q", tc.kind, tc.ns, tc.objName, got, tc.want)
			}
		})
	}
}

func requireDescriptionContains(t *testing.T, findings []models.Finding, ruleID, want string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID && strings.Contains(f.Description, want) {
			return
		}
	}
	t.Fatalf("expected rule %s description to contain %q; not found in %d findings", ruleID, want, len(findings))
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}

	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}

func metav1ObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
	}
}
