package rbac

import (
	"context"
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
