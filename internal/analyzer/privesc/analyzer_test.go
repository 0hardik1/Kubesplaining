package privesc

import (
	"context"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func objectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

func TestAnalyzerFindsClusterAdminAndSecretsPaths(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("default", "")},
				{ObjectMeta: objectMeta("kube-system", "")},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: objectMeta("reader-pod", "default"),
					Spec:       corev1.PodSpec{ServiceAccountName: "reader"},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: objectMeta("reader-role", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
						{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterrolebindings"}, Verbs: []string{"create"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("reader-role", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "reader-role"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "reader", Namespace: "default"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	var sawClusterAdmin, sawSecrets bool
	for _, f := range findings {
		if f.RuleID == "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" && f.Subject != nil && f.Subject.Name == "reader" {
			sawClusterAdmin = true
		}
		if f.RuleID == "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS" && f.Subject != nil && f.Subject.Name == "reader" {
			sawSecrets = true
		}
	}
	if !sawClusterAdmin {
		t.Fatalf("expected cluster-admin path from reader SA, findings=%v", findings)
	}
	if !sawSecrets {
		t.Fatalf("expected kube-system-secrets path from reader SA, findings=%v", findings)
	}
}

func TestAnalyzerFindsPodEscapeChain(t *testing.T) {
	t.Parallel()

	privileged := true
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("default", "")},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: objectMeta("risky", "default"),
					Spec: corev1.PodSpec{
						ServiceAccountName: "default",
						Containers: []corev1.Container{
							{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}},
						},
					},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: objectMeta("pod-creator", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("pod-creator", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-creator"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "deployer", Namespace: "default"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	var sawNodeEscape bool
	for _, f := range findings {
		if f.RuleID == "KUBE-PRIVESC-PATH-NODE-ESCAPE" && f.Subject != nil && f.Subject.Name == "deployer" && len(f.EscalationPath) >= 2 {
			sawNodeEscape = true
			break
		}
	}
	if !sawNodeEscape {
		t.Fatalf("expected multi-hop node-escape path from deployer SA, findings=%v", findings)
	}
}

func TestAnalyzerSkipsSystemSubjects(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("system-admin", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "system:masters"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, f := range findings {
		if f.Subject != nil && f.Subject.Name == "system:masters" {
			t.Fatalf("did not expect finding for system:masters subject, got %+v", f)
		}
	}
}
