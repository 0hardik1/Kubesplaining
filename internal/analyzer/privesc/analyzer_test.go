package privesc

import (
	"context"
	"fmt"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
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

func TestNamespaceScopedRBACDoesNotEmitClusterAdmin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		roleRule     rbacv1.PolicyRule
		bannedRuleID string
	}{
		{
			name: "modify_role_binding via RoleBinding",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"create", "update", "patch"},
			},
			bannedRuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		},
		{
			name: "bind_or_escalate via RoleBinding",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"bind", "escalate"},
			},
			bannedRuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		},
		{
			name: "impersonate users via RoleBinding (dead RBAC, no path)",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
			},
			bannedRuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		},
		{
			name: "impersonate groups via RoleBinding (dead RBAC, no system:masters path)",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"groups"},
				Verbs:     []string{"impersonate"},
			},
			bannedRuleID: "KUBE-PRIVESC-PATH-SYSTEM-MASTERS",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					Namespaces: []corev1.Namespace{
						{ObjectMeta: objectMeta("dev", "")},
					},
					ServiceAccounts: []corev1.ServiceAccount{
						{ObjectMeta: objectMeta("dev-sa", "dev")},
					},
					Roles: []rbacv1.Role{
						{
							ObjectMeta: objectMeta("ns-rule", "dev"),
							Rules:      []rbacv1.PolicyRule{tc.roleRule},
						},
					},
					RoleBindings: []rbacv1.RoleBinding{
						{
							ObjectMeta: objectMeta("ns-rule-binding", "dev"),
							RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "ns-rule"},
							Subjects: []rbacv1.Subject{
								{Kind: "ServiceAccount", Name: "dev-sa", Namespace: "dev"},
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
				if f.Subject == nil || f.Subject.Name != "dev-sa" || f.Subject.Namespace != "dev" {
					continue
				}
				if f.RuleID == tc.bannedRuleID {
					t.Fatalf("namespace-scoped grant produced unexpected %s finding for dev/dev-sa: %+v", tc.bannedRuleID, f)
				}
			}
		})
	}
}

func TestNamespaceScopedRBACEmitsNamespaceAdminPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		roleRule rbacv1.PolicyRule
	}{
		{
			name: "modify_role_binding via RoleBinding emits namespace-admin",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"create", "update", "patch"},
			},
		},
		{
			name: "bind_or_escalate via RoleBinding emits namespace-admin",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"bind", "escalate"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					Namespaces: []corev1.Namespace{
						{ObjectMeta: objectMeta("dev", "")},
					},
					ServiceAccounts: []corev1.ServiceAccount{
						{ObjectMeta: objectMeta("dev-sa", "dev")},
					},
					Roles: []rbacv1.Role{
						{
							ObjectMeta: objectMeta("ns-rule", "dev"),
							Rules:      []rbacv1.PolicyRule{tc.roleRule},
						},
					},
					RoleBindings: []rbacv1.RoleBinding{
						{
							ObjectMeta: objectMeta("ns-rule-binding", "dev"),
							RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "ns-rule"},
							Subjects: []rbacv1.Subject{
								{Kind: "ServiceAccount", Name: "dev-sa", Namespace: "dev"},
							},
						},
					},
				},
			}

			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}

			var match *models.Finding
			for i, f := range findings {
				if f.Subject == nil || f.Subject.Name != "dev-sa" {
					continue
				}
				if f.RuleID == "KUBE-PRIVESC-PATH-NAMESPACE-ADMIN" {
					match = &findings[i]
					break
				}
			}
			if match == nil {
				t.Fatalf("expected KUBE-PRIVESC-PATH-NAMESPACE-ADMIN finding for dev/dev-sa, got findings=%+v", findings)
			}
			if match.Resource == nil || match.Resource.Kind != "Namespace" || match.Resource.Name != "dev" {
				t.Fatalf("expected namespace-admin finding to be anchored to Namespace/dev, got resource=%+v", match.Resource)
			}
			if match.Namespace != "dev" {
				t.Fatalf("expected finding.Namespace = dev, got %q", match.Namespace)
			}
			if match.Severity != models.SeverityHigh {
				t.Fatalf("expected severity HIGH for namespace-admin, got %q", match.Severity)
			}
		})
	}
}

func TestNamespaceScopedImpersonateServiceAccountsEmitsPerSATarget(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("team-a", "")},
				{ObjectMeta: objectMeta("team-b", "")},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{ObjectMeta: objectMeta("impersonator", "team-a")},
				{ObjectMeta: objectMeta("victim", "team-a")},
				{ObjectMeta: objectMeta("out-of-scope", "team-b")},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: objectMeta("impersonate-sa", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"impersonate"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: objectMeta("impersonate-sa-binding", "team-a"),
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "impersonate-sa"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "impersonator", Namespace: "team-a"},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)

	const fromImpersonator = "subject:ServiceAccount/team-a/impersonator"
	var sawTeamAEdge bool
	for _, edge := range graph.Edges {
		if edge.From != fromImpersonator {
			continue
		}
		if edge.To == sinkClusterAdmin || edge.To == sinkSystemMasters {
			t.Fatalf("namespace-scoped impersonate serviceaccounts must not reach a cluster-wide sink: %+v", *edge)
		}
		if edge.Action != "impersonate_serviceaccount" {
			continue
		}
		switch edge.To {
		case "subject:ServiceAccount/team-a/victim", "subject:ServiceAccount/team-a/default":
			sawTeamAEdge = true
		case "subject:ServiceAccount/team-b/out-of-scope", "subject:ServiceAccount/team-b/default":
			t.Fatalf("namespace-scoped impersonate edge leaked into team-b: %+v", *edge)
		case fromImpersonator:
			t.Fatalf("self-edge emitted: %+v", *edge)
		}
	}
	if !sawTeamAEdge {
		var dump []string
		for _, edge := range graph.Edges {
			dump = append(dump, fmt.Sprintf("%+v", *edge))
		}
		t.Fatalf("expected at least one impersonate_serviceaccount edge to a team-a SA, got edges=%v", dump)
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, f := range findings {
		if f.Subject != nil && f.Subject.Name == "impersonator" && f.RuleID == "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
			t.Fatalf("namespace-scoped impersonate serviceaccounts produced cluster-admin finding: %+v", f)
		}
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
