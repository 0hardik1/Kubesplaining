package privesc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func objectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

// TestNameScopedSecretGetNoKubeSystemPath verifies that a cluster-wide `get secrets`
// grant restricted to a specific resourceNames does NOT produce a
// kube-system-secrets escalation path: the sink means "compromise the kube-system
// secret store", which a get on one named secret cannot achieve. An unrestricted
// grant of the same verb still does.
func TestNameScopedSecretGetNoKubeSystemPath(t *testing.T) {
	t.Parallel()

	build := func(rule rbacv1.PolicyRule) models.Snapshot {
		return models.Snapshot{
			Resources: models.SnapshotResources{
				Namespaces:   []corev1.Namespace{{ObjectMeta: objectMeta("default", "")}, {ObjectMeta: objectMeta("kube-system", "")}},
				ClusterRoles: []rbacv1.ClusterRole{{ObjectMeta: objectMeta("reader-role", ""), Rules: []rbacv1.PolicyRule{rule}}},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
					ObjectMeta: objectMeta("reader-role", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "reader-role"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "reader", Namespace: "default"}},
				}},
			},
		}
	}
	hasSecretsPath := func(t *testing.T, snap models.Snapshot) bool {
		t.Helper()
		findings, err := New().Analyze(context.Background(), snap)
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}
		for _, f := range findings {
			if f.RuleID == "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS" {
				return true
			}
		}
		return false
	}

	scoped := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}, ResourceNames: []string{"tls-cert"}}
	if hasSecretsPath(t, build(scoped)) {
		t.Error("name-scoped get secrets must not produce a kube-system-secrets path")
	}
	unrestricted := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}
	if !hasSecretsPath(t, build(unrestricted)) {
		t.Error("unrestricted get secrets should still produce a kube-system-secrets path")
	}
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
						// `create clusterrolebindings` reaches cluster-admin only together
						// with `bind`, which is what clears the API server's escalation
						// check on the binding write.
						{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterrolebindings"}, Verbs: []string{"create"}},
						{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}},
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
				// Enforce Restricted so the direct KUBE-PRIVESC-002
				// (pod_create_privileged_escape) edge does not fire; this test
				// exercises the multi-hop create-pod -> mount SA -> escape chain
				// via the already-running privileged pod. The -002 1-hop edge has
				// its own coverage in TestPrivilegedPodCreateEscapeEdge.
				{ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
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
		name string
		// roleRule is granted through a RoleBinding in namespace dev. clusterRule, when
		// set, is granted through a ClusterRoleBinding, and exists so a case can supply
		// the cluster-scoped half of an RBAC-write conjunction: without it the subject
		// reaches no sink at all and the case would prove nothing about scope.
		roleRule     rbacv1.PolicyRule
		clusterRule  *rbacv1.PolicyRule
		bannedRuleID string
	}{
		{
			name: "modify_role_binding via RoleBinding",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"create", "update", "patch"},
			},
			clusterRule: &rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind"},
			},
			bannedRuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		},
		{
			name: "bind_or_escalate via RoleBinding",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"create", "update", "escalate"},
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

			if tc.clusterRule != nil {
				snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
					{
						ObjectMeta: objectMeta("cluster-rule", ""),
						Rules:      []rbacv1.PolicyRule{*tc.clusterRule},
					},
				}
				snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
					{
						ObjectMeta: objectMeta("cluster-rule-binding", ""),
						RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-rule"},
						Subjects: []rbacv1.Subject{
							{Kind: "ServiceAccount", Name: "dev-sa", Namespace: "dev"},
						},
					},
				}
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
		name string
		// See TestNamespaceScopedRBACDoesNotEmitClusterAdmin for why clusterRule exists:
		// binding a ClusterRole into a namespace needs `bind` on clusterroles, and
		// clusterroles is cluster-scoped, so that half can only arrive this way.
		roleRule    rbacv1.PolicyRule
		clusterRule *rbacv1.PolicyRule
	}{
		{
			name: "modify_role_binding via RoleBinding emits namespace-admin",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
				Verbs:     []string{"create", "update", "patch"},
			},
			clusterRule: &rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
				Verbs:     []string{"bind"},
			},
		},
		{
			name: "bind_or_escalate via RoleBinding emits namespace-admin",
			roleRule: rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles"},
				Verbs:     []string{"create", "update", "escalate"},
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

			if tc.clusterRule != nil {
				snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
					{
						ObjectMeta: objectMeta("cluster-rule", ""),
						Rules:      []rbacv1.PolicyRule{*tc.clusterRule},
					},
				}
				snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
					{
						ObjectMeta: objectMeta("cluster-rule-binding", ""),
						RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-rule"},
						Subjects: []rbacv1.Subject{
							{Kind: "ServiceAccount", Name: "dev-sa", Namespace: "dev"},
						},
					},
				}
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

// hasEdge reports whether the graph carries an edge with the given action from
// `from` to `to`.
func hasEdge(graph *models.EscalationGraph, from, action, to string) bool {
	for _, e := range graph.Edges {
		if e.From == from && e.Action == action && e.To == to {
			return true
		}
	}
	return false
}

// clusterRoleGraph builds a graph for a single ClusterRole (with rules) bound
// cluster-wide to default/<saName>, plus the supplied namespaces.
func clusterRoleGraph(saName string, namespaces []corev1.Namespace, rules ...rbacv1.PolicyRule) *models.EscalationGraph {
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: namespaces,
			ClusterRoles: []rbacv1.ClusterRole{
				{ObjectMeta: objectMeta("role", ""), Rules: rules},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("role", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "role"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: "default"}},
				},
			},
		},
	}
	return BuildGraph(snapshot)
}

// TestPrivilegedPodCreateEscapeEdge covers the KUBE-PRIVESC-002 graph edge: a
// pod-create grant in a namespace that allows privileged pods yields a direct
// edge to the node-escape sink; a Restricted-enforced namespace suppresses it.
func TestPrivilegedPodCreateEscapeEdge(t *testing.T) {
	t.Parallel()

	permissive := []corev1.Namespace{{ObjectMeta: objectMeta("dev", "")}}
	graph := clusterRoleGraph("deployer", permissive,
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}})
	if !hasEdge(graph, "subject:ServiceAccount/default/deployer", "pod_create_privileged_escape", sinkNodeEscape) {
		t.Fatalf("expected pod_create_privileged_escape edge to node-escape sink, edges=%v", graph.Edges)
	}

	restricted := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "dev", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
	}
	graph = clusterRoleGraph("deployer", restricted,
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}})
	if hasEdge(graph, "subject:ServiceAccount/default/deployer", "pod_create_privileged_escape", sinkNodeEscape) {
		t.Fatalf("restricted namespace must suppress the pod_create_privileged_escape edge")
	}
}

// TestSecretMintEdge covers the KUBE-PRIVESC-007 graph edge: cluster-scoped
// create + get on secrets yields an edge to the token-mint sink.
func TestSecretMintEdge(t *testing.T) {
	t.Parallel()

	graph := clusterRoleGraph("minter", nil,
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "get"}})
	if !hasEdge(graph, "subject:ServiceAccount/default/minter", "secret_mint_token", sinkTokenMint) {
		t.Fatalf("expected secret_mint_token edge to token-mint sink, edges=%v", graph.Edges)
	}

	// create-only must not produce the edge.
	graph = clusterRoleGraph("creator", nil,
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}})
	if hasEdge(graph, "subject:ServiceAccount/default/creator", "secret_mint_token", sinkTokenMint) {
		t.Fatalf("create-only secrets grant must not produce a secret_mint_token edge")
	}
}

// TestNodeMigrateEdge covers the KUBE-PRIVESC-016 graph edge: delete pods plus
// cluster-scoped node manipulation yields an edge to the node-escape sink.
func TestNodeMigrateEdge(t *testing.T) {
	t.Parallel()

	graph := clusterRoleGraph("drainer", nil,
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"delete"}})
	if !hasEdge(graph, "subject:ServiceAccount/default/drainer", "node_drain_migrate", sinkNodeEscape) {
		t.Fatalf("expected node_drain_migrate edge to node-escape sink, edges=%v", graph.Edges)
	}
}

// TestEphemeralContainerEdge covers the KUBE-PRIVESC-013 graph edge: an
// ephemeral-container grant targets the ServiceAccounts that running pods mount.
func TestEphemeralContainerEdge(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{{ObjectMeta: objectMeta("default", "")}},
			Pods: []corev1.Pod{
				{ObjectMeta: objectMeta("victim-pod", "default"), Spec: corev1.PodSpec{ServiceAccountName: "victim"}},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{ObjectMeta: objectMeta("injector", ""), Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"}, Verbs: []string{"patch"}},
				}},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("injector", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "injector"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "injector", Namespace: "default"}},
				},
			},
		},
	}
	graph := BuildGraph(snapshot)
	if !hasEdge(graph, "subject:ServiceAccount/default/injector", "ephemeral_container_inject", "subject:ServiceAccount/default/victim") {
		t.Fatalf("expected ephemeral_container_inject edge to the victim pod's SA, edges=%v", graph.Edges)
	}
}

// TestDifficultyScoringPrefersEasyLongChains proves a long chain of trivial hops
// outranks a short chain that needs attacker-controlled infrastructure. Under the
// old length-only attenuation this ordering was backwards.
func TestDifficultyScoringPrefersEasyLongChains(t *testing.T) {
	t.Parallel()

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
// downgrades severity: a deep chain of ordinary RBAC grants is still critical.
func TestDifficultyScoringKeepsEasyChainsCritical(t *testing.T) {
	t.Parallel()

	easyHop := models.EscalationHop{Action: "impersonate", Difficulty: "easy"}
	hops := []models.EscalationHop{easyHop, easyHop, easyHop, easyHop}

	severity, _, _ := targetScoring(models.TargetClusterAdmin, hops)
	if severity != models.SeverityCritical {
		t.Fatalf("a 4-hop all-easy chain to cluster-admin should stay critical, got %s", severity)
	}
}

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

// TestFindingRemediationNamesEvaluatedCutWhenAlternateExists is the regression
// test for defect (c): CSV and SARIF consumers see only Finding.Remediation and
// Finding.Tags, with nothing saying which cut "privesc:survives-first-cut" is
// about. hopsRemediation often recommends a different, cheaper mid-chain hop, so
// without this sentence a reader can misattribute the tag to that hop instead of
// to the hop-1 binding cut the alternate pass actually evaluated.
func TestFindingRemediationNamesEvaluatedCutWhenAlternateExists(t *testing.T) {
	path := models.EscalationPath{
		Source: models.SubjectRef{Kind: "ServiceAccount", Name: "twice", Namespace: "app"},
		Target: models.TargetClusterAdmin,
		Hops: []models.EscalationHop{
			{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "admin-a", Permission: "cluster-admin"},
		},
		AlternateHops: []models.EscalationHop{
			{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "admin-b", Permission: "cluster-admin"},
		},
	}

	finding := findingFromPath(path)

	if !strings.Contains(finding.Remediation, "admin-a") {
		t.Errorf("Remediation should name hop 1's binding (admin-a), the one the alternate pass actually cut: %q", finding.Remediation)
	}
	if !strings.Contains(finding.Remediation, "survives") {
		t.Errorf("Remediation should note that a route survives the evaluated cut: %q", finding.Remediation)
	}
}

// TestFindingRemediationUnchangedWithoutAlternate proves the common case (no
// alternate) keeps today's Remediation prose byte-for-byte, per the brief's
// smallest-fix constraint.
func TestFindingRemediationUnchangedWithoutAlternate(t *testing.T) {
	hops := []models.EscalationHop{{Step: 1, Action: "bound_to_cluster_admin", SourceBinding: "only", Permission: "cluster-admin"}}
	path := models.EscalationPath{
		Source: models.SubjectRef{Kind: "ServiceAccount", Name: "once", Namespace: "app"},
		Target: models.TargetClusterAdmin,
		Hops:   hops,
	}

	finding := findingFromPath(path)
	want := contentClusterAdminPath(path.Source, hops).Remediation
	if finding.Remediation != want {
		t.Errorf("Remediation changed for a finding without an alternate:\ngot:  %q\nwant: %q", finding.Remediation, want)
	}
}

// TestFindingFromPathSuffixesAWSIAMRoleIDByARN is the direct regression test for
// defect (b): findingFromPath must not collapse two different AWS IAM roles into
// one finding ID. Target and TargetNamespace are identical for every IAM role path
// (the enum is always aws_iam_role, the namespace is always empty), so without a
// per-role suffix the ID built from ruleID:sourceKey:target alone is byte-identical
// for both roles below.
//
// The suffix comes from the terminal hop's ToSubject.Name (the raw ARN), not the
// sanitized TargetID node ID: buildPath already sets that field to the external
// node's Subject, whose Name is the ARN, so no further plumbing is needed. This
// also proves the ARN wins over TargetID when both are available.
func TestFindingFromPathSuffixesAWSIAMRoleIDByARN(t *testing.T) {
	source := models.SubjectRef{Kind: "ServiceAccount", Name: "deployer", Namespace: "app"}
	pathTo := func(arn, targetID string) models.EscalationPath {
		return models.EscalationPath{
			Source:   source,
			Target:   models.TargetAWSIAMRole,
			TargetID: targetID,
			Hops: []models.EscalationHop{
				{Step: 1, Action: "irsa_assume_role", Permission: arn, ToSubject: models.SubjectRef{Kind: "User", Name: arn}},
			},
		}
	}

	roleOneARN := "arn:aws:iam::111111111111:role/RoleOne"
	roleTwoARN := "arn:aws:iam::222222222222:role/RoleTwo"
	f1 := findingFromPath(pathTo(roleOneARN, "external:aws-iam:role-one"))
	f2 := findingFromPath(pathTo(roleTwoARN, "external:aws-iam:role-two"))

	if f1.ID == f2.ID {
		t.Fatalf("two different IAM roles produced the same finding ID: %q", f1.ID)
	}
	if !strings.Contains(f1.ID, roleOneARN) {
		t.Errorf("f1.ID = %q, want it to contain the ARN %q", f1.ID, roleOneARN)
	}
	if !strings.Contains(f2.ID, roleTwoARN) {
		t.Errorf("f2.ID = %q, want it to contain the ARN %q", f2.ID, roleTwoARN)
	}
	if strings.Contains(f1.ID, "external:aws-iam:") {
		t.Errorf("f1.ID = %q, should prefer the raw ARN over the sanitized TargetID node ID", f1.ID)
	}
}

// TestFindingFromPathAWSIAMRoleIDFallsBackToTargetID covers the defensive fallback:
// a path with no hops (should not happen in practice, since the source is never a
// sink) still gets a stable, non-colliding suffix from TargetID rather than an
// empty one.
func TestFindingFromPathAWSIAMRoleIDFallsBackToTargetID(t *testing.T) {
	path := models.EscalationPath{
		Source:   models.SubjectRef{Kind: "ServiceAccount", Name: "deployer", Namespace: "app"},
		Target:   models.TargetAWSIAMRole,
		TargetID: "external:aws-iam:role-one",
	}
	finding := findingFromPath(path)
	if !strings.HasSuffix(finding.ID, ":external:aws-iam:role-one") {
		t.Errorf("finding.ID = %q, want it to end with the TargetID fallback", finding.ID)
	}
}

// twoIRSARoleSnapshot builds a fixture where one source (deployer) has `create
// pods` in a namespace hosting two ServiceAccounts, each carrying a different
// eks.amazonaws.com/role-arn annotation. deployer reaches both roles via a 2-hop
// pod-create-then-assume-role chain, so both paths tie on Source, Target
// (aws_iam_role for both), TargetNamespace (empty for both), and hop count (2 for
// both): the exact shape behind defect (b).
func twoIRSARoleSnapshot() models.Snapshot {
	snapshot := models.Snapshot{Metadata: models.SnapshotMetadata{CloudProvider: "eks"}}
	snapshot.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: objectMeta("app", "")}}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("deployer", "app")},
		{ObjectMeta: metav1.ObjectMeta{
			Name: "sa-a", Namespace: "app",
			Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::111111111111:role/RoleOne"},
		}},
		{ObjectMeta: metav1.ObjectMeta{
			Name: "sa-b", Namespace: "app",
			Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::222222222222:role/RoleTwo"},
		}},
	}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: objectMeta("pod-creator", "app"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: objectMeta("pod-creator-binding", "app"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "app"},
			},
		},
	}
	return snapshot
}

// TestAWSIAMRoleFindingIDsDistinguishTwoRoles is the end-to-end regression test for
// defect (b): a subject that can reach two different AWS IAM roles must produce two
// distinct findings, not one that silently drops whichever role lost the map
// iteration race. Cross-reference: this is the same under-specified-key defect Task
// 11 fixed one layer up, at the engine's dedupe key (see analyzer/correlate.go and
// its dedupeKey); this is it one layer down, inside privesc's own `seen` map in
// Analyze.
//
// Before the fix both chains produced the byte-identical ID
// "KUBE-PRIVESC-PATH-AWS-IAM-ROLE:ServiceAccount/app/deployer:aws_iam_role" (Target
// and TargetNamespace tie because both are the enum aws_iam_role and empty
// respectively), and Analyze's seen map silently kept whichever sorted first. An
// out-of-process audit measured a 26/4 split across 30 runs.
//
// Asserting len == 2 is not enough: a regression that names the same role twice
// under two coincidentally different IDs would still pass a bare length check. This
// asserts both roles are present by name, identically across N runs, since the
// underlying nondeterminism (ties broken by map iteration order) would otherwise
// turn a real regression into an intermittent flake instead of a clean failure.
func TestAWSIAMRoleFindingIDsDistinguishTwoRoles(t *testing.T) {
	snapshot := twoIRSARoleSnapshot()

	for i := 0; i < 20; i++ {
		findings, err := New().Analyze(context.Background(), snapshot)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}

		var deployerFindings []models.Finding
		for _, f := range findings {
			if f.RuleID != "KUBE-PRIVESC-PATH-AWS-IAM-ROLE" {
				continue
			}
			if f.Subject == nil || f.Subject.Key() != "ServiceAccount/app/deployer" {
				continue
			}
			deployerFindings = append(deployerFindings, f)
		}

		if len(deployerFindings) != 2 {
			t.Fatalf("run %d: want 2 deployer AWS IAM role findings, got %d: %+v", i, len(deployerFindings), deployerFindings)
		}

		ids := map[string]bool{}
		var sawRoleOne, sawRoleTwo bool
		for _, f := range deployerFindings {
			ids[f.ID] = true
			if strings.Contains(string(f.Evidence), "RoleOne") {
				sawRoleOne = true
			}
			if strings.Contains(string(f.Evidence), "RoleTwo") {
				sawRoleTwo = true
			}
		}
		if len(ids) != 2 {
			t.Fatalf("run %d: want 2 distinct finding IDs, got %v", i, ids)
		}
		if !sawRoleOne || !sawRoleTwo {
			t.Fatalf("run %d: want both RoleOne and RoleTwo named, sawRoleOne=%v sawRoleTwo=%v (%+v)", i, sawRoleOne, sawRoleTwo, deployerFindings)
		}
	}
}
