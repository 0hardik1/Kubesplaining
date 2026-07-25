package privesc

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCSRApproveEdgeRequiresBothHalves checks the post-pass: a subject must
// hold cluster-scoped `create csr` AND cluster-scoped `update csr/approval`
// before the graph emits an edge to the system:masters sink. Each verb in
// isolation must NOT emit the edge.
func TestCSRApproveEdgeRequiresBothHalves(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		rules      []rbacv1.PolicyRule
		expectEdge bool
	}{
		{
			name: "only create — no edge",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
			},
			expectEdge: false,
		},
		{
			name: "only approve — no edge",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			},
			expectEdge: false,
		},
		{
			name: "both halves — edge fires",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			},
			expectEdge: true,
		},
		{
			name: "both halves via patch verb — edge fires",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"patch"}},
			},
			expectEdge: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					ClusterRoles: []rbacv1.ClusterRole{
						{ObjectMeta: objectMeta("csr-role", ""), Rules: tc.rules},
					},
					ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
						{
							ObjectMeta: objectMeta("csr-binding", ""),
							RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "csr-role"},
							Subjects: []rbacv1.Subject{
								{Kind: "ServiceAccount", Name: "csr-sa", Namespace: "default"},
							},
						},
					},
				},
			}
			graph := BuildGraph(snapshot)
			const subjectID = "subject:ServiceAccount/default/csr-sa"
			var sawEdge bool
			for _, edge := range graph.Edges {
				if edge.From != subjectID {
					continue
				}
				if edge.Action == "csr_approve" && edge.To == sinkSystemMasters {
					sawEdge = true
					if edge.Technique != "KUBE-PRIVESC-011" {
						t.Errorf("expected csr_approve edge to carry Technique=KUBE-PRIVESC-011, got %q", edge.Technique)
					}
				}
			}
			if sawEdge != tc.expectEdge {
				t.Fatalf("expectEdge=%v, sawEdge=%v; edges=%+v", tc.expectEdge, sawEdge, graph.Edges)
			}
		})
	}
}

// TestCSRApproveEdgeRequiresClusterScope guards that namespace-scoped grants
// (impossible in practice for CSRs, which are cluster-scoped, but worth a
// regression test) do NOT count toward either half.
func TestCSRApproveEdgeRequiresClusterScope(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{
				{
					ObjectMeta: objectMeta("csr-role-ns", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: objectMeta("csr-rb", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "csr-role-ns"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "csr-sa-ns", Namespace: "team-a"},
					},
				},
			},
		},
	}
	graph := BuildGraph(snapshot)
	for _, edge := range graph.Edges {
		if edge.Action == "csr_approve" {
			t.Fatalf("namespace-scoped grant produced unexpected csr_approve edge: %+v", *edge)
		}
	}
}

// TestImpersonateSystemMastersEdgeFires confirms the existing system:masters
// edge still emits when a subject holds cluster-scoped `impersonate groups`
// (which covers impersonating system:masters). The edge predates the CSR work;
// this test locks in its presence so future refactors don't drop it.
func TestImpersonateSystemMastersEdgeFires(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: objectMeta("imp-groups", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"groups"}, Verbs: []string{"impersonate"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("imp-groups-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "imp-groups"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "imp-sa", Namespace: "default"},
					},
				},
			},
		},
	}
	graph := BuildGraph(snapshot)
	const subjectID = "subject:ServiceAccount/default/imp-sa"
	var sawEdge bool
	for _, edge := range graph.Edges {
		if edge.From != subjectID {
			continue
		}
		if edge.To == sinkSystemMasters && edge.Action == "impersonate_system_masters" {
			sawEdge = true
			break
		}
	}
	if !sawEdge {
		var dump []string
		for _, e := range graph.Edges {
			dump = append(dump, e.Action+"/"+e.From+"→"+e.To)
		}
		t.Fatalf("expected impersonate_system_masters edge from %s to %s; got edges=%v", subjectID, sinkSystemMasters, dump)
	}
}

// TestCSRApprovePathReachesSystemMasters wires the per-edge check above into a
// full BFS run: the analyzer must emit a KUBE-PRIVESC-PATH-SYSTEM-MASTERS
// finding for a subject that holds both CSR halves.
func TestCSRApprovePathReachesSystemMasters(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("default", "")},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: objectMeta("csr-takeover", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("csr-takeover-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "csr-takeover"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "csr-attacker", Namespace: "default"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	var sawSystemMasters bool
	for _, f := range findings {
		if f.RuleID != "KUBE-PRIVESC-PATH-SYSTEM-MASTERS" {
			continue
		}
		if f.Subject == nil || f.Subject.Name != "csr-attacker" {
			continue
		}
		sawSystemMasters = true
		var sawCSRHop bool
		for _, h := range f.EscalationPath {
			if h.Action == "csr_approve" {
				sawCSRHop = true
				break
			}
		}
		if !sawCSRHop {
			t.Errorf("KUBE-PRIVESC-PATH-SYSTEM-MASTERS for csr-attacker missing csr_approve hop: %+v", f.EscalationPath)
		}
	}
	if !sawSystemMasters {
		t.Fatalf("expected KUBE-PRIVESC-PATH-SYSTEM-MASTERS finding for csr-attacker, got %d findings", len(findings))
	}
}

// TestControlPlaneSAIsTraversableButNotASource proves a non-system kube-system
// ServiceAccount can serve as a chain intermediate while never seeding a search.
func TestControlPlaneSAIsTraversableButNotASource(t *testing.T) {
	t.Parallel()

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

// TestNamespaceAdminReachesColocatedServiceAccounts proves the namespace-admin
// sink is walked past into the ServiceAccounts that live in that namespace, so a
// subject bounded to one namespace still surfaces the cluster-admin-bound identity
// co-hosted there.
func TestNamespaceAdminReachesColocatedServiceAccounts(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("tenant", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("powerful", "tenant")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: objectMeta("binder", "tenant"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"rolebindings"},
			Verbs:     []string{"create"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("binder-rb", "tenant"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "binder"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "attacker", Namespace: "tenant"}},
	}}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: objectMeta("powerful-crb", ""),
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

// TestControlPlaneNodeEscapeContinuation proves node-root continues to system:masters
// only when a schedulable control-plane node exists in the snapshot. On a properly
// tainted multi-node cluster an escaping tenant pod lands on a worker, where no
// cluster PKI lives, so continuing would be a false positive.
func TestControlPlaneNodeEscapeContinuation(t *testing.T) {
	t.Parallel()

	cpNode := func(taints []corev1.Taint) corev1.Node {
		meta := objectMeta("cp-0", "")
		meta.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
		return corev1.Node{ObjectMeta: meta, Spec: corev1.NodeSpec{Taints: taints}}
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
		{"workers only", []corev1.Node{{ObjectMeta: objectMeta("w-0", "")}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := models.Snapshot{}
			snapshot.Resources.Nodes = tc.nodes
			snapshot.Resources.Pods = []corev1.Pod{{
				ObjectMeta: objectMeta("escaper", "app"),
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
