package privesc

import (
	"context"
	"slices"
	"sort"
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

// TestCSRApproveEdgeWildcardGrantors pins the split addCSRApprovalEdge keeps between
// the two questions it asks about each CSR half.
//
// "Does this half exist?" gates emission and ignores full `*/*/*` rules: a subject
// whose only grant is a wildcard is already reported as cluster-admin in one hop
// through that same binding, so a second route to system:masters would be noise. That
// was the behaviour of the wildcard early return in addEdgesForRule, which the CSR
// halves used to sit behind, and it must not change.
//
// "Who grants this half?" feeds CutBreakers and DOES count wildcard rules, because a
// wildcard binding really does grant both verbs. Before the split, a wildcard binding
// was invisible to collection, so a half it granted alongside a narrow binding looked
// like it had a sole grantor. The cut pass then banned the csr_approve edge on the
// narrow binding's cut and reported the route closed, while the wildcard binding still
// opened it: a surviving route reported as remediated, which hides exposure.
func TestCSRApproveEdgeWildcardGrantors(t *testing.T) {
	t.Parallel()

	wildcard := rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}
	// Same wildcard pinned to resourceNames. permissions.Grants drops `create` on a
	// top-level resource when resourceNames is set (create carries no object name at
	// authorization time) but keeps update/patch on a subresource, so this rule really
	// grants the approve half and really does not grant the create half.
	wildcardNamed := rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}, ResourceNames: []string{"pinned"}}
	createHalf := rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}}
	approveHalf := rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}}

	type binding struct {
		name  string
		rules []rbacv1.PolicyRule
	}

	cases := []struct {
		name string
		// clusterBindings each become a ClusterRole plus a ClusterRoleBinding of the
		// same name granting it to the subject.
		clusterBindings []binding
		// namespacedBinding, when set, becomes a Role plus a RoleBinding in namespace
		// "team-a". CSRs are cluster-scoped, so it must count for neither question.
		namespacedBinding *binding
		expectEdge        bool
		wantBreakers      []string
	}{
		{
			name:            "pure wildcard subject emits no edge",
			clusterBindings: []binding{{name: "crb-wild", rules: []rbacv1.PolicyRule{wildcard}}},
			expectEdge:      false,
		},
		{
			name: "wildcard beside a narrow create-only binding emits no edge",
			clusterBindings: []binding{
				{name: "crb-wild", rules: []rbacv1.PolicyRule{wildcard}},
				{name: "crb-create", rules: []rbacv1.PolicyRule{createHalf}},
			},
			expectEdge: false,
		},
		{
			name:            "single narrow binding is the sole grantor of both halves",
			clusterBindings: []binding{{name: "crb-csr", rules: []rbacv1.PolicyRule{createHalf, approveHalf}}},
			expectEdge:      true,
			wantBreakers:    []string{"crb-csr"},
		},
		{
			name: "wildcard beside a narrow binding leaves neither half with a sole grantor",
			clusterBindings: []binding{
				{name: "crb-wild", rules: []rbacv1.PolicyRule{wildcard}},
				{name: "crb-csr", rules: []rbacv1.PolicyRule{createHalf, approveHalf}},
			},
			expectEdge:   true,
			wantBreakers: nil,
		},
		{
			name: "wildcard pinned to resourceNames grants only the approve half",
			clusterBindings: []binding{
				{name: "crb-wild-named", rules: []rbacv1.PolicyRule{wildcardNamed}},
				{name: "crb-csr", rules: []rbacv1.PolicyRule{createHalf, approveHalf}},
			},
			expectEdge: true,
			// The approve half now has two grantors and contributes nothing; the create
			// half still has crb-csr alone, so cutting it does close the route.
			wantBreakers: []string{"crb-csr"},
		},
		{
			name:              "namespaced wildcard grants neither half of a cluster-scoped primitive",
			clusterBindings:   []binding{{name: "crb-csr", rules: []rbacv1.PolicyRule{createHalf, approveHalf}}},
			namespacedBinding: &binding{name: "rb-wild", rules: []rbacv1.PolicyRule{wildcard}},
			expectEdge:        true,
			wantBreakers:      []string{"crb-csr"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "csr-sa", Namespace: "default"}
			snapshot := models.Snapshot{}
			for _, b := range tc.clusterBindings {
				snapshot.Resources.ClusterRoles = append(snapshot.Resources.ClusterRoles, rbacv1.ClusterRole{
					ObjectMeta: objectMeta(b.name+"-role", ""),
					Rules:      b.rules,
				})
				snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
					ObjectMeta: objectMeta(b.name, ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: b.name + "-role"},
					Subjects:   []rbacv1.Subject{subject},
				})
			}
			if b := tc.namespacedBinding; b != nil {
				snapshot.Resources.Roles = append(snapshot.Resources.Roles, rbacv1.Role{
					ObjectMeta: objectMeta(b.name+"-role", "team-a"),
					Rules:      b.rules,
				})
				snapshot.Resources.RoleBindings = append(snapshot.Resources.RoleBindings, rbacv1.RoleBinding{
					ObjectMeta: objectMeta(b.name, "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: b.name + "-role"},
					Subjects:   []rbacv1.Subject{subject},
				})
			}

			graph := BuildGraph(snapshot)
			const subjectID = "subject:ServiceAccount/default/csr-sa"
			var edges []*models.EscalationEdge
			for _, edge := range graph.Edges {
				if edge.From == subjectID && edge.Action == "csr_approve" {
					edges = append(edges, edge)
				}
			}
			if !tc.expectEdge {
				if len(edges) != 0 {
					t.Fatalf("want no csr_approve edge, got %d: %+v", len(edges), edges[0])
				}
				return
			}
			if len(edges) != 1 {
				t.Fatalf("want exactly 1 csr_approve edge, got %d; edges=%+v", len(edges), graph.Edges)
			}
			// A correlation edge stays uncuttable in its own right: it extends the ban
			// predicate through CutBreakers only, never through edgeCut. Stamping a
			// SourceBinding here would also make it a candidate first-hop cut key,
			// which would change which alternates get searched for.
			if edges[0].SourceBinding != "" || edges[0].BindingNamespace != "" {
				t.Errorf("csr_approve edge must carry no binding provenance, got %+v", *edges[0])
			}
			var got []string
			for _, b := range edges[0].CutBreakers {
				got = append(got, b.Name)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.wantBreakers...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("CutBreakers: got %v, want %v", got, want)
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
// cutting and the cut-resilient pass must skip it. Scoped to the pod_host_escape
// action rather than every edge into sinkNodeEscape, because
// pod_create_privileged_escape also targets that sink and, unlike this one, DOES
// carry provenance (see TestPrivilegedPodCreateEdgeStampsProvenance).
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
		if edge.Action != "pod_host_escape" {
			continue
		}
		checked++
		if edge.SourceBinding != "" || edge.SourceRole != "" {
			t.Errorf("pod-escape edge %q carries provenance %q/%q, want none",
				edge.Action, edge.SourceBinding, edge.SourceRole)
		}
	}
	if checked == 0 {
		t.Fatal("no pod_host_escape edge emitted; fixture is wrong")
	}
}

// TestPrivilegedPodCreateEdgeStampsProvenance proves the KUBE-PRIVESC-002
// pod_create_privileged_escape edge carries the granting binding. Unlike
// addSecretMintEdge and addNodeMigrateEdge, which correlate two rules that may
// come from two different bindings, this edge derives from a single `create
// pods` rule, so naming the binding is unambiguous and the cut-resilient pass
// must be able to key off it.
func TestPrivilegedPodCreateEdgeStampsProvenance(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "dev"}},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "dev"}},
	}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-creator", Namespace: "dev"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-creator-binding", Namespace: "dev"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
	}

	graph := BuildGraph(snapshot)

	var found bool
	for _, edge := range graph.Edges {
		if edge.Action != "pod_create_privileged_escape" {
			continue
		}
		found = true
		if edge.SourceBinding != "pod-creator-binding" {
			t.Errorf("edge SourceBinding = %q, want %q", edge.SourceBinding, "pod-creator-binding")
		}
		if edge.SourceRole != "pod-creator" {
			t.Errorf("edge SourceRole = %q, want %q", edge.SourceRole, "pod-creator")
		}
		if edge.BindingNamespace != "dev" {
			t.Errorf("edge BindingNamespace = %q, want %q", edge.BindingNamespace, "dev")
		}
	}
	if !found {
		t.Fatal("no pod_create_privileged_escape edge emitted; fixture is wrong")
	}
}

// TestPrivilegedPodCreateEmitsEdgePerBinding pins that two bindings granting the same
// capability produce two edges. Collapsing them to one makes the cut-resilient pass
// report a route closed while the second binding still opens it, which is the failure
// this whole feature exists to prevent.
func TestPrivilegedPodCreateEmitsEdgePerBinding(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("team-a", "")},
		{ObjectMeta: objectMeta("team-b", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("deployer", "dev")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: objectMeta("pod-creator-a", "team-a"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
		{
			ObjectMeta: objectMeta("pod-creator-b", "team-b"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create"},
			}},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: objectMeta("deploy-a", "team-a"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator-a"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
		{
			ObjectMeta: objectMeta("deploy-b", "team-b"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator-b"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
	}

	graph := BuildGraph(snapshot)

	const subjectID = "subject:ServiceAccount/dev/deployer"
	bindings := map[string]bool{}
	var count int
	for _, edge := range graph.Edges {
		if edge.From != subjectID || edge.To != sinkNodeEscape || edge.Action != "pod_create_privileged_escape" {
			continue
		}
		count++
		bindings[edge.SourceBinding] = true
	}
	if count != 2 {
		t.Fatalf("want 2 pod_create_privileged_escape edges, got %d (edges=%+v)", count, graph.Edges)
	}
	for _, want := range []string{"deploy-a", "deploy-b"} {
		if !bindings[want] {
			t.Errorf("no pod_create_privileged_escape edge stamped with binding %q; got %v", want, bindings)
		}
	}
}

// TestPrivilegedPodCreateDedupesWithinOneBinding keeps the fix from swinging too far:
// one binding whose Role carries two rules that both match must still yield one edge,
// or a role with many pod rules would fan out into meaningless parallel edges.
func TestPrivilegedPodCreateDedupesWithinOneBinding(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("team-a", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("deployer", "dev")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: objectMeta("pod-creator", "team-a"),
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"pods", "secrets"},
					Verbs:     []string{"create"},
				},
			},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: objectMeta("deploy-a", "team-a"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-creator"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "dev"},
			},
		},
	}

	graph := BuildGraph(snapshot)

	const subjectID = "subject:ServiceAccount/dev/deployer"
	var count int
	for _, edge := range graph.Edges {
		if edge.From != subjectID || edge.To != sinkNodeEscape || edge.Action != "pod_create_privileged_escape" {
			continue
		}
		count++
	}
	if count != 1 {
		t.Fatalf("want 1 pod_create_privileged_escape edge (two rules, one binding), got %d (edges=%+v)", count, graph.Edges)
	}
}

// TestNodeMigrateEdgeRecordsSoleGrantorAsCutBreaker covers the audit's reproduction:
// one ClusterRole grants both halves of the node_drain_migrate correlation (delete
// pods, node manipulation), bound by ONE ClusterRoleBinding. The edge still carries
// no SourceBinding, because no single binding "granted" the correlation, but that one
// binding is the sole grantor of both halves, so removing the subject from it would
// break the edge. CutBreakers must name it.
func TestNodeMigrateEdgeRecordsSoleGrantorAsCutBreaker(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("agent", "ops")},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta: objectMeta("node-ops", ""),
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
				{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"update"}},
			},
		},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("node-ops-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "node-ops"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"},
			},
		},
	}

	graph := BuildGraph(snapshot)

	var found bool
	for _, edge := range graph.Edges {
		if edge.Action != "node_drain_migrate" {
			continue
		}
		found = true
		if edge.SourceBinding != "" {
			t.Errorf("SourceBinding = %q, want empty: no single binding grants the correlation", edge.SourceBinding)
		}
		if len(edge.CutBreakers) != 1 {
			t.Fatalf("want 1 CutBreaker, got %d (%+v)", len(edge.CutBreakers), edge.CutBreakers)
		}
		if edge.CutBreakers[0].Name != "node-ops-crb" || edge.CutBreakers[0].Namespace != "" {
			t.Errorf("CutBreakers[0] = %+v, want {Name: node-ops-crb, Namespace: \"\"}", edge.CutBreakers[0])
		}
	}
	if !found {
		t.Fatal("no node_drain_migrate edge emitted; fixture is wrong")
	}
}

// TestNodeMigrateEdgeHasNoCutBreakerWhenEachHalfHasTwoGrantors is the guard rail
// against over-banning: when EACH half is granted redundantly by two different
// bindings, cutting either one alone leaves the other binding still granting BOTH
// halves, so the correlation survives and CutBreakers must stay empty. (An earlier
// version of this test used a fixture where the two halves were partitioned across
// the two bindings instead of duplicated on both; that fixture actually proves the
// opposite property. See TestNodeMigrateEdgeRecordsBothSoleGrantorsWhenHalvesArePartitioned.)
func TestNodeMigrateEdgeHasNoCutBreakerWhenEachHalfHasTwoGrantors(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("agent", "ops")},
	}
	bothHalves := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
		{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"update"}},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{ObjectMeta: objectMeta("node-ops-a", ""), Rules: bothHalves},
		{ObjectMeta: objectMeta("node-ops-b", ""), Rules: bothHalves},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("node-ops-a-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "node-ops-a"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}},
		},
		{
			ObjectMeta: objectMeta("node-ops-b-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "node-ops-b"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}},
		},
	}

	graph := BuildGraph(snapshot)

	var found bool
	for _, edge := range graph.Edges {
		if edge.Action != "node_drain_migrate" {
			continue
		}
		found = true
		if len(edge.CutBreakers) != 0 {
			t.Errorf("want no CutBreakers when each half has two grantors, got %+v", edge.CutBreakers)
		}
	}
	if !found {
		t.Fatal("no node_drain_migrate edge emitted; fixture is wrong")
	}
}

// TestNodeMigrateEdgeRecordsBothSoleGrantorsWhenHalvesArePartitioned covers the
// shape a correlation edge actually needs to guard: the two halves are partitioned
// across two DIFFERENT single-grantor bindings (delete pods solely via one, node
// manipulation solely via the other). Cutting EITHER binding un-grants its half,
// and the correlation (which needs both) no longer holds no matter what the other
// half still has, so BOTH bindings must appear in CutBreakers, not neither.
func TestNodeMigrateEdgeRecordsBothSoleGrantorsWhenHalvesArePartitioned(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("agent", "ops")},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta: objectMeta("pod-deleter", ""),
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
			},
		},
		{
			ObjectMeta: objectMeta("node-manipulator", ""),
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"update"}},
			},
		},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("pod-deleter-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-deleter"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}},
		},
		{
			ObjectMeta: objectMeta("node-manipulator-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "node-manipulator"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}},
		},
	}

	graph := BuildGraph(snapshot)

	var found bool
	for _, edge := range graph.Edges {
		if edge.Action != "node_drain_migrate" {
			continue
		}
		found = true
		got := map[string]bool{}
		for _, b := range edge.CutBreakers {
			got[b.Name] = true
		}
		if len(edge.CutBreakers) != 2 || !got["pod-deleter-crb"] || !got["node-manipulator-crb"] {
			t.Errorf("want CutBreakers = [pod-deleter-crb, node-manipulator-crb], got %+v", edge.CutBreakers)
		}
	}
	if !found {
		t.Fatal("no node_drain_migrate edge emitted; fixture is wrong")
	}
}

// TestSecretMintEdgeRecordsSoleGrantorAsCutBreaker mirrors
// TestNodeMigrateEdgeRecordsSoleGrantorAsCutBreaker for the secret_mint_token
// correlation (create secrets, get secrets, both cluster-scoped).
func TestSecretMintEdgeRecordsSoleGrantorAsCutBreaker(t *testing.T) {
	snapshot := models.Snapshot{}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("agent", "ops")},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta: objectMeta("secret-minter", ""),
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}},
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			},
		},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("secret-minter-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "secret-minter"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent", Namespace: "ops"}},
		},
	}

	graph := BuildGraph(snapshot)

	var found bool
	for _, edge := range graph.Edges {
		if edge.Action != "secret_mint_token" {
			continue
		}
		found = true
		if edge.SourceBinding != "" {
			t.Errorf("SourceBinding = %q, want empty: no single binding grants the correlation", edge.SourceBinding)
		}
		if len(edge.CutBreakers) != 1 {
			t.Fatalf("want 1 CutBreaker, got %d (%+v)", len(edge.CutBreakers), edge.CutBreakers)
		}
		if edge.CutBreakers[0].Name != "secret-minter-crb" || edge.CutBreakers[0].Namespace != "" {
			t.Errorf("CutBreakers[0] = %+v, want {Name: secret-minter-crb, Namespace: \"\"}", edge.CutBreakers[0])
		}
	}
	if !found {
		t.Fatal("no secret_mint_token edge emitted; fixture is wrong")
	}
}

// TestPodCreateTargetsClusterScopeOrderIsDeterministic guards podCreateTargets'
// cluster-scope branch (graph.go): it used to flatten subjectsByNs by ranging the
// map directly, and Go re-randomizes map iteration order on every range. That order
// becomes the order edges are appended to graph.Edges; buildAdjacency preserves
// insertion order into adj, and BFS walks adj[node] in it, so the flatten order
// silently decided which of several equal-length chains a finding reports, on a
// scan-by-scan basis, with no finding or rule ID changing.
//
// The fixture needs at least two namespaces, each holding at least two
// ServiceAccounts, plus a subject with a cluster-scoped `create pods` grant: with
// fewer keys than that, subjectsByNs has too few entries for map iteration to ever
// reorder them in practice, and the test would pass vacuously even against the
// unfixed code.
func TestPodCreateTargetsClusterScopeOrderIsDeterministic(t *testing.T) {
	build := func() *models.EscalationGraph {
		snapshot := models.Snapshot{}
		snapshot.Resources.Namespaces = []corev1.Namespace{
			{ObjectMeta: objectMeta("ns-a", "")},
			{ObjectMeta: objectMeta("ns-b", "")},
			{ObjectMeta: objectMeta("ns-c", "")},
			{ObjectMeta: objectMeta("attacker-ns", "")},
		}
		snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
			{ObjectMeta: objectMeta("sa-a1", "ns-a")},
			{ObjectMeta: objectMeta("sa-a2", "ns-a")},
			{ObjectMeta: objectMeta("sa-b1", "ns-b")},
			{ObjectMeta: objectMeta("sa-b2", "ns-b")},
			{ObjectMeta: objectMeta("sa-c1", "ns-c")},
			{ObjectMeta: objectMeta("sa-c2", "ns-c")},
			{ObjectMeta: objectMeta("attacker", "attacker-ns")},
		}
		snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
			{
				ObjectMeta: objectMeta("pod-creator-cluster", ""),
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"create"},
				}},
			},
		}
		snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: objectMeta("pod-creator-binding", ""),
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-creator-cluster"},
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "attacker", Namespace: "attacker-ns"},
				},
			},
		}
		return BuildGraph(snapshot)
	}

	// projection isolates the pod_create_token_theft edges leaving "attacker", as
	// "from|to|action" per edge in graph.Edges order, joined. This is the exact
	// projection that flapped before the fix: the same set of targets, in a
	// different order.
	attackerID := nodeID(models.SubjectRef{Kind: "ServiceAccount", Name: "attacker", Namespace: "attacker-ns"})
	projection := func(graph *models.EscalationGraph) []string {
		var out []string
		for _, edge := range graph.Edges {
			if edge.From != attackerID || edge.Action != "pod_create_token_theft" {
				continue
			}
			out = append(out, edge.From+"|"+edge.To+"|"+edge.Action)
		}
		return out
	}

	baseline := projection(build())
	// 6 explicit SAs across 3 namespaces, each namespace also gaining an implicit
	// "default" SA: enough distinct map keys that map iteration reorders them in
	// practice across repeated builds.
	if len(baseline) < 6 {
		t.Fatalf("fixture too small to exercise reordering: got %d targets, want >= 6 (%v)", len(baseline), baseline)
	}

	for i := 0; i < 20; i++ {
		got := projection(build())
		if len(got) != len(baseline) {
			t.Fatalf("run %d: target count changed, got %d want %d", i, len(got), len(baseline))
		}
		for j := range baseline {
			if got[j] != baseline[j] {
				t.Fatalf("run %d: edge order diverged at index %d\n got:  %v\n want: %v", i, j, got, baseline)
			}
		}
	}
}
