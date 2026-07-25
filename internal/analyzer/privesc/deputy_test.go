package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// fluxSnapshot builds a snapshot where a tenant SA can create Flux Kustomizations.
// installController controls whether the reconciling controller SA actually exists,
// which is the precision gate for the whole edge family.
func fluxSnapshot(installController bool) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("tenant", "")},
		{ObjectMeta: objectMeta("flux-system", "")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: objectMeta("gitops", "tenant"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
			Resources: []string{"kustomizations"},
			Verbs:     []string{"create", "patch"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("gitops-rb", "tenant"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "gitops"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev-deployer", Namespace: "tenant"}},
	}}
	if installController {
		snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
			{ObjectMeta: objectMeta("kustomize-controller", "flux-system")},
		}
		snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
			ObjectMeta: objectMeta("flux-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "kustomize-controller", Namespace: "flux-system"},
			},
		}}
	}
	return snapshot
}

// TestConfusedDeputyBridgesToControllerSA proves a tenant holding no dangerous
// Kubernetes verb of its own still reaches cluster-admin by steering a reconciler.
func TestConfusedDeputyBridgesToControllerSA(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(fluxSnapshot(true))
	paths := FindPaths(graph, 5)

	var found bool
	for _, p := range paths {
		if p.Source.Name == "dev-deployer" && p.Target == models.TargetClusterAdmin &&
			len(p.Hops) >= 2 && p.Hops[0].Action == "operator_reconcile" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want dev-deployer -> kustomize-controller -> cluster_admin; paths: %+v", paths)
	}
}

// TestConfusedDeputyRequiresInstalledController is the precision gate: a stray RBAC
// grant on a CRD that no operator serves must produce nothing.
func TestConfusedDeputyRequiresInstalledController(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(fluxSnapshot(false))
	for _, edge := range graph.Edges {
		if edge.Action == "operator_reconcile" {
			t.Fatalf("emitted an operator_reconcile edge with no controller SA installed: %+v", edge)
		}
	}
}
