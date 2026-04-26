package manifest

import "testing"

func TestLoadSnapshotFromManifestFile(t *testing.T) {
	t.Parallel()

	snapshot, err := LoadSnapshot("../../testdata/manifests/risky-resource.yaml", "")
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}

	if len(snapshot.Resources.Deployments) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(snapshot.Resources.Deployments))
	}
	if len(snapshot.Resources.ClusterRoles) != 1 {
		t.Fatalf("expected 1 clusterrole, got %d", len(snapshot.Resources.ClusterRoles))
	}
	if len(snapshot.Resources.ClusterRoleBindings) != 1 {
		t.Fatalf("expected 1 clusterrolebinding, got %d", len(snapshot.Resources.ClusterRoleBindings))
	}
	if len(snapshot.Resources.MutatingWebhookConfigs) != 1 {
		t.Fatalf("expected 1 mutating webhook config, got %d", len(snapshot.Resources.MutatingWebhookConfigs))
	}
}
