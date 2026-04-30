package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWriteAndReadSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "snapshot.json")

	snap := models.NewSnapshot()
	snap.Metadata.ClusterName = "test-cluster"
	snap.Metadata.CollectionWarnings = []string{"limited list permissions"}
	snap.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	}
	snap.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			},
		},
	}
	snap.Resources.SecretsMetadata = []models.SecretMetadata{
		{Name: "tls", Namespace: "default", Type: corev1.SecretTypeTLS},
	}

	if err := WriteSnapshot(path, snap); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	// File exists and parent dirs were created.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("snapshot file not written: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("snapshot file is empty")
	}

	got, err := ReadSnapshot(path)
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	if got.Metadata.ClusterName != "test-cluster" {
		t.Errorf("cluster name not preserved: %q", got.Metadata.ClusterName)
	}
	if len(got.Resources.Namespaces) != 2 {
		t.Errorf("namespaces count = %d, want 2", len(got.Resources.Namespaces))
	}
	if len(got.Resources.Roles) != 1 || got.Resources.Roles[0].Rules[0].Resources[0] != "pods" {
		t.Errorf("roles not preserved: %#v", got.Resources.Roles)
	}
	if len(got.Resources.SecretsMetadata) != 1 || got.Resources.SecretsMetadata[0].Type != corev1.SecretTypeTLS {
		t.Errorf("secret metadata not preserved: %#v", got.Resources.SecretsMetadata)
	}
}

func TestReadSnapshotMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ReadSnapshot(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error for missing snapshot file")
	}
}

func TestReadSnapshotInvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("seed broken file: %v", err)
	}

	_, err := ReadSnapshot(path)
	if err == nil {
		t.Fatal("expected decode error for malformed JSON")
	}
}
