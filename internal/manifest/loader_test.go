package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestLoadSnapshotMultiDocumentYAML(t *testing.T) {
	t.Parallel()

	doc := `apiVersion: v1
kind: Namespace
metadata:
  name: team-a
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deployer
  namespace: team-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: deployer
    namespace: team-a
---
# A blank document and pure-comment document should be tolerated.
---
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: team-a
spec:
  containers:
    - name: c
      image: nginx:latest
`
	path := writeTemp(t, "multi.yaml", doc)
	snap, err := LoadSnapshot(path, "")
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}

	if len(snap.Resources.Namespaces) != 1 {
		t.Errorf("namespaces = %d, want 1", len(snap.Resources.Namespaces))
	}
	if len(snap.Resources.ServiceAccounts) != 1 {
		t.Errorf("service_accounts = %d, want 1", len(snap.Resources.ServiceAccounts))
	}
	if len(snap.Resources.Roles) != 1 {
		t.Errorf("roles = %d, want 1", len(snap.Resources.Roles))
	}
	if len(snap.Resources.RoleBindings) != 1 {
		t.Errorf("role_bindings = %d, want 1", len(snap.Resources.RoleBindings))
	}
	if len(snap.Resources.Pods) != 1 {
		t.Errorf("pods = %d, want 1", len(snap.Resources.Pods))
	}
	if snap.Metadata.ClusterName != "manifest-scan" {
		t.Errorf("ClusterName = %q, want manifest-scan", snap.Metadata.ClusterName)
	}
}

func TestLoadSnapshotListWrapper(t *testing.T) {
	t.Parallel()

	doc := `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: cm-1
      namespace: default
    data:
      foo: bar
  - apiVersion: v1
    kind: Secret
    metadata:
      name: tls
      namespace: default
      labels:
        app: web
    type: kubernetes.io/tls
`
	path := writeTemp(t, "list.yaml", doc)
	snap, err := LoadSnapshot(path, "")
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}

	if len(snap.Resources.ConfigMaps) != 1 || snap.Resources.ConfigMaps[0].Data["foo"] != "bar" {
		t.Errorf("ConfigMap data not preserved: %#v", snap.Resources.ConfigMaps)
	}
	if len(snap.Resources.SecretsMetadata) != 1 {
		t.Fatalf("secrets metadata = %d, want 1", len(snap.Resources.SecretsMetadata))
	}
	sec := snap.Resources.SecretsMetadata[0]
	if sec.Labels["app"] != "web" {
		t.Errorf("secret labels not preserved: %#v", sec.Labels)
	}
	if string(sec.Type) != "kubernetes.io/tls" {
		t.Errorf("secret type not preserved: %q", sec.Type)
	}
}

func TestLoadSnapshotResourceTypeHint(t *testing.T) {
	t.Parallel()

	// A bare manifest with no `kind` field should be classified using the hint.
	doc := `apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: cluster-admin-clone
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`
	path := writeTemp(t, "bare.yaml", doc)
	snap, err := LoadSnapshot(path, "ClusterRole")
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if len(snap.Resources.ClusterRoles) != 1 {
		t.Errorf("hint should classify as ClusterRole, got %#v", snap.Resources.ClusterRoles)
	}
}

func TestLoadSnapshotUnsupportedKind(t *testing.T) {
	t.Parallel()

	doc := `apiVersion: example.com/v1
kind: Frobnicator
metadata:
  name: x
`
	path := writeTemp(t, "frob.yaml", doc)
	_, err := LoadSnapshot(path, "")
	if err == nil {
		t.Fatal("expected error for unsupported kind")
	}
}

func TestLoadSnapshotMissingKindWithoutHint(t *testing.T) {
	t.Parallel()

	doc := `apiVersion: v1
metadata:
  name: anonymous
`
	path := writeTemp(t, "headerless.yaml", doc)
	_, err := LoadSnapshot(path, "")
	if err == nil {
		t.Fatal("expected error when no kind and no hint")
	}
}

func TestLoadSnapshotFileNotFound(t *testing.T) {
	t.Parallel()

	_, err := LoadSnapshot(filepath.Join(t.TempDir(), "no.yaml"), "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadSnapshotInvalidYAML(t *testing.T) {
	t.Parallel()

	path := writeTemp(t, "bad.yaml", "kind: Pod\nmetadata: { not-balanced")
	_, err := LoadSnapshot(path, "")
	if err == nil {
		t.Fatal("expected decode error for malformed YAML")
	}
}

func TestKindFromHintCaseInsensitive(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"role":                           "Role",
		"ClusterRole":                    "ClusterRole",
		"ROLEBINDING":                    "RoleBinding",
		"clusterrolebinding":             "ClusterRoleBinding",
		"pod":                            "Pod",
		"service":                        "Service",
		"deployment":                     "Deployment",
		"daemonset":                      "DaemonSet",
		"statefulset":                    "StatefulSet",
		"job":                            "Job",
		"cronjob":                        "CronJob",
		"serviceaccount":                 "ServiceAccount",
		"networkpolicy":                  "NetworkPolicy",
		"namespace":                      "Namespace",
		"validatingwebhookconfiguration": "ValidatingWebhookConfiguration",
		"mutatingwebhookconfiguration":   "MutatingWebhookConfiguration",
		"":                               "",
		"frobnicator":                    "",
	}
	for in, want := range cases {
		if got := kindFromHint(in); got != want {
			t.Errorf("kindFromHint(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
