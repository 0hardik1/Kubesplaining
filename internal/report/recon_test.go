package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// urlMutatingWebhook builds a single MutatingWebhookConfiguration whose only
// webhook routes via an out-of-cluster URL — used to exercise the OutOfClusterWebhooks
// counter without depending on the fixture's service-typed webhook.
func urlMutatingWebhook(url string) admissionregistrationv1.MutatingWebhookConfiguration {
	return admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "url-hook"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name:         "ext.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{URL: &url},
		}},
	}
}

func TestApiReachability(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw       string
		wantHost  string
		wantLabel string
	}{
		{"", "", "unknown"},
		{"https://127.0.0.1:43123", "127.0.0.1", "loopback"},
		{"https://10.0.0.1:6443", "10.0.0.1", "private"},
		{"https://192.168.1.10:6443", "192.168.1.10", "private"},
		{"https://172.16.0.5:6443", "172.16.0.5", "private"},
		{"https://203.0.113.10:6443", "203.0.113.10", "public"},
		{"https://169.254.169.254", "169.254.169.254", "linklocal"},
		{"https://eks.example.com", "eks.example.com", "unknown"},
	}
	for _, tc := range cases {
		host, label := apiReachability(tc.raw)
		if host != tc.wantHost || label != tc.wantLabel {
			t.Errorf("apiReachability(%q) = (%q, %q), want (%q, %q)",
				tc.raw, host, label, tc.wantHost, tc.wantLabel)
		}
	}
}

func TestDistroFromVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cluster string
		kubelet string
		want    string
	}{
		{"v1.28.5", "v1.28.5-eks-1234abcd", "EKS v1.28.5"},
		{"v1.28.5", "v1.28.5", "v1.28.5"},
		{"v1.28.5-gke.100", "v1.28.5-gke.100", "GKE v1.28.5-gke.100"},
		{"v1.28.5", "v1.28.5+aks-patch1", "AKS v1.28.5"},
		{"", "v1.30.0", "v1.30.0"},
		{"", "", ""},
	}
	for _, tc := range cases {
		got := distroFromVersion(tc.cluster, tc.kubelet)
		if got != tc.want {
			t.Errorf("distroFromVersion(%q, %q) = %q, want %q",
				tc.cluster, tc.kubelet, got, tc.want)
		}
	}
}

func TestCloudFromNodes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		nodes []corev1.Node
		want  string
	}{
		{"empty", nil, ""},
		{
			name: "aws with region",
			nodes: []corev1.Node{{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"topology.kubernetes.io/region": "us-east-1"}},
				Spec:       corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0abcd"},
			}},
			want: "AWS / us-east-1",
		},
		{
			name: "gce no region",
			nodes: []corev1.Node{{
				Spec: corev1.NodeSpec{ProviderID: "gce://project/zone/instance"},
			}},
			want: "GCE",
		},
		{
			name: "no providerID, region only",
			nodes: []corev1.Node{{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"topology.kubernetes.io/region": "eu-west-2"}},
			}},
			want: "eu-west-2",
		},
	}
	for _, tc := range cases {
		got := cloudFromNodes(tc.nodes)
		if got != tc.want {
			t.Errorf("%s: cloudFromNodes() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestBuildReconEmptySnapshot(t *testing.T) {
	t.Parallel()
	r := buildRecon(models.NewSnapshot(), nil, nil)

	// Headline chips must always be present so the collapsed disclosure isn't blank.
	if got := len(r.HeadlineChips); got != 4 {
		t.Fatalf("HeadlineChips: want 4, got %d (%#v)", got, r.HeadlineChips)
	}
	if r.Shape.NodeCount != 0 || r.Shape.PodCount != 0 {
		t.Errorf("expected zero counts on empty snapshot, got %#v", r.Shape)
	}
	if r.Ownership.ClusterAdmins.Total != 0 {
		t.Errorf("expected zero cluster-admins, got %d", r.Ownership.ClusterAdmins.Total)
	}
	if r.Shape.APIReachability != "unknown" {
		t.Errorf("expected APIReachability=unknown when no URL, got %q", r.Shape.APIReachability)
	}
	if r.Shape.CloudLabel == "" {
		t.Errorf("CloudLabel should default to a non-empty placeholder, got empty")
	}
}

func TestBuildReconMinimalRiskyFixture(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "testdata", "snapshots", "minimal-risky.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var snap models.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	subjects := permissions.Aggregate(snap)
	r := buildRecon(snap, nil, subjects)

	// Cluster shape — fixture has 2 namespaces, 1 pod, 0 nodes.
	if r.Shape.NamespaceCount != 2 {
		t.Errorf("NamespaceCount: want 2, got %d", r.Shape.NamespaceCount)
	}
	if r.Shape.PodCount != 1 {
		t.Errorf("PodCount: want 1, got %d", r.Shape.PodCount)
	}
	if r.Shape.NodeCount != 0 {
		t.Errorf("NodeCount: want 0, got %d", r.Shape.NodeCount)
	}
	// fixture.local is a DNS name → unknown reachability (we never resolve).
	if r.Shape.APIReachability != "unknown" {
		t.Errorf("APIReachability: want unknown, got %q", r.Shape.APIReachability)
	}

	// Ownership — fixture has no cluster-admin binding.
	if r.Ownership.ClusterAdmins.Total != 0 {
		t.Errorf("ClusterAdmins.Total: want 0, got %d", r.Ownership.ClusterAdmins.Total)
	}
	// reader-role grants get,list on secrets via cluster-role-binding to ServiceAccount/default/reader.
	if r.Ownership.SecretReaders.Total != 1 {
		t.Errorf("SecretReaders.Total: want 1, got %d (sample=%v)",
			r.Ownership.SecretReaders.Total, r.Ownership.SecretReaders.Sample)
	}

	// Surface — fixture has 1 mutating webhook (service-typed → 0 out-of-cluster).
	if r.Surface.MutatingWebhooks != 1 {
		t.Errorf("MutatingWebhooks: want 1, got %d", r.Surface.MutatingWebhooks)
	}
	if r.Surface.OutOfClusterWebhooks != 0 {
		t.Errorf("OutOfClusterWebhooks: want 0, got %d", r.Surface.OutOfClusterWebhooks)
	}

	// Guardrails — 1 NetworkPolicy (in flat-network); default namespace has pods + no NetPol.
	if r.Guardrails.NetworkPolicies != 1 {
		t.Errorf("NetworkPolicies: want 1, got %d", r.Guardrails.NetworkPolicies)
	}
	if r.Guardrails.NamespacesProtected != 1 {
		t.Errorf("NamespacesProtected: want 1, got %d", r.Guardrails.NamespacesProtected)
	}
	if r.Guardrails.NamespacesUnprotected != 1 {
		t.Errorf("NamespacesUnprotected: want 1 (default has pod, no netpol), got %d",
			r.Guardrails.NamespacesUnprotected)
	}
}

func TestBuildReconClusterAdminFiltersSystemMasters(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	snap.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:masters"}, // bootstrap binding — must be filtered
				{Kind: "ServiceAccount", Name: "ops", Namespace: "kube-system"},
				{Kind: "User", Name: "alice@example.com"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "irrelevant"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "viewer"}},
		},
	}

	r := buildRecon(snap, nil, permissions.Aggregate(snap))

	if r.Ownership.ClusterAdmins.Total != 2 {
		t.Errorf("ClusterAdmins.Total: want 2 (system:masters filtered), got %d (sample=%v)",
			r.Ownership.ClusterAdmins.Total, r.Ownership.ClusterAdmins.Sample)
	}
	for _, s := range r.Ownership.ClusterAdmins.Sample {
		if s == "Group/system:masters" {
			t.Errorf("ClusterAdmins.Sample contains system:masters, expected filtered: %v",
				r.Ownership.ClusterAdmins.Sample)
		}
	}
	if r.Ownership.ClusterAdmins.Anchor == "" {
		t.Errorf("ClusterAdmins.Anchor: want non-empty deep-link, got empty")
	}
}

func TestBuildReconHeadlineChips(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	// One cluster-admin holder + zero NetworkPolicies should both flag danger.
	snap.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "ca"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
	}}

	r := buildRecon(snap, nil, permissions.Aggregate(snap))
	if len(r.HeadlineChips) != 4 {
		t.Fatalf("want 4 chips, got %d", len(r.HeadlineChips))
	}
	// Order is fixed by buildHeadlineChips: nodes, cluster-admins, LoadBalancers, NetworkPolicies.
	if r.HeadlineChips[1].Tone != "danger" {
		t.Errorf("cluster-admins chip tone: want danger when >0, got %q", r.HeadlineChips[1].Tone)
	}
	if r.HeadlineChips[3].Tone != "danger" {
		t.Errorf("NetworkPolicies chip tone: want danger when 0, got %q", r.HeadlineChips[3].Tone)
	}
	if r.HeadlineChips[0].Value != "0" {
		t.Errorf("nodes chip value: want 0, got %q", r.HeadlineChips[0].Value)
	}
}

func TestBuildReconPrivescAnchorsSurfaceFromFindings(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:       "f1",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "x", Namespace: "y"},
			Tags:     []string{"module:privesc"},
		},
		{
			ID:       "f2",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "z", Namespace: "y"},
			Tags:     []string{"module:privesc"},
		},
		{
			ID:       "f3",
			RuleID:   "KUBE-PRIVESC-PATH-NODE-ESCAPE",
			Severity: models.SeverityHigh,
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "n", Namespace: "y"},
			Tags:     []string{"module:privesc"},
		},
	}

	r := buildRecon(snap, findings, nil)
	if r.Ownership.PrivescToAdminCount != 2 {
		t.Errorf("PrivescToAdminCount: want 2, got %d", r.Ownership.PrivescToAdminCount)
	}
	if r.Ownership.PrivescToAdminAnchor != "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Errorf("PrivescToAdminAnchor: want finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN, got %q",
			r.Ownership.PrivescToAdminAnchor)
	}
	if r.Ownership.NodeEscapeCount != 1 {
		t.Errorf("NodeEscapeCount: want 1, got %d", r.Ownership.NodeEscapeCount)
	}
}

func TestBuildReconExposedSurfaceCounts(t *testing.T) {
	t.Parallel()
	snap := models.NewSnapshot()
	priv := true
	snap.Resources.Pods = []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "host-net", Namespace: "default"},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				Containers:  []corev1.Container{{Name: "app"}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rooty", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: &priv}},
				},
			},
		},
	}
	snap.Resources.MutatingWebhookConfigs = []admissionregistrationv1.MutatingWebhookConfiguration{
		urlMutatingWebhook("https://hooks.example.com/mutate"),
	}
	snap.Resources.Services = []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "default"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}},
		{ObjectMeta: metav1.ObjectMeta{Name: "internal", Namespace: "default"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort}},
		{ObjectMeta: metav1.ObjectMeta{Name: "weird", Namespace: "default"}, Spec: corev1.ServiceSpec{ExternalIPs: []string{"203.0.113.5"}}},
	}

	r := buildRecon(snap, nil, nil)
	if r.Surface.HostNetworkPods.Total != 1 {
		t.Errorf("HostNetworkPods.Total: want 1, got %d", r.Surface.HostNetworkPods.Total)
	}
	if r.Surface.PrivilegedPods.Total != 1 {
		t.Errorf("PrivilegedPods.Total: want 1, got %d", r.Surface.PrivilegedPods.Total)
	}
	if r.Surface.LoadBalancers.Total != 1 {
		t.Errorf("LoadBalancers.Total: want 1, got %d", r.Surface.LoadBalancers.Total)
	}
	if r.Surface.NodePorts != 1 {
		t.Errorf("NodePorts: want 1, got %d", r.Surface.NodePorts)
	}
	if r.Surface.ExternalIPs != 1 {
		t.Errorf("ExternalIPs: want 1, got %d", r.Surface.ExternalIPs)
	}
	if r.Surface.OutOfClusterWebhooks != 1 {
		t.Errorf("OutOfClusterWebhooks: want 1 (URL-typed), got %d", r.Surface.OutOfClusterWebhooks)
	}
}
