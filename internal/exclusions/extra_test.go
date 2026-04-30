package exclusions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardik/kubesplaining/internal/collector"
	"github.com/hardik/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPresetMinimal(t *testing.T) {
	t.Parallel()

	cfg, err := Preset("minimal")
	if err != nil {
		t.Fatalf("Preset(minimal): %v", err)
	}
	if len(cfg.Global.ExcludeNamespaces) == 0 {
		t.Error("minimal preset should still exclude some namespaces")
	}
	// Minimal must not include kube-system (the standard preset's broader sweep).
	for _, ns := range cfg.Global.ExcludeNamespaces {
		if ns == "kube-system" {
			t.Errorf("minimal preset should not exclude kube-system, got %v", cfg.Global.ExcludeNamespaces)
		}
	}
}

func TestPresetUnsupportedReturnsError(t *testing.T) {
	t.Parallel()

	_, err := Preset("aggressive")
	if err == nil {
		t.Fatal("expected error for unsupported preset")
	}
	if !strings.Contains(err.Error(), "aggressive") {
		t.Errorf("error should name the bad preset, got %q", err.Error())
	}
}

func TestLoadAndWriteRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "exclusions.yaml")

	original := Config{
		Global: GlobalConfig{
			ExcludeNamespaces: []string{"team-a", "team-b"},
			ExcludeFindingIDs: []string{"KUBE-NETPOL-*"},
			ExcludeSubjects: []SubjectExclusion{
				{Kind: "ServiceAccount", Namespace: "platform", Name: "controller", Reason: "owned by platform"},
			},
		},
		PodSecurity: PodSecurityConfig{
			ExcludeChecks: []CheckExclusion{
				{Check: "hostNetwork", Namespace: "monitoring"},
			},
		},
	}

	if err := Write(path, original); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(got.Global.ExcludeNamespaces) != 2 || got.Global.ExcludeNamespaces[0] != "team-a" {
		t.Errorf("ExcludeNamespaces not round-tripped: %#v", got.Global.ExcludeNamespaces)
	}
	if len(got.Global.ExcludeSubjects) != 1 || got.Global.ExcludeSubjects[0].Reason != "owned by platform" {
		t.Errorf("ExcludeSubjects not round-tripped: %#v", got.Global.ExcludeSubjects)
	}
	if len(got.PodSecurity.ExcludeChecks) != 1 || got.PodSecurity.ExcludeChecks[0].Check != "hostNetwork" {
		t.Errorf("ExcludeChecks not round-tripped: %#v", got.PodSecurity.ExcludeChecks)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("global: [not-a-map"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error for malformed YAML")
	}
}

func TestEnrichFromSnapshotAddsSystemNamespaces(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	snap := models.NewSnapshot()
	snap.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},    // already excluded; should dedupe
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-flannel"}},   // kube- prefix → auto-add
		{ObjectMeta: metav1.ObjectMeta{Name: "tigera-system"}},  // -system suffix → auto-add
		{ObjectMeta: metav1.ObjectMeta{Name: "user-namespace"}}, // neither → leave alone
	}
	if err := collector.WriteSnapshot(path, snap); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	cfg, err := Preset("standard")
	if err != nil {
		t.Fatalf("Preset(standard): %v", err)
	}
	enriched, err := EnrichFromSnapshot(cfg, path)
	if err != nil {
		t.Fatalf("EnrichFromSnapshot: %v", err)
	}

	mustContain(t, enriched.Global.ExcludeNamespaces, "kube-flannel")
	mustContain(t, enriched.Global.ExcludeNamespaces, "tigera-system")
	mustNotContain(t, enriched.Global.ExcludeNamespaces, "user-namespace")
	mustNotContain(t, enriched.Global.ExcludeNamespaces, "default")

	// kube-system was already there and should not be duplicated.
	count := 0
	for _, ns := range enriched.Global.ExcludeNamespaces {
		if ns == "kube-system" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("kube-system should appear exactly once, got %d (%v)", count, enriched.Global.ExcludeNamespaces)
	}
}

func TestEnrichFromSnapshotEmptyPathIsNoop(t *testing.T) {
	t.Parallel()

	cfg, _ := Preset("standard")
	got, err := EnrichFromSnapshot(cfg, "")
	if err != nil {
		t.Fatalf("EnrichFromSnapshot(\"\"): %v", err)
	}
	if len(got.Global.ExcludeNamespaces) != len(cfg.Global.ExcludeNamespaces) {
		t.Errorf("empty path should leave config unchanged")
	}
}

func TestEnrichFromSnapshotMissingFileError(t *testing.T) {
	t.Parallel()

	cfg, _ := Preset("standard")
	_, err := EnrichFromSnapshot(cfg, filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected error for missing snapshot")
	}
}

func TestMatchRBACSubjectScopedToModule(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RBAC: RBACConfig{
			ExcludeSubjects: []SubjectExclusion{
				{Kind: "ServiceAccount", Namespace: "kube-*", Name: "*", Reason: "system SAs"},
			},
		},
	}

	// Match: tagged module:rbac and matches the subject pattern.
	matched := models.Finding{
		ID: "f", RuleID: "KUBE-RBAC-OVERBROAD-001",
		Subject: &models.SubjectRef{Kind: "ServiceAccount", Namespace: "kube-system", Name: "controller"},
		Tags:    []string{"module:rbac"},
	}
	got := Match(cfg, matched)
	if !got.Matched {
		t.Errorf("expected match for module:rbac subject, got reason=%q", got.Reason)
	}
	if got.Reason != "system SAs" {
		t.Errorf("reason = %q, want 'system SAs'", got.Reason)
	}

	// Skipped: not tagged module:rbac → matchesRBAC must short-circuit.
	other := matched
	other.Tags = []string{"module:secrets"}
	if Match(cfg, other).Matched {
		t.Error("non-rbac module finding should not be matched by RBACConfig")
	}

	// Mismatched namespace → no match.
	wrongNs := matched
	wrongNs.Subject = &models.SubjectRef{Kind: "ServiceAccount", Namespace: "team-a", Name: "controller"}
	if Match(cfg, wrongNs).Matched {
		t.Error("wrong namespace should not match RBAC pattern")
	}
}

func TestMatchRBACDefaultReason(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RBAC: RBACConfig{
			ExcludeSubjects: []SubjectExclusion{
				{Kind: "User", Name: "alice"}, // no Reason — falls back to default.
			},
		},
	}
	finding := models.Finding{
		ID: "f", RuleID: "KUBE-RBAC-OVERBROAD-001",
		Subject: &models.SubjectRef{Kind: "User", Name: "alice"},
		Tags:    []string{"module:rbac"},
	}

	got := Match(cfg, finding)
	if got.Reason != "matched rbac.exclude_subjects" {
		t.Errorf("expected default reason, got %q", got.Reason)
	}
}

func TestMatchPodSecurityWorkloadByPattern(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PodSecurity: PodSecurityConfig{
			ExcludeWorkloads: []WorkloadExclusion{
				{Kind: "Deployment", Namespace: "monitoring", NamePattern: "prometheus-*", Reason: "monitoring exception"},
			},
		},
	}

	finding := models.Finding{
		ID: "f", RuleID: "KUBE-ESCAPE-003",
		Resource: &models.ResourceRef{Kind: "Deployment", Namespace: "monitoring", Name: "prometheus-server"},
		Tags:     []string{"module:pod_security"},
	}

	got := Match(cfg, finding)
	if !got.Matched {
		t.Fatalf("expected workload pattern match, reason=%q", got.Reason)
	}
	if got.Reason != "monitoring exception" {
		t.Errorf("reason = %q", got.Reason)
	}
}

func TestMatchPodSecurityWorkloadKindMismatch(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PodSecurity: PodSecurityConfig{
			ExcludeWorkloads: []WorkloadExclusion{
				{Kind: "Deployment", Name: "prometheus"},
			},
		},
	}
	finding := models.Finding{
		ID: "f", RuleID: "KUBE-ESCAPE-003",
		Resource: &models.ResourceRef{Kind: "DaemonSet", Name: "prometheus"},
		Tags:     []string{"module:pod_security"},
	}

	if Match(cfg, finding).Matched {
		t.Error("DaemonSet should not be matched by Deployment-scoped exclusion")
	}
}

func TestMatchPodSecurityCheckByRuleID(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PodSecurity: PodSecurityConfig{
			ExcludeChecks: []CheckExclusion{
				{Check: "KUBE-ESCAPE-003", Namespace: "monitoring", Reason: "host net OK in monitoring"},
			},
		},
	}
	finding := models.Finding{
		ID: "f", RuleID: "KUBE-ESCAPE-003", Namespace: "monitoring",
		Tags: []string{"module:pod_security"},
	}

	got := Match(cfg, finding)
	if !got.Matched || got.Reason != "host net OK in monitoring" {
		t.Errorf("expected RuleID-based check match, got matched=%v reason=%q", got.Matched, got.Reason)
	}
}

func TestMatchNetworkPolicyByNamespace(t *testing.T) {
	t.Parallel()

	cfg := Config{
		NetworkPolicy: NetworkPolicyConfig{
			ExcludeNamespaces: []string{"team-*"},
		},
	}

	matched := models.Finding{
		ID: "f", RuleID: "KUBE-NETPOL-COVERAGE-001",
		Namespace: "team-a",
		Tags:      []string{"module:network_policy"},
	}
	if !Match(cfg, matched).Matched {
		t.Error("expected network namespace match")
	}

	// Wrong module tag → must not be matched by NetworkPolicyConfig.
	notNetwork := matched
	notNetwork.Tags = []string{"module:rbac"}
	if Match(cfg, notNetwork).Matched {
		t.Error("non-network module should not be matched by NetworkPolicyConfig")
	}
}

func TestMatchPodSecurityCheckEmptyCheckSkipped(t *testing.T) {
	t.Parallel()

	// An empty Check field is treated as "no check" and must not produce false positives.
	cfg := Config{
		PodSecurity: PodSecurityConfig{
			ExcludeChecks: []CheckExclusion{{Namespace: "default"}},
		},
	}
	finding := models.Finding{
		ID: "f", RuleID: "KUBE-ESCAPE-003", Namespace: "default",
		Tags: []string{"module:pod_security"},
	}
	if Match(cfg, finding).Matched {
		t.Error("empty Check should not match anything")
	}
}

func TestMatchesPatternEmptyOperands(t *testing.T) {
	t.Parallel()

	// Both operands matter; the matcher must reject empty strings on either side.
	if matchesPattern("", "anything") {
		t.Error("empty pattern should never match")
	}
	if matchesPattern("anything", "") {
		t.Error("empty candidate should never match")
	}
	if !matchesPattern("foo", "foo") {
		t.Error("exact equality should match")
	}
	if !matchesPattern("foo-*", "foo-bar") {
		t.Error("glob should match")
	}
}

func mustContain(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, x := range haystack {
		if x == needle {
			return
		}
	}
	t.Errorf("expected %q in %v", needle, haystack)
}

func mustNotContain(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, x := range haystack {
		if x == needle {
			t.Errorf("did not expect %q in %v", needle, haystack)
			return
		}
	}
}
