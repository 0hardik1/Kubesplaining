package analyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// snapshotWithLabeledNamespaces builds a Snapshot whose Resources.Namespaces slice carries the
// given enforce-mode label per name. Empty values mean "no label" so the test can mix labeled
// and unlabeled namespaces.
func snapshotWithLabeledNamespaces(enforceByName map[string]string) models.Snapshot {
	snapshot := models.Snapshot{}
	for name, level := range enforceByName {
		labels := map[string]string{}
		if level != "" {
			labels["pod-security.kubernetes.io/enforce"] = level
		}
		snapshot.Resources.Namespaces = append(snapshot.Resources.Namespaces, corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		})
	}
	return snapshot
}

// podsecFinding builds a fake pod-security finding with the canonical module + check tags so
// the admission stage can route it. Other tests use the same shape but vary the namespace and
// check value to exercise different lookup paths.
func podsecFinding(id, ruleID, namespace, check string, severity models.Severity, score float64) models.Finding {
	return models.Finding{
		ID:        id,
		RuleID:    ruleID,
		Severity:  severity,
		Score:     score,
		Namespace: namespace,
		Tags:      []string{"module:pod_security", "check:" + check},
	}
}

func TestAdmissionSuppressDropsBlockedFinding(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:prod", "KUBE-ESCAPE-001", "prod", "privileged", models.SeverityCritical, 9.9),
			podsecFinding("priv:dev", "KUBE-ESCAPE-001", "dev", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := snapshotWithLabeledNamespaces(map[string]string{
		"prod": "restricted",
		"dev":  "",
	})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (dev only), got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Namespace != "dev" {
		t.Errorf("expected dev finding to survive, got %q", result.Findings[0].Namespace)
	}
	if result.Admission.Suppressed != 1 {
		t.Errorf("expected Suppressed=1, got %d", result.Admission.Suppressed)
	}
	if result.Admission.SuppressedByNamespace["prod"]["KUBE-ESCAPE-001"] != 1 {
		t.Errorf("expected per-namespace suppression count for prod, got %v", result.Admission.SuppressedByNamespace)
	}
}

func TestAdmissionAttenuateDownweightsBlockedFinding(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:prod", "KUBE-ESCAPE-001", "prod", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := snapshotWithLabeledNamespaces(map[string]string{"prod": "restricted"})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeAttenuate})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding to survive attenuation, got %d", len(result.Findings))
	}
	got := result.Findings[0]
	// Severity drops exactly one bucket (Critical → High); score snaps to the floor of
	// the new bucket so downstream consumers see a Score/Severity pair that's internally
	// consistent and clearly not Critical anymore.
	if got.Severity != models.SeverityHigh {
		t.Errorf("expected severity High after one-bucket-down attenuation, got %v", got.Severity)
	}
	if got.Score != 7.0 {
		t.Errorf("expected score 7.0 (floor of High bucket), got %v", got.Score)
	}
	if !hasTag(got.Tags, "admission:mitigated-psa-restricted") {
		t.Errorf("expected admission:mitigated-psa-restricted tag, got %v", got.Tags)
	}
	if result.Admission.Attenuated != 1 {
		t.Errorf("expected Attenuated=1, got %d", result.Admission.Attenuated)
	}
}

func TestAdmissionOffPreservesFindings(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:prod", "KUBE-ESCAPE-001", "prod", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := snapshotWithLabeledNamespaces(map[string]string{"prod": "restricted"})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeOff})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Score != 9.9 {
		t.Errorf("admission off must not reweight: %+v", result.Findings)
	}
	if result.Admission.Suppressed != 0 || result.Admission.Attenuated != 0 {
		t.Errorf("admission off must not count any actions: %+v", result.Admission)
	}
}

func TestAdmissionAuditOnlyTagsButNeverSuppresses(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:logs", "KUBE-ESCAPE-001", "logs", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "logs",
			Labels: map[string]string{"pod-security.kubernetes.io/audit": "restricted"},
		},
	}}

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("audit-only must not suppress, got %d findings", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("audit-only must not attenuate severity, got %v", result.Findings[0].Severity)
	}
	if !hasTag(result.Findings[0].Tags, "admission:audit-psa-restricted") {
		t.Errorf("expected admission:audit-psa-restricted tag, got %v", result.Findings[0].Tags)
	}
	if result.Admission.AuditOnly != 1 {
		t.Errorf("expected AuditOnly=1, got %d", result.Admission.AuditOnly)
	}
}

func TestAdmissionDoesNotTouchNonPodSecurityFindings(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "rbac",
		findings: []models.Finding{
			{ID: "r", RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityHigh, Score: 7.0, Namespace: "prod", Tags: []string{"module:rbac"}},
		},
	}
	snapshot := snapshotWithLabeledNamespaces(map[string]string{"prod": "restricted"})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("rbac findings must not be suppressed by PSA labels, got %d", len(result.Findings))
	}
	if result.Admission.Suppressed != 0 {
		t.Errorf("expected no suppression for rbac module, got %d", result.Admission.Suppressed)
	}
}

func TestParseAdmissionMode(t *testing.T) {
	cases := []struct {
		in    string
		want  AdmissionMode
		valid bool
	}{
		{"", AdmissionModeSuppress, true},
		{"suppress", AdmissionModeSuppress, true},
		{"SUPPRESS", AdmissionModeSuppress, true},
		{"  attenuate  ", AdmissionModeAttenuate, true},
		{"off", AdmissionModeOff, true},
		{"evaluate-vap", "", false},
		{"strict", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ParseAdmissionMode(tc.in)
			if ok != tc.valid {
				t.Fatalf("ParseAdmissionMode(%q) ok=%v want %v", tc.in, ok, tc.valid)
			}
			if ok && got != tc.want {
				t.Errorf("ParseAdmissionMode(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want || strings.EqualFold(tag, want) {
			return true
		}
	}
	return false
}
