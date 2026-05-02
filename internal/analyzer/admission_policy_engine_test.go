package analyzer

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// snapshotWithEngines stuffs minimal placeholder objects into the snapshot's
// policy-engine fields so detectPolicyEngines() reports the requested engines.
// Each boolean adds one no-name placeholder to the relevant slice — enough to
// flip the len() > 0 check.
func snapshotWithEngines(kyverno, gatekeeper, vap bool) models.Snapshot {
	s := models.Snapshot{}
	if kyverno {
		s.Resources.KyvernoClusterPolicies = []unstructured.Unstructured{{}}
	}
	if gatekeeper {
		s.Resources.GatekeeperConstraintTemplates = []unstructured.Unstructured{{}}
	}
	if vap {
		s.Resources.ValidatingAdmissionPolicies = []admissionregistrationv1.ValidatingAdmissionPolicy{{}}
	}
	return s
}

func TestPolicyEngineDetectionPopulatesSummary(t *testing.T) {
	t.Parallel()
	mod := &stubModule{name: "podsec"}
	snapshot := snapshotWithEngines(true, false, true)
	// Add a namespace so the engine has something to look at.
	snapshot.Resources.Namespaces = []corev1.Namespace{{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}},
	}}

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	want := []string{"kyverno", "vap"}
	if len(result.Admission.PolicyEnginesDetected) != len(want) {
		t.Fatalf("PolicyEnginesDetected = %v want %v", result.Admission.PolicyEnginesDetected, want)
	}
	for i := range want {
		if result.Admission.PolicyEnginesDetected[i] != want[i] {
			t.Errorf("PolicyEnginesDetected[%d] = %q want %q", i, result.Admission.PolicyEnginesDetected[i], want[i])
		}
	}
}

func TestPolicyEngineTagAppliedPerEngine(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:dev", "KUBE-ESCAPE-001", "dev", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := snapshotWithEngines(true, true, true)
	snapshot.Resources.Namespaces = []corev1.Namespace{{
		ObjectMeta: metav1.ObjectMeta{Name: "dev"},
	}}

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 surviving finding, got %d", len(result.Findings))
	}
	for _, want := range []string{
		"admission:policy-engine-detected:gatekeeper",
		"admission:policy-engine-detected:kyverno",
		"admission:policy-engine-detected:vap",
	} {
		if !hasTag(result.Findings[0].Tags, want) {
			t.Errorf("missing tag %q in %v", want, result.Findings[0].Tags)
		}
	}
	// One finding tagged, three engines — counter increments once per finding.
	if result.Admission.PolicyEngineTagged != 1 {
		t.Errorf("PolicyEngineTagged = %d want 1", result.Admission.PolicyEngineTagged)
	}
	// Score must be unchanged: tag is informational, not a mitigation.
	if result.Findings[0].Score != 9.9 {
		t.Errorf("Score changed by tagging: got %v want 9.9", result.Findings[0].Score)
	}
}

func TestPolicyEngineNoEnginesNoTag(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:dev", "KUBE-ESCAPE-001", "dev", "privileged", models.SeverityCritical, 9.9),
		},
	}
	// No engines, but at least one namespace with PSA enforce so the posture
	// finding doesn't fire and noise this test.
	snapshot := snapshotWithLabeledNamespaces(map[string]string{"dev": "restricted"})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, finding := range result.Findings {
		for _, tag := range finding.Tags {
			if len(tag) >= len("admission:policy-engine-detected:") &&
				tag[:len("admission:policy-engine-detected:")] == "admission:policy-engine-detected:" {
				t.Errorf("unexpected policy-engine-detected tag with no engines: %s", tag)
			}
		}
	}
	if result.Admission.PolicyEngineTagged != 0 {
		t.Errorf("PolicyEngineTagged = %d want 0", result.Admission.PolicyEngineTagged)
	}
}

func TestPolicyEngineSuppressedFindingNotTagged(t *testing.T) {
	t.Parallel()
	mod := &stubModule{
		name: "podsec",
		findings: []models.Finding{
			podsecFinding("priv:prod", "KUBE-ESCAPE-001", "prod", "privileged", models.SeverityCritical, 9.9),
			podsecFinding("priv:dev", "KUBE-ESCAPE-001", "dev", "privileged", models.SeverityCritical, 9.9),
		},
	}
	snapshot := snapshotWithEngines(true, false, false) // Kyverno detected
	// prod has restricted enforce so its priv finding is suppressed; dev has none.
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "dev"}},
	}

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeSuppress})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Only the dev finding should survive, and it should carry the kyverno tag.
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 surviving finding (dev), got %d", len(result.Findings))
	}
	if result.Findings[0].Namespace != "dev" {
		t.Errorf("expected dev finding to survive, got %q", result.Findings[0].Namespace)
	}
	if !hasTag(result.Findings[0].Tags, "admission:policy-engine-detected:kyverno") {
		t.Errorf("expected dev finding to carry kyverno tag, got %v", result.Findings[0].Tags)
	}
	// Counter is once per surviving tagged finding (the suppressed one is gone).
	if result.Admission.PolicyEngineTagged != 1 {
		t.Errorf("PolicyEngineTagged = %d want 1 (suppressed finding shouldn't count)", result.Admission.PolicyEngineTagged)
	}
}

func TestPolicyEngineModeOffStripsPostureFinding(t *testing.T) {
	t.Parallel()
	// Inject a fake posture finding via a stub module; the engine stage should drop
	// it when mode == off because users opted out of admission reasoning.
	mod := &stubModule{
		name: "admission",
		findings: []models.Finding{
			{
				ID:       "KUBE-ADMISSION-NO-POLICY-ENGINE-001",
				RuleID:   "KUBE-ADMISSION-NO-POLICY-ENGINE-001",
				Severity: models.SeverityMedium,
				Score:    4.0,
				Tags:     []string{"module:admission", "check:no_policy_engine"},
			},
			{
				ID:       "KUBE-ADMISSION-001:foo",
				RuleID:   "KUBE-ADMISSION-001",
				Severity: models.SeverityHigh,
				Score:    7.9,
				Tags:     []string{"module:admission"},
			},
		},
	}
	snapshot := models.Snapshot{}

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeOff})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "KUBE-ADMISSION-NO-POLICY-ENGINE-001" {
			t.Errorf("posture finding should be stripped when mode=off, got %+v", f)
		}
	}
	// The unrelated KUBE-ADMISSION-001 finding must still be present.
	var sawAdm001 bool
	for _, f := range result.Findings {
		if f.RuleID == "KUBE-ADMISSION-001" {
			sawAdm001 = true
		}
	}
	if !sawAdm001 {
		t.Errorf("non-posture admission finding was lost: %+v", result.Findings)
	}
}

func TestPolicyEnginePostureFindingNotAttenuated(t *testing.T) {
	t.Parallel()
	// Regression guard: the KUBE-ADMISSION-NO-POLICY-ENGINE-001 finding carries
	// module:admission (not module:pod_security), so the PSA mitigation stage's
	// isPodSecurityFinding check must return false and leave it untouched even
	// when mode == attenuate and a namespace has enforce labels.
	mod := &stubModule{
		name: "admission",
		findings: []models.Finding{
			{
				ID:        "KUBE-ADMISSION-NO-POLICY-ENGINE-001",
				RuleID:    "KUBE-ADMISSION-NO-POLICY-ENGINE-001",
				Severity:  models.SeverityMedium,
				Score:     4.0,
				Namespace: "", // cluster-wide
				Tags:      []string{"module:admission", "check:no_policy_engine"},
			},
		},
	}
	snapshot := snapshotWithLabeledNamespaces(map[string]string{"prod": "restricted"})

	result, err := engineWith(mod).Analyze(context.Background(), snapshot, Options{AdmissionMode: AdmissionModeAttenuate})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected posture finding to survive attenuation, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityMedium || result.Findings[0].Score != 4.0 {
		t.Errorf("posture finding was attenuated: severity=%v score=%v", result.Findings[0].Severity, result.Findings[0].Score)
	}
	if hasTag(result.Findings[0].Tags, "admission:mitigated-psa-restricted") {
		t.Errorf("posture finding should not carry mitigated-psa tag, got %v", result.Findings[0].Tags)
	}
}
