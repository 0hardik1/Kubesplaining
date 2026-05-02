package admission

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAnalyzerFindsWebhookBypassRisks(t *testing.T) {
	t.Parallel()

	ignore := admissionregistrationv1.Ignore
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "risky-webhook"},
					Webhooks: []admissionregistrationv1.MutatingWebhook{
						{
							Name:                    "mutate.vulnerable.local",
							AdmissionReviewVersions: []string{"v1"},
							SideEffects:             sideEffectsPtr(admissionregistrationv1.SideEffectClassNone),
							FailurePolicy:           &ignore,
							ObjectSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"admission": "enabled"},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "kubernetes.io/metadata.name",
										Operator: metav1.LabelSelectorOpNotIn,
										Values:   []string{"kube-system"},
									},
								},
							},
							Rules: []admissionregistrationv1.RuleWithOperations{
								{
									Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
									Rule: admissionregistrationv1.Rule{
										APIGroups:   []string{""},
										APIVersions: []string{"v1"},
										Resources:   []string{"pods"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-ADMISSION-001")
	assertRulePresent(t, findings, "KUBE-ADMISSION-002")
	assertRulePresent(t, findings, "KUBE-ADMISSION-003")
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}

func sideEffectsPtr(value admissionregistrationv1.SideEffectClass) *admissionregistrationv1.SideEffectClass {
	return &value
}

func TestShouldEmitNoPolicyEngineFinding(t *testing.T) {
	t.Parallel()

	withNamespaces := func(labelsByName map[string]map[string]string) models.Snapshot {
		s := models.Snapshot{}
		for name, labels := range labelsByName {
			s.Resources.Namespaces = append(s.Resources.Namespaces, corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			})
		}
		return s
	}

	cases := []struct {
		name     string
		snapshot func() models.Snapshot
		want     bool
	}{
		{
			name:     "manifest mode (no namespaces) — never emit",
			snapshot: func() models.Snapshot { return models.Snapshot{} },
			want:     false,
		},
		{
			name: "single namespace, no PSA, no engines — emit",
			snapshot: func() models.Snapshot {
				return withNamespaces(map[string]map[string]string{"default": nil})
			},
			want: true,
		},
		{
			name: "PSA enforce restricted on any namespace — suppress",
			snapshot: func() models.Snapshot {
				return withNamespaces(map[string]map[string]string{
					"default": nil,
					"prod":    {"pod-security.kubernetes.io/enforce": "restricted"},
				})
			},
			want: false,
		},
		{
			name: "PSA enforce baseline on any namespace — suppress",
			snapshot: func() models.Snapshot {
				return withNamespaces(map[string]map[string]string{
					"prod": {"pod-security.kubernetes.io/enforce": "baseline"},
				})
			},
			want: false,
		},
		{
			name: "PSA enforce privileged is not a defense — emit",
			snapshot: func() models.Snapshot {
				// HasEnforce() returns false for privileged level (it's the most permissive
				// PSS level — blocks nothing), so the posture finding should still fire.
				return withNamespaces(map[string]map[string]string{
					"default": {"pod-security.kubernetes.io/enforce": "privileged"},
				})
			},
			want: true,
		},
		{
			name: "PSA audit-only — not a defense, emit",
			snapshot: func() models.Snapshot {
				// audit and warn modes log violations but don't reject creates/updates.
				return withNamespaces(map[string]map[string]string{
					"default": {"pod-security.kubernetes.io/audit": "restricted"},
				})
			},
			want: true,
		},
		{
			name: "VAP present — suppress",
			snapshot: func() models.Snapshot {
				s := withNamespaces(map[string]map[string]string{"default": nil})
				s.Resources.ValidatingAdmissionPolicies = []admissionregistrationv1.ValidatingAdmissionPolicy{{}}
				return s
			},
			want: false,
		},
		{
			name: "Kyverno ClusterPolicy present — suppress",
			snapshot: func() models.Snapshot {
				s := withNamespaces(map[string]map[string]string{"default": nil})
				s.Resources.KyvernoClusterPolicies = []unstructured.Unstructured{{}}
				return s
			},
			want: false,
		},
		{
			name: "Kyverno namespaced Policy present — suppress",
			snapshot: func() models.Snapshot {
				s := withNamespaces(map[string]map[string]string{"default": nil})
				s.Resources.KyvernoPolicies = []unstructured.Unstructured{{}}
				return s
			},
			want: false,
		},
		{
			name: "Gatekeeper ConstraintTemplate present — suppress",
			snapshot: func() models.Snapshot {
				s := withNamespaces(map[string]map[string]string{"default": nil})
				s.Resources.GatekeeperConstraintTemplates = []unstructured.Unstructured{{}}
				return s
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldEmitNoPolicyEngineFinding(tc.snapshot()); got != tc.want {
				t.Errorf("shouldEmitNoPolicyEngineFinding = %v want %v", got, tc.want)
			}
		})
	}
}

func TestAnalyzerEmitsNoPolicyEngineFinding(t *testing.T) {
	t.Parallel()
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	assertRulePresent(t, findings, "KUBE-ADMISSION-NO-POLICY-ENGINE-001")

	// And confirm the finding has the expected shape: cluster-wide (no Resource),
	// MEDIUM, with the right tags.
	for _, f := range findings {
		if f.RuleID != "KUBE-ADMISSION-NO-POLICY-ENGINE-001" {
			continue
		}
		if f.Severity != models.SeverityMedium {
			t.Errorf("expected MEDIUM, got %v", f.Severity)
		}
		if f.Resource != nil {
			t.Errorf("posture finding should be cluster-wide (Resource=nil), got %+v", f.Resource)
		}
		var sawModule, sawCheck bool
		for _, tag := range f.Tags {
			if tag == "module:admission" {
				sawModule = true
			}
			if tag == "check:no_policy_engine" {
				sawCheck = true
			}
		}
		if !sawModule || !sawCheck {
			t.Errorf("expected module:admission and check:no_policy_engine tags, got %v", f.Tags)
		}
	}
}
