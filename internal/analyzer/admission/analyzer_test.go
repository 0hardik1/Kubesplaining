package admission

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
