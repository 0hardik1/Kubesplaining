package admission

import (
	"context"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNameReturnsModuleIdentifier(t *testing.T) {
	t.Parallel()
	if New().Name() != "admission" {
		t.Errorf("Name() = %q, want admission", New().Name())
	}
}

func TestAnalyzerEmptySnapshotProducesNoFindings(t *testing.T) {
	t.Parallel()

	got, err := New().Analyze(context.Background(), models.Snapshot{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %v", got)
	}
}

func TestAnalyzerValidatingWebhookFlagsSameRisks(t *testing.T) {
	t.Parallel()

	ignore := admissionregistrationv1.Ignore
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "validator"},
					Webhooks: []admissionregistrationv1.ValidatingWebhook{
						{
							Name:          "v.example",
							FailurePolicy: &ignore,
							Rules: []admissionregistrationv1.RuleWithOperations{
								{
									Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
									Rule: admissionregistrationv1.Rule{
										APIGroups: []string{""}, APIVersions: []string{"v1"},
										Resources: []string{"pods"},
									},
								},
							},
							ObjectSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"audit": "yes"},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"kube-system"}},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	mustRule(t, got, "KUBE-ADMISSION-001")
	mustRule(t, got, "KUBE-ADMISSION-002")
	mustRule(t, got, "KUBE-ADMISSION-003")
}

func TestAnalyzerSafeWebhookProducesNothing(t *testing.T) {
	t.Parallel()

	fail := admissionregistrationv1.Fail
	// Webhook with FailurePolicy=Fail, no object selector, and no sensitive-namespace exemption
	// should produce zero findings.
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "safe"},
					Webhooks: []admissionregistrationv1.MutatingWebhook{
						{
							Name:          "safe.example",
							FailurePolicy: &fail,
							Rules: []admissionregistrationv1.RuleWithOperations{
								{
									Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
									Rule: admissionregistrationv1.Rule{
										APIGroups: []string{""}, APIVersions: []string{"v1"},
										Resources: []string{"pods"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %#v", got)
	}
}

func TestInterceptsSecurityCriticalResources(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		rules []admissionregistrationv1.RuleWithOperations
		want  bool
	}{
		{
			name: "create pods",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{Resources: []string{"pods"}}},
			},
			want: true,
		},
		{
			name: "update deployments",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Update},
					Rule: admissionregistrationv1.Rule{Resources: []string{"deployments"}}},
			},
			want: true,
		},
		{
			name: "wildcard operation",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{Resources: []string{"pods"}}},
			},
			want: true,
		},
		{
			name: "wildcard resources",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{Resources: []string{"*"}}},
			},
			want: true,
		},
		{
			name: "delete only — not security-critical for fail-open",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Delete},
					Rule: admissionregistrationv1.Rule{Resources: []string{"pods"}}},
			},
			want: false,
		},
		{
			name: "non-security resource",
			rules: []admissionregistrationv1.RuleWithOperations{
				{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{Resources: []string{"configmaps"}}},
			},
			want: false,
		},
		{
			name:  "no rules",
			rules: nil,
			want:  false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := interceptsSecurityCriticalResources(tc.rules); got != tc.want {
				t.Errorf("interceptsSecurityCriticalResources(%v) = %v, want %v", tc.rules, got, tc.want)
			}
		})
	}
}

func TestSelectorHasBypassableObjectMatch(t *testing.T) {
	t.Parallel()

	if selectorHasBypassableObjectMatch(nil) {
		t.Error("nil selector should be safe")
	}
	if selectorHasBypassableObjectMatch(&metav1.LabelSelector{}) {
		t.Error("empty selector should be safe")
	}
	if !selectorHasBypassableObjectMatch(&metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "x"},
	}) {
		t.Error("matchLabels-based selector is bypassable")
	}
	if !selectorHasBypassableObjectMatch(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: metav1.LabelSelectorOpExists}},
	}) {
		t.Error("matchExpressions-based selector is bypassable")
	}
}

func TestSelectorExcludesSensitiveNamespaces(t *testing.T) {
	t.Parallel()

	t.Run("nil selector", func(t *testing.T) {
		if selectorExcludesSensitiveNamespaces(nil) {
			t.Error("nil selector should not exclude system namespaces")
		}
	})

	t.Run("NotIn kube-system", func(t *testing.T) {
		got := selectorExcludesSensitiveNamespaces(&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn,
				Values: []string{"kube-system"},
			}},
		})
		if !got {
			t.Error("NotIn kube-system should be flagged")
		}
	})

	t.Run("NotIn -system suffix", func(t *testing.T) {
		got := selectorExcludesSensitiveNamespaces(&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpNotIn,
				Values: []string{"tigera-system"},
			}},
		})
		if !got {
			t.Error("-system suffix should be flagged")
		}
	})

	t.Run("DoesNotExist", func(t *testing.T) {
		got := selectorExcludesSensitiveNamespaces(&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpDoesNotExist,
			}},
		})
		if !got {
			t.Error("DoesNotExist on metadata.name should be flagged")
		}
	})

	t.Run("unrelated key", func(t *testing.T) {
		got := selectorExcludesSensitiveNamespaces(&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "team", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"kube-system"},
			}},
		})
		if got {
			t.Error("non-metadata.name key should not be flagged")
		}
	})

	t.Run("In operator does not exclude", func(t *testing.T) {
		got := selectorExcludesSensitiveNamespaces(&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpIn,
				Values: []string{"kube-system"},
			}},
		})
		if got {
			t.Error("In operator INCLUDES kube-system, must not be flagged")
		}
	})
}

func TestAnalyzerDedupesRepeatedWebhookEntries(t *testing.T) {
	t.Parallel()

	ignore := admissionregistrationv1.Ignore
	hook := admissionregistrationv1.MutatingWebhook{
		Name: "dup.example", FailurePolicy: &ignore,
		Rules: []admissionregistrationv1.RuleWithOperations{
			{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{Resources: []string{"pods"}}},
		},
	}
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{
				{ObjectMeta: metav1.ObjectMeta{Name: "dup"}, Webhooks: []admissionregistrationv1.MutatingWebhook{hook, hook}},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	count := 0
	for _, f := range got {
		if f.RuleID == "KUBE-ADMISSION-001" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate webhooks should produce one finding, got %d", count)
	}
}

func mustRule(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s, findings=%v", ruleID, findings)
}
