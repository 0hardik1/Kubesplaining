// Package admission analyzes Validating/MutatingWebhookConfigurations for
// common weaknesses like fail-open security webhooks, bypassable selectors,
// and exemptions that skip sensitive namespaces.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/scoring"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer produces admission-webhook findings from a snapshot.
type Analyzer struct{}

// webhookContext carries identity metadata for a mutating webhook so findings can point back at its configuration.
type webhookContext struct {
	ConfigKind string
	ConfigName string
	Webhook    admissionregistrationv1.MutatingWebhook
}

// validatingWebhookContext carries identity metadata for a validating webhook so findings can point back at its configuration.
type validatingWebhookContext struct {
	ConfigKind string
	ConfigName string
	Webhook    admissionregistrationv1.ValidatingWebhook
}

// New returns a new admission analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "admission"
}

// Analyze walks every validating and mutating webhook configuration and flags weaknesses around failurePolicy and selectors.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, cfg := range snapshot.Resources.MutatingWebhookConfigs {
		for _, webhook := range cfg.Webhooks {
			ctx := webhookContext{ConfigKind: "MutatingWebhookConfiguration", ConfigName: cfg.Name, Webhook: webhook}
			findings = analyzeMutating(ctx, findings, seen)
		}
	}
	for _, cfg := range snapshot.Resources.ValidatingWebhookConfigs {
		for _, webhook := range cfg.Webhooks {
			ctx := validatingWebhookContext{ConfigKind: "ValidatingWebhookConfiguration", ConfigName: cfg.Name, Webhook: webhook}
			findings = analyzeValidating(ctx, findings, seen)
		}
	}

	return findings, nil
}

// analyzeMutating checks one mutating webhook entry for fail-open, bypassable selector, and sensitive-namespace exemption issues.
func analyzeMutating(ctx webhookContext, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	webhook := ctx.Webhook
	if interceptsSecurityCriticalResources(webhook.Rules) && webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-001", models.SeverityHigh, 7.9,
			"Security-critical webhook uses failurePolicy Ignore",
			"This mutating webhook targets sensitive resources but will fail open if the webhook backend is unavailable.",
			map[string]any{"failurePolicy": webhook.FailurePolicy, "rules": webhook.Rules},
			"Use `failurePolicy: Fail` for security-critical webhooks so outages do not silently disable enforcement.",
			"failurePolicyIgnore"))
	}

	if selectorHasBypassableObjectMatch(webhook.ObjectSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-002", models.SeverityMedium, 6.1,
			"Webhook can be bypassed via object labels",
			"This webhook uses an object selector, which means workloads may avoid admission by omitting or changing matching labels.",
			map[string]any{"objectSelector": webhook.ObjectSelector},
			"Prefer rules that apply independent of workload-controlled labels for security-sensitive admission checks.",
			"objectSelector"))
	}

	if selectorExcludesSensitiveNamespaces(webhook.NamespaceSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-003", models.SeverityMedium, 6.4,
			"Webhook excludes sensitive namespaces",
			"This webhook's namespace selector excludes at least one sensitive namespace, which can leave privileged areas outside admission control.",
			map[string]any{"namespaceSelector": webhook.NamespaceSelector},
			"Review namespace exemptions and ensure privileged namespaces are intentionally and safely excluded.",
			"namespaceSelector"))
	}

	return findings
}

// analyzeValidating mirrors analyzeMutating for validating webhooks, applying the same weakness checks.
func analyzeValidating(ctx validatingWebhookContext, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	webhook := ctx.Webhook
	if interceptsSecurityCriticalResources(webhook.Rules) && webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-001", models.SeverityHigh, 7.9,
			"Security-critical webhook uses failurePolicy Ignore",
			"This validating webhook targets sensitive resources but will fail open if the webhook backend is unavailable.",
			map[string]any{"failurePolicy": webhook.FailurePolicy, "rules": webhook.Rules},
			"Use `failurePolicy: Fail` for security-critical webhooks so outages do not silently disable enforcement.",
			"failurePolicyIgnore"))
	}

	if selectorHasBypassableObjectMatch(webhook.ObjectSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-002", models.SeverityMedium, 6.1,
			"Webhook can be bypassed via object labels",
			"This webhook uses an object selector, which means workloads may avoid admission by omitting or changing matching labels.",
			map[string]any{"objectSelector": webhook.ObjectSelector},
			"Prefer rules that apply independent of workload-controlled labels for security-sensitive admission checks.",
			"objectSelector"))
	}

	if selectorExcludesSensitiveNamespaces(webhook.NamespaceSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name, "KUBE-ADMISSION-003", models.SeverityMedium, 6.4,
			"Webhook excludes sensitive namespaces",
			"This webhook's namespace selector excludes at least one sensitive namespace, which can leave privileged areas outside admission control.",
			map[string]any{"namespaceSelector": webhook.NamespaceSelector},
			"Review namespace exemptions and ensure privileged namespaces are intentionally and safely excluded.",
			"namespaceSelector"))
	}

	return findings
}

// interceptsSecurityCriticalResources reports whether any rule intercepts create/update on pod-like resources, which is the case that matters for fail-open risks.
func interceptsSecurityCriticalResources(rules []admissionregistrationv1.RuleWithOperations) bool {
	for _, rule := range rules {
		if !containsAnyOperation(rule.Operations, admissionregistrationv1.Create, admissionregistrationv1.Update) {
			continue
		}
		if containsAnyString(rule.Rule.Resources, "*", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "podtemplates") {
			return true
		}
	}
	return false
}

func containsAnyOperation(values []admissionregistrationv1.OperationType, wanted ...admissionregistrationv1.OperationType) bool {
	for _, value := range values {
		if value == admissionregistrationv1.OperationAll {
			return true
		}
		for _, candidate := range wanted {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func containsAnyString(values []string, wanted ...string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
		for _, candidate := range wanted {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

// selectorHasBypassableObjectMatch reports whether the selector depends on object labels that a workload author could omit to bypass admission.
func selectorHasBypassableObjectMatch(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	return len(selector.MatchLabels) > 0 || len(selector.MatchExpressions) > 0
}

// selectorExcludesSensitiveNamespaces reports whether the namespace selector explicitly exempts kube-system or other "-system" namespaces from admission.
func selectorExcludesSensitiveNamespaces(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	for _, expr := range selector.MatchExpressions {
		if expr.Key != "kubernetes.io/metadata.name" {
			continue
		}
		if expr.Operator == metav1.LabelSelectorOpNotIn || expr.Operator == metav1.LabelSelectorOpDoesNotExist {
			for _, value := range expr.Values {
				if value == "kube-system" || strings.HasSuffix(value, "-system") {
					return true
				}
			}
			if expr.Operator == metav1.LabelSelectorOpDoesNotExist {
				return true
			}
		}
	}
	return false
}

// webhookFinding materializes an admission-webhook finding tied to the given webhook configuration.
func webhookFinding(configKind, configName, webhookName, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, configName, webhookName),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryInfrastructureModification,
		Title:       title,
		Description: description,
		Resource: &models.ResourceRef{
			Kind:     configKind,
			Name:     configName,
			APIGroup: admissionregistrationv1.GroupName,
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/",
		},
		Tags: []string{"module:admission", "check:" + check},
	}
}

// appendUnique deduplicates by Finding.ID before appending.
func appendUnique(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}
