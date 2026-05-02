// Package admission analyzes Validating/MutatingWebhookConfigurations for
// common weaknesses like fail-open security webhooks, bypassable selectors,
// and exemptions that skip sensitive namespaces.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer/admission/mitigation"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
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

	// Cluster-wide posture check. The engine stage applyPolicyEnginePresenceTags
	// strips this finding when --admission-mode=off, so the analyzer can stay
	// admission-unaware: emit unconditionally when conditions are met.
	if shouldEmitNoPolicyEngineFinding(snapshot) {
		findings = append(findings, postureFinding(
			"KUBE-ADMISSION-NO-POLICY-ENGINE-001",
			models.SeverityMedium,
			scoring.MinScoreForSeverity(models.SeverityMedium),
			contentNoPolicyEngine(),
			"no_policy_engine",
		))
	}

	return findings, nil
}

// shouldEmitNoPolicyEngineFinding returns true when (a) the snapshot has at
// least one namespace (gates out manifest-mode single-resource scans), (b) no
// namespace carries a PSA enforce label at baseline or stricter, and (c) no
// policy-engine resources were observed. All three must hold — any defense in
// place suppresses the posture finding.
func shouldEmitNoPolicyEngineFinding(snapshot models.Snapshot) bool {
	if len(snapshot.Resources.Namespaces) == 0 {
		return false
	}
	for _, ns := range snapshot.Resources.Namespaces {
		if mitigation.PSAStateForLabels(ns.Labels).HasEnforce() {
			return false
		}
	}
	if len(snapshot.Resources.ValidatingAdmissionPolicies) > 0 ||
		len(snapshot.Resources.KyvernoClusterPolicies) > 0 ||
		len(snapshot.Resources.KyvernoPolicies) > 0 ||
		len(snapshot.Resources.GatekeeperConstraintTemplates) > 0 {
		return false
	}
	return true
}

// postureFinding materializes a cluster-wide finding with no Resource, Subject,
// or Namespace. The deterministic ID is just the rule ID — there is only ever
// one instance per cluster scan, so no per-instance disambiguation is needed.
// Carries the module:admission tag (so the PSA stage's isPodSecurityFinding
// check returns false and won't try to attenuate it) and a check tag for
// downstream filtering.
func postureFinding(ruleID string, severity models.Severity, score float64, content ruleContent, check string) models.Finding {
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:               ruleID,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            scoring.Clamp(score),
		Category:         models.CategoryInfrastructureModification,
		Title:            content.Title,
		Description:      content.Description,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:admission", "check:" + check},
	}
}

// analyzeMutating checks one mutating webhook entry for fail-open, bypassable selector, and sensitive-namespace exemption issues.
func analyzeMutating(ctx webhookContext, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	webhook := ctx.Webhook
	if interceptsSecurityCriticalResources(webhook.Rules) && webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-001", models.SeverityHigh, 7.9,
			map[string]any{"failurePolicy": webhook.FailurePolicy, "rules": webhook.Rules},
			"failurePolicyIgnore",
			contentAdmission001(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	if selectorHasBypassableObjectMatch(webhook.ObjectSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-002", models.SeverityMedium, 6.1,
			map[string]any{"objectSelector": webhook.ObjectSelector},
			"objectSelector",
			contentAdmission002(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	if selectorExcludesSensitiveNamespaces(webhook.NamespaceSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-003", models.SeverityMedium, 6.4,
			map[string]any{"namespaceSelector": webhook.NamespaceSelector},
			"namespaceSelector",
			contentAdmission003(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	return findings
}

// analyzeValidating mirrors analyzeMutating for validating webhooks, applying the same weakness checks.
func analyzeValidating(ctx validatingWebhookContext, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	webhook := ctx.Webhook
	if interceptsSecurityCriticalResources(webhook.Rules) && webhook.FailurePolicy != nil && *webhook.FailurePolicy == admissionregistrationv1.Ignore {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-001", models.SeverityHigh, 7.9,
			map[string]any{"failurePolicy": webhook.FailurePolicy, "rules": webhook.Rules},
			"failurePolicyIgnore",
			contentAdmission001(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	if selectorHasBypassableObjectMatch(webhook.ObjectSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-002", models.SeverityMedium, 6.1,
			map[string]any{"objectSelector": webhook.ObjectSelector},
			"objectSelector",
			contentAdmission002(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	if selectorExcludesSensitiveNamespaces(webhook.NamespaceSelector) {
		findings = appendUnique(findings, seen, webhookFinding(ctx.ConfigKind, ctx.ConfigName, webhook.Name,
			"KUBE-ADMISSION-003", models.SeverityMedium, 6.4,
			map[string]any{"namespaceSelector": webhook.NamespaceSelector},
			"namespaceSelector",
			contentAdmission003(ctx.ConfigKind, ctx.ConfigName, webhook.Name)))
	}

	return findings
}

// interceptsSecurityCriticalResources reports whether any rule intercepts create/update on pod-like resources, which is the case that matters for fail-open risks.
func interceptsSecurityCriticalResources(rules []admissionregistrationv1.RuleWithOperations) bool {
	for _, rule := range rules {
		if !containsAnyOperation(rule.Operations, admissionregistrationv1.Create, admissionregistrationv1.Update) {
			continue
		}
		if containsAnyString(rule.Resources, "*", "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "podtemplates") {
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

// webhookFinding materializes an admission-webhook finding from a ruleContent. The structured
// content (Scope, Impact, AttackScenario, RemediationSteps, LearnMore, MitreTechniques) carries
// the senior-staff-grade detail; the analyzer supplies severity, score, evidence, and the rule
// ID + dedup key.
func webhookFinding(configKind, configName, webhookName, ruleID string, severity models.Severity, score float64, evidence map[string]any, check string, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, configName, webhookName),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryInfrastructureModification,
		Title:       content.Title,
		Description: content.Description,
		Resource: &models.ResourceRef{
			Kind:     configKind,
			Name:     configName,
			APIGroup: admissionregistrationv1.GroupName,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:admission", "check:" + check},
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
