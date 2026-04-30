// Package secrets analyzes Secret metadata and ConfigMap contents for
// hygiene issues such as legacy service-account tokens, sensitive kube-system
// data, credential-like keys leaked into ConfigMaps, and risky CoreDNS rules.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	corev1 "k8s.io/api/core/v1"
)

// Analyzer produces secret-and-configmap-focused findings from a snapshot.
type Analyzer struct{}

// credentialLikeKeys lists substrings that, when seen in a ConfigMap key, suggest a credential is stored outside a Secret.
var credentialLikeKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"key",
	"api_key",
	"apikey",
	"client_secret",
	"access_key",
	"credentials",
	"connection_string",
	"dsn",
}

// New returns a new secrets analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "secrets"
}

// Analyze flags legacy service-account tokens, opaque kube-system secrets,
// credential-like ConfigMap keys, and risky CoreDNS configurations.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, secret := range snapshot.Resources.SecretsMetadata {
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			findings = appendUnique(findings, seen, secretFinding(secret,
				"KUBE-SECRETS-001", models.SeverityHigh, 7.8,
				map[string]any{"type": secret.Type},
				"serviceAccountToken",
				contentSecrets001(secret.Namespace, secret.Name)))
		}

		if secret.Namespace == "kube-system" && secret.Type == corev1.SecretTypeOpaque {
			findings = appendUnique(findings, seen, secretFinding(secret,
				"KUBE-SECRETS-002", models.SeverityMedium, 5.9,
				map[string]any{"type": secret.Type},
				"opaqueKubeSystem",
				contentSecrets002(secret.Name)))
		}
	}

	for _, configMap := range snapshot.Resources.ConfigMaps {
		if keys := matchedCredentialKeys(configMap.Data); len(keys) > 0 {
			findings = appendUnique(findings, seen, configMapFinding(configMap,
				"KUBE-CONFIGMAP-001", models.SeverityMedium, 6.3,
				map[string]any{"matched_keys": keys},
				"credentialLikeKeys",
				contentConfigMap001(configMap.Namespace, configMap.Name, keys)))
		}

		if configMap.Namespace == "kube-system" && configMap.Name == "coredns" {
			if corefile, ok := configMap.Data["Corefile"]; ok && suspiciousCoreDNS(corefile) {
				findings = appendUnique(findings, seen, configMapFinding(configMap,
					"KUBE-CONFIGMAP-002", models.SeverityHigh, 7.5,
					map[string]any{"name": configMap.Name},
					"corednsRiskyDirectives",
					contentConfigMap002()))
			}
		}
	}

	return findings, nil
}

// matchedCredentialKeys returns the sorted list of keys whose normalized name contains any credential-like fragment.
func matchedCredentialKeys(data map[string]string) []string {
	if len(data) == 0 {
		return nil
	}

	matches := make([]string, 0)
	for key := range data {
		normalized := strings.ToLower(strings.TrimSpace(key))
		for _, candidate := range credentialLikeKeys {
			if strings.Contains(normalized, candidate) {
				matches = append(matches, key)
				break
			}
		}
	}

	slices.Sort(matches)
	return matches
}

// suspiciousCoreDNS reports whether a CoreDNS Corefile contains rewrite or external-forward directives that warrant review.
func suspiciousCoreDNS(corefile string) bool {
	normalized := strings.ToLower(corefile)
	return strings.Contains(normalized, " rewrite ") ||
		strings.Contains(normalized, "\nrewrite ") ||
		strings.Contains(normalized, "forward . 8.8.8.8") ||
		strings.Contains(normalized, "forward . 1.1.1.1") ||
		strings.Contains(normalized, "forward . tls://")
}

// referencesFromContent flattens content.LearnMore into a []string of URLs for the legacy
// References field — JSON/SARIF/CSV consumers see the URLs; HTML uses the structured form.
func referencesFromContent(content ruleContent) []string {
	urls := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		urls = append(urls, ref.URL)
	}
	return urls
}

// secretFinding materializes a Secret-scoped finding from a ruleContent.
func secretFinding(secret models.SecretMetadata, ruleID string, severity models.Severity, score float64, evidence map[string]any, check string, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, secret.Namespace, secret.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryDataExfiltration,
		Title:       content.Title,
		Description: content.Description,
		Namespace:   secret.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "Secret",
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       referencesFromContent(content),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:secrets", "check:" + check},
	}
}

// configMapFinding materializes a ConfigMap-scoped finding from a ruleContent.
func configMapFinding(configMap models.ConfigMapSnapshot, ruleID string, severity models.Severity, score float64, evidence map[string]any, check string, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, configMap.Namespace, configMap.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryDataExfiltration,
		Title:       content.Title,
		Description: content.Description,
		Namespace:   configMap.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      configMap.Name,
			Namespace: configMap.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       referencesFromContent(content),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:secrets", "check:" + check},
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
