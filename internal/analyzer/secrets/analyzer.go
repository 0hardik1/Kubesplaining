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

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/scoring"
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
			findings = appendUnique(findings, seen, secretFinding(secret, "KUBE-SECRETS-001", models.SeverityHigh, 7.8,
				"Long-lived service account token secret present",
				"This secret uses the legacy `kubernetes.io/service-account-token` pattern, which creates long-lived credentials that are harder to rotate safely.",
				map[string]any{"type": secret.Type},
				"Prefer projected service account tokens and remove legacy token secrets where possible.",
				"serviceAccountToken"))
		}

		if secret.Namespace == "kube-system" && secret.Type == corev1.SecretTypeOpaque {
			findings = appendUnique(findings, seen, secretFinding(secret, "KUBE-SECRETS-002", models.SeverityMedium, 5.9,
				"Opaque secret stored in kube-system",
				"An opaque secret is stored in `kube-system`, which often indicates infrastructure credentials or cluster-level integrations.",
				map[string]any{"type": secret.Type},
				"Review whether this secret is still required and restrict who can read it.",
				"opaqueKubeSystem"))
		}
	}

	for _, configMap := range snapshot.Resources.ConfigMaps {
		if keys := matchedCredentialKeys(configMap.Data); len(keys) > 0 {
			findings = appendUnique(findings, seen, configMapFinding(configMap, "KUBE-CONFIGMAP-001", models.SeverityMedium, 6.3,
				"ConfigMap contains credential-like keys",
				"This ConfigMap contains keys that look like credentials or connection secrets, which may indicate sensitive data is stored outside Kubernetes Secrets.",
				map[string]any{"matched_keys": keys},
				"Move sensitive values into Secrets or an external secret manager and keep ConfigMaps for non-sensitive configuration only.",
				"credentialLikeKeys"))
		}

		if configMap.Namespace == "kube-system" && configMap.Name == "coredns" {
			if corefile, ok := configMap.Data["Corefile"]; ok && suspiciousCoreDNS(corefile) {
				findings = appendUnique(findings, seen, configMapFinding(configMap, "KUBE-CONFIGMAP-002", models.SeverityHigh, 7.5,
					"CoreDNS configuration contains risky directives",
					"The CoreDNS ConfigMap contains directives that can alter or redirect DNS behavior in ways that deserve review.",
					map[string]any{"name": configMap.Name},
					"Review CoreDNS rewrites and external forwarders to ensure they are intentional and trusted.",
					"corednsRiskyDirectives"))
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

// secretFinding materializes a Secret-scoped finding.
func secretFinding(secret models.SecretMetadata, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, secret.Namespace, secret.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryDataExfiltration,
		Title:       title,
		Description: description,
		Namespace:   secret.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "Secret",
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/secret/",
		},
		Tags: []string{"module:secrets", "check:" + check},
	}
}

// configMapFinding materializes a ConfigMap-scoped finding.
func configMapFinding(configMap models.ConfigMapSnapshot, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, configMap.Namespace, configMap.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryDataExfiltration,
		Title:       title,
		Description: description,
		Namespace:   configMap.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      configMap.Name,
			Namespace: configMap.Namespace,
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/configmap/",
		},
		Tags: []string{"module:secrets", "check:" + check},
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
