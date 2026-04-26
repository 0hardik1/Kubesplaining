package secrets

import (
	"context"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

func TestAnalyzerFindsSecretAndConfigMapRisks(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{
					Name:      "legacy-token",
					Namespace: "default",
					Type:      corev1.SecretTypeServiceAccountToken,
				},
				{
					Name:      "infra-creds",
					Namespace: "kube-system",
					Type:      corev1.SecretTypeOpaque,
				},
			},
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "app-config",
					Namespace: "default",
					Data: map[string]string{
						"db_password": "",
						"username":    "",
					},
				},
				{
					Name:      "coredns",
					Namespace: "kube-system",
					Data: map[string]string{
						"Corefile": ".:53 {\n    rewrite name exact example.com evil.internal\n}\n",
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-SECRETS-001")
	assertRulePresent(t, findings, "KUBE-SECRETS-002")
	assertRulePresent(t, findings, "KUBE-CONFIGMAP-001")
	assertRulePresent(t, findings, "KUBE-CONFIGMAP-002")
}

func TestMatchedCredentialKeys(t *testing.T) {
	t.Parallel()

	keys := matchedCredentialKeys(map[string]string{
		"db_password": "",
		"dsn":         "",
		"username":    "",
	})

	if len(keys) != 2 {
		t.Fatalf("expected 2 matched keys, got %v", keys)
	}
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
