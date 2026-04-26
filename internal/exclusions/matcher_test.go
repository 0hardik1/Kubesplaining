package exclusions

import (
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
)

func TestApplyFiltersMatchingFindings(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Global: GlobalConfig{
			ExcludeNamespaces: []string{"kube-system"},
			ExcludeFindingIDs: []string{"KUBE-NETPOL-*"},
		},
	}

	findings := []models.Finding{
		{
			ID:        "one",
			RuleID:    "KUBE-NETPOL-COVERAGE-001",
			Namespace: "default",
		},
		{
			ID:        "two",
			RuleID:    "KUBE-PRIVESC-005",
			Namespace: "kube-system",
		},
		{
			ID:        "three",
			RuleID:    "KUBE-PRIVESC-001",
			Namespace: "default",
		},
	}

	filtered, excluded := Apply(cfg, findings)
	if excluded != 2 {
		t.Fatalf("expected 2 excluded findings, got %d", excluded)
	}
	if len(filtered) != 1 || filtered[0].ID != "three" {
		t.Fatalf("unexpected filtered findings: %#v", filtered)
	}
}

func TestMatchPodSecurityCheckByTag(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PodSecurity: PodSecurityConfig{
			ExcludeChecks: []CheckExclusion{
				{Check: "hostNetwork", Namespace: "kube-system"},
			},
		},
	}

	finding := models.Finding{
		ID:        "one",
		RuleID:    "KUBE-ESCAPE-003",
		Namespace: "kube-system",
		Tags:      []string{"module:pod_security", "check:hostNetwork"},
	}

	result := Match(cfg, finding)
	if !result.Matched {
		t.Fatalf("expected finding to match exclusion")
	}
}
