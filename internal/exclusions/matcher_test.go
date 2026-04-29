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

// TestStandardPresetMatchesBuiltInNoise covers the auto-applied default behavior: the standard preset
// should suppress findings about kube-controller-manager SAs, system: groups/users, kubeadm:* groups,
// and kubeadm:* ClusterRoles, while leaving real user-created subjects untouched.
func TestStandardPresetMatchesBuiltInNoise(t *testing.T) {
	t.Parallel()

	cfg, err := Preset("standard")
	if err != nil {
		t.Fatalf("Preset(standard) failed: %v", err)
	}

	cases := []struct {
		name    string
		finding models.Finding
		match   bool
	}{
		{
			name: "controller-manager SA in kube-system",
			finding: models.Finding{
				ID: "a", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Subject: &models.SubjectRef{Kind: "ServiceAccount", Namespace: "kube-system", Name: "clusterrole-aggregation-controller"},
			},
			match: true,
		},
		{
			name: "system:masters group bound to cluster-admin",
			finding: models.Finding{
				ID: "b", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Subject:  &models.SubjectRef{Kind: "Group", Name: "system:masters"},
				Resource: &models.ResourceRef{Kind: "RBACRule", Name: "cluster-admin"},
			},
			match: true,
		},
		{
			name: "kubeadm:cluster-admins group",
			finding: models.Finding{
				ID: "c", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Subject: &models.SubjectRef{Kind: "Group", Name: "kubeadm:cluster-admins"},
			},
			match: true,
		},
		{
			name: "system: user (kube-controller-manager identity)",
			finding: models.Finding{
				ID: "d", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Subject: &models.SubjectRef{Kind: "User", Name: "system:kube-controller-manager"},
			},
			match: true,
		},
		{
			name: "kubeadm:get-nodes ClusterRole binding",
			finding: models.Finding{
				ID: "e", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Resource: &models.ResourceRef{Kind: "RBACRule", Name: "kubeadm:get-nodes"},
			},
			match: true,
		},
		{
			name: "real user-created Group should not match",
			finding: models.Finding{
				ID: "f", RuleID: "KUBE-RBAC-OVERBROAD-001",
				Subject:  &models.SubjectRef{Kind: "Group", Name: "release-engineering"},
				Resource: &models.ResourceRef{Kind: "RBACRule", Name: "cluster-admin"},
			},
			match: false,
		},
		{
			name: "user SA in user namespace should not match",
			finding: models.Finding{
				ID: "g", RuleID: "KUBE-PRIVESC-005",
				Subject: &models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "deployer"},
			},
			match: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := Match(cfg, tc.finding)
			if result.Matched != tc.match {
				t.Fatalf("expected match=%v, got match=%v reason=%q", tc.match, result.Matched, result.Reason)
			}
		})
	}
}
