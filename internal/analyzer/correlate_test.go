package analyzer

import (
	"slices"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
)

func TestCorrelateBumpsSubjectOnCriticalPath(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "bad-sa"}
	findings := []models.Finding{
		{
			RuleID:         "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity:       models.SeverityCritical,
			Score:          9.8,
			Subject:        &subject,
			EscalationPath: []models.EscalationHop{{Step: 1, Action: "wildcard"}},
		},
		{
			RuleID:   "KUBE-PRIVESC-001",
			Severity: models.SeverityHigh,
			Score:    8.0,
			Subject:  &subject,
		},
	}

	got := correlate(findings)

	if got[1].Score != 10.0 {
		t.Errorf("score not bumped+clamped: want 10.0, got %v", got[1].Score)
	}
	if !slices.Contains(got[1].Tags, "chain:amplified") {
		t.Errorf("chain:amplified tag missing: %v", got[1].Tags)
	}
}

func TestCorrelateDoesNotBumpPrivescFindings(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "bad-sa"}
	findings := []models.Finding{
		{
			RuleID:         "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity:       models.SeverityCritical,
			Score:          9.8,
			Subject:        &subject,
			EscalationPath: []models.EscalationHop{{Step: 1}},
		},
	}

	got := correlate(findings)

	if got[0].Score != 9.8 {
		t.Errorf("privesc finding score changed: want 9.8, got %v", got[0].Score)
	}
}

func TestCorrelateIgnoresSubjectsWithoutPaths(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "boring-sa"}
	findings := []models.Finding{
		{
			RuleID:   "KUBE-PRIVESC-005",
			Severity: models.SeverityHigh,
			Score:    8.2,
			Subject:  &subject,
		},
	}

	got := correlate(findings)

	if got[0].Score != 8.2 {
		t.Errorf("unrelated finding should not be bumped: got %v", got[0].Score)
	}
	if slices.Contains(got[0].Tags, "chain:amplified") {
		t.Errorf("unrelated finding should not carry chain tag")
	}
}

func TestCorrelateUsesHighestSinkSeverity(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "leaker"}
	findings := []models.Finding{
		{
			RuleID:         "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS",
			Severity:       models.SeverityHigh,
			Subject:        &subject,
			EscalationPath: []models.EscalationHop{{Step: 1}},
		},
		{
			RuleID:         "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity:       models.SeverityCritical,
			Subject:        &subject,
			EscalationPath: []models.EscalationHop{{Step: 1}, {Step: 2}},
		},
		{
			RuleID:   "KUBE-PRIVESC-005",
			Severity: models.SeverityHigh,
			Score:    7.0,
			Subject:  &subject,
		},
	}

	got := correlate(findings)

	if got[2].Score != 9.0 {
		t.Errorf("want critical-path bump (+2.0) → 9.0, got %v", got[2].Score)
	}
}

func TestDedupeKeepsHighestScoreAndUnionsTags(t *testing.T) {
	resource := &models.ResourceRef{Kind: "RBACRule", Name: "dangerous"}
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "sa"}
	findings := []models.Finding{
		{RuleID: "KUBE-PRIVESC-005", Score: 7.0, Severity: models.SeverityHigh, Subject: subject, Resource: resource, Tags: []string{"module:rbac"}},
		{RuleID: "KUBE-PRIVESC-005", Score: 8.5, Severity: models.SeverityHigh, Subject: subject, Resource: resource, Tags: []string{"chain:amplified"}},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want 1 finding after dedupe, got %d", len(got))
	}
	if got[0].Score != 8.5 {
		t.Errorf("want highest score kept: 8.5, got %v", got[0].Score)
	}
	for _, want := range []string{"module:rbac", "chain:amplified"} {
		if !slices.Contains(got[0].Tags, want) {
			t.Errorf("tag %q missing from merged tags: %v", want, got[0].Tags)
		}
	}
}

func TestDedupePreservesDifferentKeys(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KUBE-PRIVESC-005", Score: 7.0, Subject: &models.SubjectRef{Kind: "SA", Name: "a"}},
		{RuleID: "KUBE-PRIVESC-005", Score: 7.0, Subject: &models.SubjectRef{Kind: "SA", Name: "b"}},
	}

	got := dedupe(findings)

	if len(got) != 2 {
		t.Fatalf("want 2 findings (different subjects), got %d", len(got))
	}
}

func TestDedupePassesThroughKeyless(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KUBE-NETPOL-COVERAGE-001", Score: 7.4},
		{RuleID: "KUBE-NETPOL-COVERAGE-001", Score: 7.4},
	}

	got := dedupe(findings)

	if len(got) != 2 {
		t.Fatalf("keyless findings should not be merged: got %d", len(got))
	}
}
