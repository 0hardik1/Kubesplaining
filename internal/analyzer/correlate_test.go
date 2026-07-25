package analyzer

import (
	"slices"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestCorrelateBumpsSubjectOnCriticalPath(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "bad-sa"}
	findings := []models.Finding{
		{
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    9.8,
			Subject:  &subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "pod_create_token_theft", Technique: "KUBE-PRIVESC-001", FromSubject: subject},
			},
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

// TestCorrelateOnlyBumpsEdgeFindings is the core of the causal-correlation fix: two
// findings share the path-source subject, but only the one whose rule is an actual
// edge of the chain (the pod-create grant) is amplified; the unrelated root-container
// weakness on the same ServiceAccount is left alone.
func TestCorrelateOnlyBumpsEdgeFindings(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "bad-sa"}
	findings := []models.Finding{
		{
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    9.8,
			Subject:  &subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "impersonate", Technique: "KUBE-PRIVESC-008", FromSubject: subject},
			},
		},
		{
			RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityCritical, Score: 7.0, Subject: &subject,
		},
		{
			RuleID: "KUBE-PODSEC-ROOT-001", Severity: models.SeverityMedium, Score: 5.0, Subject: &subject,
		},
	}

	got := correlate(findings)

	if got[1].Score != 9.0 || !slices.Contains(got[1].Tags, "chain:amplified") {
		t.Errorf("edge finding KUBE-PRIVESC-008 should be amplified 7.0 → 9.0, got %v tags=%v", got[1].Score, got[1].Tags)
	}
	if got[2].Score != 5.0 || slices.Contains(got[2].Tags, "chain:amplified") {
		t.Errorf("bystander finding KUBE-PODSEC-ROOT-001 must not be amplified: got %v tags=%v", got[2].Score, got[2].Tags)
	}
}

// TestCorrelateMatchesTechniqueFamily confirms a family-prefix edge technique
// amplifies the concrete finding whose rule ID it prefixes. Uses the cloud IRSA
// case (edge technique "KUBE-CLOUD-IRSA" → finding "KUBE-CLOUD-IRSA-ADMIN-ROLE-001"),
// a real shape: the eks IRSA finding carries the SA as its Subject.
func TestCorrelateMatchesTechniqueFamily(t *testing.T) {
	subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "pipeline"}
	findings := []models.Finding{
		{
			RuleID:   "KUBE-PRIVESC-PATH-AWS-IAM-ROLE",
			Severity: models.SeverityHigh,
			Score:    8.0,
			Subject:  &subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "irsa_assume_role", Technique: "KUBE-CLOUD-IRSA", FromSubject: subject},
			},
		},
		{RuleID: "KUBE-CLOUD-IRSA-ADMIN-ROLE-001", Severity: models.SeverityHigh, Score: 7.0, Subject: &subject},
	}

	got := correlate(findings)

	if !slices.Contains(got[1].Tags, "chain:amplified") {
		t.Errorf("KUBE-CLOUD-IRSA-ADMIN-ROLE-001 should match the KUBE-CLOUD-IRSA edge family: got tags=%v", got[1].Tags)
	}
}

// TestCorrelateSkipsResourceAnchoredFindings documents that a finding anchored to a
// Resource rather than a Subject (Subject == nil) is never amplified, even when its
// rule ID prefix-matches an escalation edge. Pod-escape findings (KUBE-ESCAPE-*,
// KUBE-PODSEC-*) are resource-anchored today, so the "KUBE-ESCAPE" edge family does
// not amplify them. This has always been the case (correlate has always skipped
// Subject == nil); the test guards against a silent change in that contract.
func TestCorrelateSkipsResourceAnchoredFindings(t *testing.T) {
	sa := models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "escaper"}
	findings := []models.Finding{
		{
			RuleID:   "KUBE-PRIVESC-PATH-NODE-ESCAPE",
			Severity: models.SeverityCritical,
			Score:    9.4,
			Subject:  &sa,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "pod_host_escape", Technique: "KUBE-ESCAPE", FromSubject: sa},
			},
		},
		// Resource-anchored escape finding: no Subject, like real podsec findings.
		{RuleID: "KUBE-ESCAPE-001", Severity: models.SeverityHigh, Score: 7.0, Resource: &models.ResourceRef{Kind: "Pod", Name: "p", Namespace: "app"}},
	}

	got := correlate(findings)

	if slices.Contains(got[1].Tags, "chain:amplified") {
		t.Errorf("resource-anchored finding (Subject == nil) must not be amplified: got tags=%v", got[1].Tags)
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
			RuleID:   "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS",
			Severity: models.SeverityHigh,
			Subject:  &subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Technique: "KUBE-PRIVESC-005", FromSubject: subject},
			},
		},
		{
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Subject:  &subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Technique: "KUBE-PRIVESC-005", FromSubject: subject},
				{Step: 2},
			},
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

// TestDedupeDropsSurviveTagWhenAlternateIsNotOnTheSurvivor proves the invariant that
// tags merge but fields do not: "privesc:survives-first-cut" asserts that
// AlternateEscalationPath is non-empty, so a survivor that did not itself carry that
// route must not keep the tag just because the finding merged away had it. The
// dropped finding here is the second one - its own fields, including
// AlternateEscalationPath, never reach the survivor, only its tags and (if higher)
// its score do.
func TestDedupeDropsSurviveTagWhenAlternateIsNotOnTheSurvivor(t *testing.T) {
	resource := &models.ResourceRef{Kind: "Namespace", Name: "prod"}
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "deployer"}
	findings := []models.Finding{
		{RuleID: "KUBE-CONFUSED-DEPUTY-001", Score: 7.0, Subject: subject, Resource: resource, Tags: []string{"module:privesc"}},
		{
			RuleID:                  "KUBE-CONFUSED-DEPUTY-001",
			Score:                   8.0,
			Subject:                 subject,
			Resource:                resource,
			Tags:                    []string{"module:privesc", "privesc:survives-first-cut"},
			AlternateEscalationPath: []models.EscalationHop{{Step: 1, Action: "bound_to_cluster_admin"}},
		},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want the two findings to collide into 1, got %d - the rest of this test is meaningless if they did not collide", len(got))
	}
	if len(got[0].AlternateEscalationPath) != 0 {
		t.Fatalf("survivor must not inherit the dropped finding's AlternateEscalationPath, got %d hops", len(got[0].AlternateEscalationPath))
	}
	if slices.Contains(got[0].Tags, "privesc:survives-first-cut") {
		t.Errorf("survivor has no AlternateEscalationPath, so it must not carry privesc:survives-first-cut; got tags %v", got[0].Tags)
	}
}

// TestDedupeKeepsSurviveTagWhenAlternateIsOnTheSurvivor is the positive companion:
// when the surviving finding itself carries AlternateEscalationPath, the tag must
// come through the ordinary tag-merge path. Without this test, unconditionally
// stripping the tag in dedupe would also satisfy the negative test above.
func TestDedupeKeepsSurviveTagWhenAlternateIsOnTheSurvivor(t *testing.T) {
	resource := &models.ResourceRef{Kind: "Namespace", Name: "prod"}
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "deployer"}
	findings := []models.Finding{
		{
			RuleID:                  "KUBE-CONFUSED-DEPUTY-001",
			Score:                   7.0,
			Subject:                 subject,
			Resource:                resource,
			Tags:                    []string{"module:privesc", "privesc:survives-first-cut"},
			AlternateEscalationPath: []models.EscalationHop{{Step: 1, Action: "bound_to_cluster_admin"}},
		},
		{RuleID: "KUBE-CONFUSED-DEPUTY-001", Score: 8.0, Subject: subject, Resource: resource, Tags: []string{"module:privesc"}},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want the two findings to collide into 1, got %d", len(got))
	}
	if !slices.Contains(got[0].Tags, "privesc:survives-first-cut") {
		t.Errorf("survivor carries AlternateEscalationPath, so the tag must be preserved; got tags %v", got[0].Tags)
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
