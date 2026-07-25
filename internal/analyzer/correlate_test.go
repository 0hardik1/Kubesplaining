package analyzer

import (
	"slices"
	"strings"
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

// TestDedupeStripsSurviveTagWithoutAlternate proves the output invariant that
// "privesc:survives-first-cut" asserts AlternateEscalationPath is non-empty: a
// finding that carries the tag without the field is a contradiction, so dedupe
// strips the tag rather than let it reach the report.
//
// This used to be phrased as a repair inside dedupe's collision branch, dropping the
// tag from a merge survivor that hadn't itself earned it. It is driven here directly,
// with a single finding and no collision at all, because dedupeKey now keys a
// chain-bearing finding on its own ID (see dedupeKey), and two privesc findings can
// never collide with each other again - the merge this test used to exercise cannot
// happen in production. The fixture carries a non-empty EscalationPath because that
// is the only shape privesc actually emits; a fixture with AlternateEscalationPath
// set but EscalationPath empty (the old fixture's shape) cannot occur there.
func TestDedupeStripsSurviveTagWithoutAlternate(t *testing.T) {
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "deployer"}
	findings := []models.Finding{
		{
			ID:             "KUBE-CONFUSED-DEPUTY-001:ServiceAccount/app/deployer:cluster_admin_equivalent",
			RuleID:         "KUBE-CONFUSED-DEPUTY-001",
			Score:          8.0,
			Subject:        subject,
			Tags:           []string{"module:privesc", "privesc:survives-first-cut"},
			EscalationPath: []models.EscalationHop{{Step: 1, Action: "operator_reconcile"}},
			// AlternateEscalationPath deliberately empty: the tag claims a route that
			// this finding does not itself carry.
		},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want the single finding to pass through unmerged, got %d", len(got))
	}
	if slices.Contains(got[0].Tags, "privesc:survives-first-cut") {
		t.Errorf("finding has no AlternateEscalationPath, so it must not carry privesc:survives-first-cut; got tags %v", got[0].Tags)
	}
}

// TestDedupeKeepsSurviveTagWithAlternate is the positive companion: a finding whose
// AlternateEscalationPath is genuinely non-empty keeps the tag. Without this test,
// unconditionally stripping the tag in dedupe would also satisfy the negative test
// above.
func TestDedupeKeepsSurviveTagWithAlternate(t *testing.T) {
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "deployer"}
	findings := []models.Finding{
		{
			ID:                      "KUBE-CONFUSED-DEPUTY-001:ServiceAccount/app/deployer:cluster_admin_equivalent",
			RuleID:                  "KUBE-CONFUSED-DEPUTY-001",
			Score:                   8.0,
			Subject:                 subject,
			Tags:                    []string{"module:privesc", "privesc:survives-first-cut"},
			EscalationPath:          []models.EscalationHop{{Step: 1, Action: "operator_reconcile"}},
			AlternateEscalationPath: []models.EscalationHop{{Step: 1, Action: "bound_to_cluster_admin"}},
		},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want the single finding to pass through unmerged, got %d", len(got))
	}
	if !slices.Contains(got[0].Tags, "privesc:survives-first-cut") {
		t.Errorf("finding carries AlternateEscalationPath, so the tag must survive; got tags %v", got[0].Tags)
	}
}

// TestDedupeKeepsDistinctEscalationChainsToDifferentSinks pins the fix for the data
// loss described in Task 11: a confused-deputy subject reaching several sinks through
// the same controller produces several findings that share RuleID, Subject, and a nil
// Resource, which used to be the entire dedupe key. Modeled on the real shape shipped
// findings had: one ServiceAccount, two of its four sinks, same RuleID, different IDs
// because the target differs.
func TestDedupeKeepsDistinctEscalationChainsToDifferentSinks(t *testing.T) {
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "deepchain-tenant", Name: "deepchain-deployer"}
	findings := []models.Finding{
		{
			ID:      "KUBE-CONFUSED-DEPUTY-001:ServiceAccount/deepchain-tenant/deepchain-deployer:cluster_admin_equivalent",
			RuleID:  "KUBE-CONFUSED-DEPUTY-001",
			Score:   9.0,
			Subject: subject,
			Tags:    []string{"module:privesc", "target:cluster_admin_equivalent"},
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "operator_reconcile"},
				{Step: 2, Action: "bound_to_cluster_admin"},
			},
		},
		{
			ID:      "KUBE-CONFUSED-DEPUTY-001:ServiceAccount/deepchain-tenant/deepchain-deployer:node_escape",
			RuleID:  "KUBE-CONFUSED-DEPUTY-001",
			Score:   8.6,
			Subject: subject,
			Tags:    []string{"module:privesc", "target:node_escape"},
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "operator_reconcile"},
				{Step: 2, Action: "pod_host_escape"},
			},
		},
	}

	got := dedupe(findings)

	if len(got) != 2 {
		t.Fatalf("want both chains to survive as distinct findings, got %d", len(got))
	}
	byTarget := map[string]models.Finding{}
	for _, f := range got {
		for _, tag := range f.Tags {
			if strings.HasPrefix(tag, "target:") {
				byTarget[tag] = f
			}
		}
	}
	clusterAdmin, ok := byTarget["target:cluster_admin_equivalent"]
	if !ok {
		t.Fatalf("cluster_admin_equivalent finding missing from output: %v", got)
	}
	nodeEscape, ok := byTarget["target:node_escape"]
	if !ok {
		t.Fatalf("node_escape finding missing from output: %v", got)
	}
	if len(clusterAdmin.Tags) != 2 || slices.Contains(clusterAdmin.Tags, "target:node_escape") {
		t.Errorf("cluster_admin_equivalent finding picked up the other finding's target tag: %v", clusterAdmin.Tags)
	}
	if len(nodeEscape.Tags) != 2 || slices.Contains(nodeEscape.Tags, "target:cluster_admin_equivalent") {
		t.Errorf("node_escape finding picked up the other finding's target tag: %v", nodeEscape.Tags)
	}
	if clusterAdmin.EscalationPath[len(clusterAdmin.EscalationPath)-1].Action != "bound_to_cluster_admin" {
		t.Errorf("cluster_admin_equivalent finding lost its own chain: %v", clusterAdmin.EscalationPath)
	}
	if nodeEscape.EscalationPath[len(nodeEscape.EscalationPath)-1].Action != "pod_host_escape" {
		t.Errorf("node_escape finding lost its own chain: %v", nodeEscape.EscalationPath)
	}
}

// TestDedupeStillCollapsesGenuineCrossModuleDuplicates is the companion to the test
// above: two findings with no EscalationPath, sharing RuleID, Subject, and ID, are a
// genuine cross-module duplicate and must still collapse to one. Without this test,
// keying every finding on its ID unconditionally would also satisfy the test above,
// but would break dedupe for the non-privesc modules that rely on the composite key.
func TestDedupeStillCollapsesGenuineCrossModuleDuplicates(t *testing.T) {
	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "app", Name: "sa"}
	findings := []models.Finding{
		{ID: "KUBE-RBAC-OVERBROAD-001:app/sa", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 6.0, Subject: subject, Tags: []string{"module:rbac"}},
		{ID: "KUBE-RBAC-OVERBROAD-001:app/sa", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 6.5, Subject: subject, Tags: []string{"module:serviceaccount"}},
	}

	got := dedupe(findings)

	if len(got) != 1 {
		t.Fatalf("want genuine cross-module duplicates to collapse to 1, got %d", len(got))
	}
	if got[0].Score != 6.5 {
		t.Errorf("want highest score kept: 6.5, got %v", got[0].Score)
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
