package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestWriteProducesExpectedArtifacts(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "test-cluster"

	findings := []models.Finding{
		{
			ID:          "finding-1",
			RuleID:      "KUBE-TEST-001",
			Severity:    models.SeverityHigh,
			Score:       8.2,
			Category:    models.CategoryPrivilegeEscalation,
			Title:       "Test finding",
			Description: "A test finding",
			Namespace:   "default",
			Resource: &models.ResourceRef{
				Kind:      "Deployment",
				Name:      "app",
				Namespace: "default",
			},
			Remediation: "Fix it",
			References:  []string{"https://example.com"},
		},
	}

	written, err := Write(tmpDir, []string{"json", "csv", "sarif"}, snapshot, findings)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	expected := []string{
		filepath.Join(tmpDir, "scan-metadata.json"),
		filepath.Join(tmpDir, "triage.csv"),
		filepath.Join(tmpDir, "findings.json"),
		filepath.Join(tmpDir, "findings.sarif"),
	}

	for _, path := range expected {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}

	if len(written) != len(expected) {
		t.Fatalf("expected %d written artifacts, got %d", len(expected), len(written))
	}
}

func TestReadWriteMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	metadata := models.SnapshotMetadata{
		ClusterName:    "fixture",
		ClusterVersion: "v1.35.0",
	}

	path, err := WriteMetadata(tmpDir, metadata)
	if err != nil {
		t.Fatalf("WriteMetadata() error = %v", err)
	}

	loaded, err := ReadMetadata(path)
	if err != nil {
		t.Fatalf("ReadMetadata() error = %v", err)
	}

	if loaded.ClusterName != metadata.ClusterName || loaded.ClusterVersion != metadata.ClusterVersion {
		t.Fatalf("unexpected metadata round trip: %#v", loaded)
	}
}

func TestBuildHTMLDataGroupsFindings(t *testing.T) {
	t.Parallel()

	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:        "f1",
			RuleID:    "KUBE-RBAC-1",
			Severity:  models.SeverityCritical,
			Category:  models.CategoryPrivilegeEscalation,
			Title:     "Critical RBAC",
			Namespace: "default",
			Subject:   &models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: "default"},
			Resource:  &models.ResourceRef{Kind: "RBACRule", Name: "admin"},
			Tags:      []string{"module:rbac"},
		},
		{
			ID:        "f2",
			RuleID:    "KUBE-NETPOL-1",
			Severity:  models.SeverityHigh,
			Category:  models.CategoryLateralMovement,
			Title:     "Open network",
			Namespace: "prod",
			Resource:  &models.ResourceRef{Kind: "Namespace", Name: "prod", Namespace: "prod"},
			Tags:      []string{"module:network_policy"},
		},
	}

	data := BuildHTMLData(snapshot, findings)
	if data.Summary.Total != 2 {
		t.Fatalf("expected total summary of 2, got %#v", data.Summary)
	}
	if len(data.Modules) != 2 {
		t.Fatalf("expected 2 module sections, got %d", len(data.Modules))
	}
	if data.Modules[0].Label != "RBAC" {
		t.Fatalf("expected first module to be RBAC, got %s", data.Modules[0].Label)
	}
	if len(data.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(data.Categories))
	}
	if len(data.TopNamespaces) == 0 || data.TopNamespaces[0].Label != "default" {
		t.Fatalf("unexpected top namespaces: %#v", data.TopNamespaces)
	}
	// The recon panel must always be populated end-to-end so the template never
	// nil-derefs; HeadlineChips is the four-pill teaser shown on the closed disclosure.
	if got := len(data.Recon.HeadlineChips); got != 4 {
		t.Fatalf("Recon.HeadlineChips: want 4, got %d", got)
	}
	if data.Recon.Shape.NodeCount != 0 {
		t.Errorf("Recon.Shape.NodeCount: want 0 from empty snapshot, got %d", data.Recon.Shape.NodeCount)
	}
}

// TestBuildHTMLDataReconPlumbsPrivescAnchor verifies that a privesc finding present in
// the input slice surfaces a clickable anchor on the recon panel — the cheapest end-to-end
// proof that buildRecon is wired into BuildHTMLData rather than left dangling.
func TestBuildHTMLDataReconPlumbsPrivescAnchor(t *testing.T) {
	t.Parallel()

	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:       "f-privesc",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "privesc path",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
			Tags:     []string{"module:privesc"},
		},
	}

	data := BuildHTMLData(snapshot, findings)
	if data.Recon.Ownership.PrivescToAdminCount != 1 {
		t.Errorf("PrivescToAdminCount: want 1, got %d", data.Recon.Ownership.PrivescToAdminCount)
	}
	if data.Recon.Ownership.PrivescToAdminAnchor != "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Errorf("PrivescToAdminAnchor: want finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN, got %q",
			data.Recon.Ownership.PrivescToAdminAnchor)
	}
}

func TestBuildHTMLDataTOCEntries(t *testing.T) {
	t.Parallel()

	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		// Two findings sharing one RuleID — the TOC must collapse them into one
		// entry with Count=2 and pick the higher severity (Critical here).
		{
			ID:       "f1",
			RuleID:   "KUBE-RBAC-1",
			Severity: models.SeverityCritical,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Wildcard verb on wildcard resource",
			Tags:     []string{"module:rbac"},
		},
		{
			ID:       "f2",
			RuleID:   "KUBE-RBAC-1",
			Severity: models.SeverityHigh,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Wildcard verb on wildcard resource",
			Tags:     []string{"module:rbac"},
		},
		// A second rule in the same module — lower severity so it sorts after the
		// collapsed entry above.
		{
			ID:       "f3",
			RuleID:   "KUBE-RBAC-2",
			Severity: models.SeverityHigh,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Bind/escalate verb granted",
			Tags:     []string{"module:rbac"},
		},
		// Different module + category — exercises the by-category bucketing.
		{
			ID:       "f4",
			RuleID:   "KUBE-NETPOL-1",
			Severity: models.SeverityMedium,
			Category: models.CategoryLateralMovement,
			Title:    "Open network",
			Tags:     []string{"module:network_policy"},
		},
	}

	data := BuildHTMLData(snapshot, findings)

	// Locate the RBAC module section deterministically (order varies with severity sort).
	var rbac *ModuleSection
	for i := range data.Modules {
		if data.Modules[i].ID == "rbac" {
			rbac = &data.Modules[i]
			break
		}
	}
	if rbac == nil {
		t.Fatalf("expected an RBAC module section, got modules: %#v", data.Modules)
	}

	if got := len(rbac.Entries); got != 2 {
		t.Fatalf("RBAC TOC: expected 2 entries (one per RuleID), got %d: %#v", got, rbac.Entries)
	}
	first := rbac.Entries[0]
	if first.RuleID != "KUBE-RBAC-1" {
		t.Fatalf("RBAC TOC[0]: expected RuleID KUBE-RBAC-1 (highest severity), got %s", first.RuleID)
	}
	if first.Severity != models.SeverityCritical {
		t.Fatalf("RBAC TOC[0]: expected severity to be raised to Critical, got %s", first.Severity)
	}
	if first.Count != 2 {
		t.Fatalf("RBAC TOC[0]: expected Count=2 (collapsed instances), got %d", first.Count)
	}
	if first.Anchor != "finding-KUBE-RBAC-1" {
		t.Fatalf("RBAC TOC[0]: expected Anchor=finding-KUBE-RBAC-1, got %q", first.Anchor)
	}
	if rbac.Entries[1].RuleID != "KUBE-RBAC-2" {
		t.Fatalf("RBAC TOC[1]: expected RuleID KUBE-RBAC-2, got %s", rbac.Entries[1].RuleID)
	}
	if rbac.Entries[1].Count != 1 {
		t.Fatalf("RBAC TOC[1]: expected Count=1, got %d", rbac.Entries[1].Count)
	}

	// By-category view — Privilege Escalation should hold both KUBE-RBAC-* rules.
	var privesc *CategorySection
	for i := range data.Categories {
		if data.Categories[i].CSSKey == "privesc" {
			privesc = &data.Categories[i]
			break
		}
	}
	if privesc == nil {
		t.Fatalf("expected a Privilege Escalation category section, got: %#v", data.Categories)
	}
	if got := len(privesc.Entries); got != 2 {
		t.Fatalf("Privesc category TOC: expected 2 entries, got %d: %#v", got, privesc.Entries)
	}
	if privesc.Entries[0].RuleID != "KUBE-RBAC-1" || privesc.Entries[0].Anchor != "finding-KUBE-RBAC-1" {
		t.Fatalf("Privesc category TOC[0]: unexpected entry %#v", privesc.Entries[0])
	}
}

func TestBuildHTMLDataRuleGroups(t *testing.T) {
	t.Parallel()

	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		// Three findings sharing one RuleID (different subjects) — should collapse
		// into one RuleGroup with InstanceCount=3 and the highest severity bubbled up.
		{
			ID:       "f1",
			RuleID:   "KUBE-RBAC-1",
			Severity: models.SeverityHigh,
			Score:    8.0,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "`ServiceAccount/default/a` can reach cluster-admin",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "a", Namespace: "default"},
			MitreTechniques: []models.MitreTechnique{
				{ID: "T1078", Name: "Valid Accounts", URL: "https://attack.mitre.org/techniques/T1078/"},
			},
			References: []string{"https://example.com/rbac-1"},
			Tags:       []string{"module:rbac"},
		},
		{
			ID:       "f2",
			RuleID:   "KUBE-RBAC-1",
			Severity: models.SeverityCritical, // top severity for the group
			Score:    9.5,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "`Group/admins` can reach cluster-admin",
			Subject:  &models.SubjectRef{Kind: "Group", Name: "admins"},
			Tags:     []string{"module:rbac"},
		},
		{
			ID:       "f3",
			RuleID:   "KUBE-RBAC-1",
			Severity: models.SeverityHigh,
			Score:    7.5,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "`ServiceAccount/default/b` can reach cluster-admin",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "b", Namespace: "default"},
			Tags:     []string{"module:rbac"},
		},
		// A second rule in the same module — separate group with InstanceCount=1.
		{
			ID:       "f4",
			RuleID:   "KUBE-RBAC-2",
			Severity: models.SeverityHigh,
			Score:    7.0,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Bind/escalate granted",
			Tags:     []string{"module:rbac"},
		},
	}

	data := BuildHTMLData(snapshot, findings)

	var rbac *ModuleSection
	for i := range data.Modules {
		if data.Modules[i].ID == "rbac" {
			rbac = &data.Modules[i]
			break
		}
	}
	if rbac == nil {
		t.Fatalf("expected an RBAC module section")
	}
	if got := len(rbac.RuleGroups); got != 2 {
		t.Fatalf("expected 2 RuleGroups (one per RuleID), got %d", got)
	}
	first := rbac.RuleGroups[0]
	if first.RuleID != "KUBE-RBAC-1" {
		t.Fatalf("first group RuleID: want KUBE-RBAC-1, got %s", first.RuleID)
	}
	if first.InstanceCount != 3 {
		t.Fatalf("first group InstanceCount: want 3, got %d", first.InstanceCount)
	}
	if first.TopSeverity != models.SeverityCritical {
		t.Fatalf("first group TopSeverity: want Critical, got %s", first.TopSeverity)
	}
	if first.MaxScore != 9.5 || first.MinScore != 7.5 {
		t.Fatalf("first group score range: want [7.5, 9.5], got [%v, %v]", first.MinScore, first.MaxScore)
	}
	if first.Anchor != "finding-KUBE-RBAC-1" {
		t.Fatalf("first group Anchor: want finding-KUBE-RBAC-1, got %q", first.Anchor)
	}
	// MITRE / References should be lifted from the exemplar (first occurrence).
	if len(first.MitreTechniques) != 1 || first.MitreTechniques[0].ID != "T1078" {
		t.Fatalf("first group MitreTechniques: want lifted from exemplar, got %#v", first.MitreTechniques)
	}
	if len(first.References) != 1 || first.References[0] != "https://example.com/rbac-1" {
		t.Fatalf("first group References: want lifted from exemplar, got %#v", first.References)
	}
	// RuleTitle should be subject-neutralized — the exemplar's subject was
	// "Group/admins", which prefixes the title; the helper replaces it with "Subjects".
	if !strings.Contains(first.RuleTitle, "Subjects ") {
		t.Fatalf("first group RuleTitle: want subject-neutralized, got %q", first.RuleTitle)
	}
	if rbac.RuleGroups[1].RuleID != "KUBE-RBAC-2" || rbac.RuleGroups[1].InstanceCount != 1 {
		t.Fatalf("second group: want KUBE-RBAC-2 / count=1, got %#v", rbac.RuleGroups[1])
	}
}

func TestRuleTitleForGroup(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title string
		subj  *models.SubjectRef
		want  string
	}{
		{
			title: "`ServiceAccount/default/risky` can reach cluster-admin equivalent in 1 hop(s)",
			subj:  &models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
			want:  "Subjects can reach cluster-admin equivalent in 1 hop(s)",
		},
		{
			title: "Group/kubeadm:cluster-admins can reach cluster-admin",
			subj:  &models.SubjectRef{Kind: "Group", Name: "kubeadm:cluster-admins"},
			want:  "Subjects can reach cluster-admin",
		},
		{
			title: "Wildcard verb on wildcard resource",
			subj:  nil,
			want:  "Wildcard verb on wildcard resource",
		},
		{
			title: "Privesc path", // subject set but not a leading match — leave alone
			subj:  &models.SubjectRef{Kind: "ServiceAccount", Name: "x", Namespace: "y"},
			want:  "Privesc path",
		},
		{
			// Trailing em-dash pattern with backticked subject (rbac titles).
			title: "Cluster-wide `impersonate` permission — `ServiceAccount/rbac-fixtures/sa-impersonate`",
			subj:  &models.SubjectRef{Kind: "ServiceAccount", Name: "sa-impersonate", Namespace: "rbac-fixtures"},
			want:  "Cluster-wide `impersonate` permission",
		},
		{
			// Trailing parenthesized backticked subject (rbac titles).
			title: "Cluster-wide `bind/escalate` on roles — RBAC bypass (`ServiceAccount/ns/sa`)",
			subj:  &models.SubjectRef{Kind: "ServiceAccount", Name: "sa", Namespace: "ns"},
			want:  "Cluster-wide `bind/escalate` on roles — RBAC bypass",
		},
	}
	for _, tc := range cases {
		got := ruleTitleForGroup(models.Finding{Title: tc.title, Subject: tc.subj})
		if got != tc.want {
			t.Errorf("ruleTitleForGroup(title=%q): got %q, want %q", tc.title, got, tc.want)
		}
	}
}

func TestRenderInlineCodeMarkdown(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{"`Group/x` can reach **cluster-admin** in 1 hop", "<code>Group/x</code> can reach <strong>cluster-admin</strong> in 1 hop"},
		{"unmatched `still safe", "unmatched still safe"},
		{"unmatched **still safe", "unmatched **still safe"},
		{"<script>", "&lt;script&gt;"},
		{"line one\nline two", "line one<br>line two"},
	}
	for _, tc := range cases {
		got := renderInlineCode(tc.in)
		if got != tc.want {
			t.Errorf("renderInlineCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHTMLReportInteractiveGraph verifies the rendered HTML carries the markup the JS layer
// requires (CSP allows scripts, JSON payload is embedded, nodes/edges have data IDs). It is a
// smoke test for the contract between Go and the embedded interactivity, not a behaviour test.
func TestHTMLReportInteractiveGraph(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:       "f-cap",
			RuleID:   "KUBE-PRIVESC-009",
			Severity: models.SeverityCritical,
			Score:    9.5,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "RBAC bind/escalate permission",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
			Tags:     []string{"module:rbac"},
		},
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}

	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	mustContain := []string{
		`script-src 'unsafe-inline'`,
		`<script type="application/json" id="kp-graph-data">`,
		`data-node-id=`,
		`data-edge-id=`,
		`class="kp-filters"`,
		`class="kp-detail"`,
		`class="kp-tooltip"`,
		`KUBE-PRIVESC-009`,
		// Cluster-reconnaissance panel — collapsed by default but always rendered.
		`class="recon-card"`,
		`Cluster reconnaissance`,
	}
	for _, needle := range mustContain {
		if !strings.Contains(html, needle) {
			t.Errorf("rendered HTML missing %q", needle)
		}
	}
}

// TestHTMLReportHidesEvidenceWhenAllKeysSuppressed verifies the template-level gate
// for the Evidence section. Privesc-path findings carry only suppressed evidence keys
// (target/hop_count/techniques/first_action/chain_summary), so renderEvidence returns
// "" — and the surrounding wrapper must hide rather than emit an empty box.
// Sister test: TestRenderEvidenceSuppressesPrivescSummary in evidence_render_test.go
// covers the unit-level behavior of renderEvidence; this one covers the template gate.
func TestHTMLReportHidesEvidenceWhenAllKeysSuppressed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()

	rawEvidence, err := json.Marshal(map[string]any{
		"target":        "cluster_admin_equivalent",
		"hop_count":     1,
		"techniques":    []string{"impersonate"},
		"first_action":  "impersonate",
		"chain_summary": []string{"1. impersonate"},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}

	findings := []models.Finding{
		{
			ID:       "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/default/risky:cluster_admin_equivalent",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    9.8,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Privesc path",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
			Evidence: rawEvidence,
			EscalationPath: []models.EscalationHop{
				{
					Step:        1,
					Action:      "impersonate",
					FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
					Permission:  "impersonate users",
					Gains:       "cluster-admin",
				},
			},
			Tags: []string{"module:privesc"},
		},
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	// Sanity: the OBSERVED ATTACK CHAIN block still rendered — that's what justifies
	// hiding Evidence in the first place.
	if !strings.Contains(html, `class="attack-chain"`) {
		t.Fatalf("expected EscalationPath markup (attack-chain) to render, but it is missing")
	}

	// The technique glossary explainer must surface for any known hop technique
	// (here: "impersonate"). If this assertion ever fails, the chain card has
	// regressed back to printing slugs without their plain-English description.
	if !strings.Contains(html, `class="step-explainer"`) {
		t.Fatalf("expected glossary-driven step-explainer markup in attack-chain card, but it is missing")
	}
	// And the human-readable technique title (from glossary.Techniques) must be
	// surfaced rather than only the raw slug.
	if !strings.Contains(html, `RBAC impersonation`) {
		t.Fatalf("expected technique title %q in chain card, but it is missing", "RBAC impersonation")
	}

	// The "Evidence" header markup must NOT appear, since the structured grid was empty.
	if strings.Contains(html, `<span class="k">Evidence</span>`) {
		t.Errorf("Evidence section still rendered for fully-suppressed payload — expected the wrapper to be hidden")
	}
	// The "Show raw JSON" toggle is part of the same wrapper — it must also be gone.
	if strings.Contains(html, `class="evidence-raw"`) {
		t.Errorf("evidence-raw <details> still rendered for fully-suppressed payload — expected the wrapper to be hidden")
	}
}

// TestHTMLReportAlternateCopyNamesTheCutAtBothSites renders a real report and checks
// the alternate copy where an operator actually reads it. The unit tests in
// evidence_render_test.go pin the strings; this pins the WIRING, which the unit tests
// structurally cannot: both call sites are template calls, so an alternate block that
// renders with a stale argument list fails at execution time and nothing else in the
// suite executes the template with a finding carrying an alternate.
//
// The same finding renders in two places with different surroundings: the Findings tab
// (`alt-chain` above a Remediation block) and the Privilege-Escalation Paths card (no
// Remediation on the card at all). Both must name the evaluated cut, which is hop 1 of
// the PRIMARY chain and not the hop the Remediation prose recommends.
func TestHTMLReportAlternateCopyNamesTheCutAtBothSites(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "mh"}

	findings := []models.Finding{
		{
			ID:       "KUBE-PRIVESC-PATH-SYSTEM-MASTERS:ServiceAccount/mh/src:system_masters",
			RuleID:   "KUBE-PRIVESC-PATH-SYSTEM-MASTERS",
			Severity: models.SeverityCritical,
			Score:    9.5,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "Privesc path to system:masters",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "mh"},
			// The recommended fix targets hop 2, while the evaluated cut is hop 1's
			// binding. That gap is the whole point of Important 3.
			Remediation: "Remove every `impersonate` grant on a path to `system:masters`.",
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "pod_create_token_theft", FromSubject: subject, SourceBinding: "mh-pods-a"},
				{Step: 2, Action: "impersonate", FromSubject: subject, SourceBinding: "mh-impersonate"},
			},
			AlternateEscalationPath: []models.EscalationHop{
				{Step: 1, Action: "pod_create_token_theft", FromSubject: subject, SourceBinding: "mh-pods-b"},
				{Step: 2, Action: "impersonate", FromSubject: subject, SourceBinding: "mh-impersonate"},
			},
			Tags: []string{"module:privesc", "privesc:survives-first-cut"},
		},
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	// Premise: both alternate blocks rendered at all (one per render site). Without
	// this the assertions below would pass just as happily against a report that
	// dropped the feature.
	if got := strings.Count(html, `<details class="alt-chain">`); got != 2 {
		t.Fatalf("want an alt-chain block at both render sites, got %d (fixture regression, not a pass)", got)
	}
	if got := strings.Count(html, "Survives cutting the <code>mh-pods-a</code> binding (2 hops)"); got != 2 {
		t.Errorf("want the summary naming the evaluated cut at both render sites, got %d occurrence(s)", got)
	}
	if got := strings.Count(html, "without the <code>mh-pods-a</code> binding"); got != 2 {
		t.Errorf("want the lead-in naming the evaluated cut at both render sites, got %d occurrence(s)", got)
	}
	// The cut is hop 1's binding, never the mid-chain hop the Remediation recommends.
	if strings.Contains(html, "Survives cutting the <code>mh-impersonate</code>") {
		t.Error("alternate copy named the remediation's hop, not the binding the cut pass evaluated")
	}
	for _, banned := range []string{"This fix does not close the route", "the fix above removes"} {
		if strings.Contains(html, banned) {
			t.Errorf("report still carries the overclaiming copy %q", banned)
		}
	}
}

func TestHTMLReportRendersTruncationBanner(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "trunc-banner-on"

	findings := []models.Finding{{
		ID:       "finding-1",
		RuleID:   "KUBE-TEST-001",
		Severity: models.SeverityHigh,
		Score:    8.0,
		Category: models.CategoryPrivilegeEscalation,
		Title:    "Banner fixture",
	}}

	written, err := WriteWithAdmission(tmpDir, []string{"html"}, snapshot, findings,
		models.AdmissionSummary{},
		models.TruncationInfo{Truncated: true, Original: 147, Shown: 20, Limit: 20})
	if err != nil {
		t.Fatalf("WriteWithAdmission() error = %v", err)
	}

	// Truncation sidecar must be written when the cap fired.
	sidecarFound := false
	for _, p := range written {
		if filepath.Base(p) == "truncation-info.json" {
			sidecarFound = true
		}
	}
	if !sidecarFound {
		t.Fatalf("expected truncation-info.json in written artifacts: %v", written)
	}

	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	if !strings.Contains(html, `<div class="truncation-banner"`) {
		t.Errorf("expected .truncation-banner div in HTML output")
	}
	if !strings.Contains(html, "Showing top 20 of 147 findings") {
		t.Errorf("expected banner copy with shown/original counts in HTML output")
	}
	if !strings.Contains(html, "kubesplaining scan --all-findings") {
		t.Errorf("expected banner to include the --all-findings rerun command")
	}
}

func TestHTMLReportOmitsTruncationBannerWhenNotTruncated(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "trunc-banner-off"

	findings := []models.Finding{{
		ID:       "finding-1",
		RuleID:   "KUBE-TEST-002",
		Severity: models.SeverityLow,
		Score:    2.0,
		Category: models.CategoryPrivilegeEscalation,
		Title:    "No-banner fixture",
	}}

	written, err := WriteWithAdmission(tmpDir, []string{"html"}, snapshot, findings,
		models.AdmissionSummary{}, models.TruncationInfo{})
	if err != nil {
		t.Fatalf("WriteWithAdmission() error = %v", err)
	}

	// No sidecar when truncation didn't fire.
	for _, p := range written {
		if filepath.Base(p) == "truncation-info.json" {
			t.Fatalf("did not expect truncation-info.json when not truncated, got %v", written)
		}
	}

	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	if strings.Contains(html, `<div class="truncation-banner"`) {
		t.Errorf("did not expect .truncation-banner div in HTML when not truncated")
	}
	if strings.Contains(html, "Showing top") {
		t.Errorf("did not expect banner copy in HTML when not truncated")
	}
}

func TestSARIFEmbedsTruncationProperty(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "sarif-trunc"

	findings := []models.Finding{{
		ID:       "finding-1",
		RuleID:   "KUBE-TEST-003",
		Severity: models.SeverityHigh,
		Score:    7.5,
		Title:    "SARIF fixture",
	}}

	if _, err := WriteWithAdmission(tmpDir, []string{"sarif"}, snapshot, findings,
		models.AdmissionSummary{},
		models.TruncationInfo{Truncated: true, Original: 50, Shown: 20, Limit: 20}); err != nil {
		t.Fatalf("WriteWithAdmission() error = %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(tmpDir, "findings.sarif"))
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}

	var doc struct {
		Runs []struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	truncRaw, ok := doc.Runs[0].Properties["truncation"]
	if !ok {
		t.Fatalf("expected runs[0].properties.truncation, got keys: %v", doc.Runs[0].Properties)
	}
	var info models.TruncationInfo
	if err := json.Unmarshal(truncRaw, &info); err != nil {
		t.Fatalf("decode truncation property: %v", err)
	}
	want := models.TruncationInfo{Truncated: true, Original: 50, Shown: 20, Limit: 20}
	if info != want {
		t.Errorf("truncation property = %#v, want %#v", info, want)
	}
}

func TestSARIFOmitsTruncationPropertyWhenNotTruncated(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "sarif-no-trunc"

	findings := []models.Finding{{
		ID:       "finding-1",
		RuleID:   "KUBE-TEST-004",
		Severity: models.SeverityLow,
		Score:    2.0,
		Title:    "SARIF fixture",
	}}

	if _, err := WriteWithAdmission(tmpDir, []string{"sarif"}, snapshot, findings,
		models.AdmissionSummary{}, models.TruncationInfo{}); err != nil {
		t.Fatalf("WriteWithAdmission() error = %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(tmpDir, "findings.sarif"))
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}

	var doc struct {
		Runs []struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if _, ok := doc.Runs[0].Properties["truncation"]; ok {
		t.Errorf("did not expect truncation property when not truncated")
	}
}

func TestReadWriteTruncationInfoRoundTrip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	info := models.TruncationInfo{
		Truncated: true,
		Original:  147,
		Shown:     20,
		Limit:     20,
	}

	path, err := WriteTruncationInfo(tmpDir, info)
	if err != nil {
		t.Fatalf("WriteTruncationInfo() error = %v", err)
	}
	if path != filepath.Join(tmpDir, "truncation-info.json") {
		t.Fatalf("unexpected path: %s", path)
	}

	loaded, err := ReadTruncationInfo(path)
	if err != nil {
		t.Fatalf("ReadTruncationInfo() error = %v", err)
	}

	if loaded != info {
		t.Fatalf("round-trip mismatch: got %#v, want %#v", loaded, info)
	}
}

func TestGuessTruncationInfoPath(t *testing.T) {
	t.Parallel()

	got := GuessTruncationInfoPath(filepath.Join("some", "dir", "findings.json"))
	want := filepath.Join("some", "dir", "truncation-info.json")
	if got != want {
		t.Fatalf("GuessTruncationInfoPath = %q, want %q", got, want)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	// Build a deterministic findings slice with N entries, all in the same
	// category — diverseTopN degenerates to a plain prefix slice in that case,
	// so the index-based assertions below still hold.
	build := func(n int) []models.Finding {
		out := make([]models.Finding, n)
		for i := range out {
			out[i] = models.Finding{
				ID:       "f-" + string(rune('a'+i)),
				RuleID:   "RULE-" + string(rune('A'+i)),
				Severity: models.SeverityHigh,
				Category: models.CategoryPrivilegeEscalation,
			}
		}
		return out
	}

	cases := []struct {
		name        string
		input       int
		limit       int
		allFindings bool
		wantLen     int
		wantTrunc   bool
		wantOrig    int
	}{
		{name: "below cap", input: 3, limit: 5, wantLen: 3, wantTrunc: false},
		{name: "at cap", input: 5, limit: 5, wantLen: 5, wantTrunc: false},
		{name: "above cap", input: 10, limit: 5, wantLen: 5, wantTrunc: true, wantOrig: 10},
		{name: "all-findings overrides", input: 10, limit: 5, allFindings: true, wantLen: 10, wantTrunc: false},
		{name: "limit zero is no-op", input: 10, limit: 0, wantLen: 10, wantTrunc: false},
		{name: "limit negative is no-op", input: 10, limit: -1, wantLen: 10, wantTrunc: false},
		{name: "empty input", input: 0, limit: 5, wantLen: 0, wantTrunc: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := build(tc.input)
			gotFindings, gotInfo := Truncate(input, tc.limit, tc.allFindings)

			if len(gotFindings) != tc.wantLen {
				t.Fatalf("len(findings) = %d, want %d", len(gotFindings), tc.wantLen)
			}
			if gotInfo.Truncated != tc.wantTrunc {
				t.Fatalf("info.Truncated = %v, want %v", gotInfo.Truncated, tc.wantTrunc)
			}
			if tc.wantTrunc {
				if gotInfo.Original != tc.wantOrig {
					t.Errorf("info.Original = %d, want %d", gotInfo.Original, tc.wantOrig)
				}
				if gotInfo.Shown != tc.wantLen {
					t.Errorf("info.Shown = %d, want %d", gotInfo.Shown, tc.wantLen)
				}
				if gotInfo.Limit != tc.limit {
					t.Errorf("info.Limit = %d, want %d", gotInfo.Limit, tc.limit)
				}
				// Top-N preservation: first element must equal the input's first element.
				if gotFindings[0].RuleID != input[0].RuleID {
					t.Errorf("top-N preservation: first finding RuleID = %q, want %q",
						gotFindings[0].RuleID, input[0].RuleID)
				}
			} else {
				// Zero-value info when no truncation.
				if gotInfo != (models.TruncationInfo{}) {
					t.Errorf("expected zero TruncationInfo when not truncated, got %#v", gotInfo)
				}
			}
		})
	}
}

func TestTruncateDiversifiesAcrossCategories(t *testing.T) {
	t.Parallel()

	// Simulate the e2e shape: a single dominant category (privesc) with many
	// findings, plus a handful of lower-volume categories. Without
	// diversification, top-N would be all privesc; with diversification, every
	// category should appear in the truncated set.
	categories := []models.RiskCategory{
		models.CategoryPrivilegeEscalation,        // 30 entries
		models.CategoryLateralMovement,            // 5 entries
		models.CategoryDataExfiltration,           // 3 entries
		models.CategoryInfrastructureModification, // 2 entries
		models.CategoryDefenseEvasion,             // 1 entry
	}
	counts := []int{30, 5, 3, 2, 1}

	// Build a globally severity-sorted slice: privesc occupies all 30 top
	// slots (CRITICAL, score 9.5), then 5 lateral CRITICALs at score 9.0,
	// then 3 exfil HIGHs, then 2 infra HIGHs, then 1 evasion MEDIUM. This
	// matches the analyzer's sort output: privesc dominates the prefix.
	findings := make([]models.Finding, 0, 41)
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityCritical,
		models.SeverityHigh, models.SeverityHigh, models.SeverityMedium,
	}
	scores := []float64{9.5, 9.0, 8.0, 7.5, 6.0}
	for i, cat := range categories {
		for j := 0; j < counts[i]; j++ {
			findings = append(findings, models.Finding{
				ID:       string(cat) + "-" + string(rune('a'+j)),
				RuleID:   "RULE-" + string(cat) + "-" + string(rune('A'+j)),
				Severity: severities[i],
				Score:    scores[i],
				Category: cat,
			})
		}
	}
	if len(findings) != 41 {
		t.Fatalf("fixture wiring: expected 41 findings, got %d", len(findings))
	}

	got, info := Truncate(findings, 10, false)

	if !info.Truncated {
		t.Fatalf("expected truncation to fire on 41-finding input with limit=10")
	}
	if len(got) != 10 {
		t.Fatalf("len(got) = %d, want 10", len(got))
	}

	// Every category that has findings must appear in the truncated set.
	seen := make(map[models.RiskCategory]int)
	for _, f := range got {
		seen[f.Category]++
	}
	for _, cat := range categories {
		if seen[cat] == 0 {
			t.Errorf("category %q absent from truncated set: %#v", cat, seen)
		}
	}

	// Verify the absolute top finding (privesc-a, the very first input entry)
	// is preserved as the top of the result — diversification must not
	// displace the highest-severity finding from position 0.
	if got[0].ID != "privilege_escalation-a" {
		t.Errorf("expected top finding to be the global top-1 'privilege_escalation-a', got %q", got[0].ID)
	}

	// Verify the result is sorted by severity rank → score.
	for i := 1; i < len(got); i++ {
		prev, cur := got[i-1], got[i]
		if prev.Severity.Rank() < cur.Severity.Rank() {
			t.Errorf("result not severity-sorted at index %d: %s before %s", i, prev.Severity, cur.Severity)
		}
	}
}

func TestDiverseTopNSingleCategoryDegenerates(t *testing.T) {
	t.Parallel()

	// When every finding shares a category, diverseTopN must return the
	// plain prefix slice — no reshuffling, no reordering.
	in := []models.Finding{
		{ID: "1", RuleID: "A", Severity: models.SeverityHigh, Category: models.CategoryPrivilegeEscalation},
		{ID: "2", RuleID: "B", Severity: models.SeverityHigh, Category: models.CategoryPrivilegeEscalation},
		{ID: "3", RuleID: "C", Severity: models.SeverityHigh, Category: models.CategoryPrivilegeEscalation},
	}
	got := diverseTopN(in, 2)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].ID != "1" || got[1].ID != "2" {
		t.Errorf("expected prefix [1,2], got [%s,%s]", got[0].ID, got[1].ID)
	}
}
