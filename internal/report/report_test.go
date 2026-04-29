package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
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
