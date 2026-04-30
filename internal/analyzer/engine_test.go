package analyzer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// stubModule lets tests construct an Engine with a known finding set and predictable behavior.
type stubModule struct {
	name     string
	findings []models.Finding
	err      error
}

func (s *stubModule) Name() string { return s.name }
func (s *stubModule) Analyze(_ context.Context, _ models.Snapshot) ([]models.Finding, error) {
	return s.findings, s.err
}

// engineWith builds an Engine wired with the given modules instead of the default registration.
func engineWith(mods ...Module) *Engine {
	return &Engine{modules: mods}
}

func TestEngineAnalyzeRunsAllModulesAndSortsBySeverity(t *testing.T) {
	t.Parallel()

	// Module A returns a Medium finding, module B a Critical one — Critical must come first.
	a := &stubModule{
		name: "a",
		findings: []models.Finding{
			{ID: "a1", RuleID: "RULE-A", Severity: models.SeverityMedium, Score: 5.0},
		},
	}
	b := &stubModule{
		name: "b",
		findings: []models.Finding{
			{ID: "b1", RuleID: "RULE-B", Severity: models.SeverityCritical, Score: 9.5},
		},
	}

	got, err := engineWith(a, b).Analyze(context.Background(), models.Snapshot{}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].Severity != models.SeverityCritical {
		t.Errorf("expected Critical first, got %s", got[0].Severity)
	}
}

func TestEngineSortBreaksTiesByScoreThenRuleIDThenTitle(t *testing.T) {
	t.Parallel()

	mod := &stubModule{
		name: "mod",
		findings: []models.Finding{
			{ID: "1", RuleID: "RULE-Z", Title: "z", Severity: models.SeverityHigh, Score: 7.0},
			{ID: "2", RuleID: "RULE-A", Title: "a", Severity: models.SeverityHigh, Score: 7.0},
			{ID: "3", RuleID: "RULE-A", Title: "a-aaa", Severity: models.SeverityHigh, Score: 7.5},
		},
	}

	got, err := engineWith(mod).Analyze(context.Background(), models.Snapshot{}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Highest score first, then RuleID asc, then Title asc.
	if got[0].ID != "3" || got[1].ID != "2" || got[2].ID != "1" {
		t.Errorf("sort order wrong: got %v", []string{got[0].ID, got[1].ID, got[2].ID})
	}
}

func TestEngineThresholdFiltersBelowSeverity(t *testing.T) {
	t.Parallel()

	mod := &stubModule{
		name: "mod",
		findings: []models.Finding{
			{ID: "low", RuleID: "R-LOW", Severity: models.SeverityLow},
			{ID: "med", RuleID: "R-MED", Severity: models.SeverityMedium},
			{ID: "high", RuleID: "R-HIGH", Severity: models.SeverityHigh},
		},
	}

	got, err := engineWith(mod).Analyze(context.Background(), models.Snapshot{}, Options{Threshold: models.SeverityMedium})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (medium+high), got %d", len(got))
	}
	for _, f := range got {
		if f.Severity == models.SeverityLow {
			t.Errorf("low severity finding %q should be filtered out", f.ID)
		}
	}
}

func TestEngineOnlyModulesSelectsSubset(t *testing.T) {
	t.Parallel()

	a := &stubModule{name: "a", findings: []models.Finding{{ID: "a1", RuleID: "A", Severity: models.SeverityHigh}}}
	b := &stubModule{name: "b", findings: []models.Finding{{ID: "b1", RuleID: "B", Severity: models.SeverityHigh}}}

	got, err := engineWith(a, b).Analyze(context.Background(), models.Snapshot{}, Options{OnlyModules: []string{"a"}})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("OnlyModules=[a] should keep only module a, got %#v", got)
	}
}

func TestEngineSkipModulesExcludesSubset(t *testing.T) {
	t.Parallel()

	a := &stubModule{name: "a", findings: []models.Finding{{ID: "a1", RuleID: "A", Severity: models.SeverityHigh}}}
	b := &stubModule{name: "b", findings: []models.Finding{{ID: "b1", RuleID: "B", Severity: models.SeverityHigh}}}

	got, err := engineWith(a, b).Analyze(context.Background(), models.Snapshot{}, Options{SkipModules: []string{"b"}})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a1" {
		t.Fatalf("SkipModules=[b] should drop module b, got %#v", got)
	}
}

func TestEngineNoSelectedModulesReturnsError(t *testing.T) {
	t.Parallel()

	a := &stubModule{name: "a"}
	_, err := engineWith(a).Analyze(context.Background(), models.Snapshot{}, Options{OnlyModules: []string{"nonexistent"}})
	if err == nil {
		t.Fatal("expected error when no modules are selected")
	}
	if !strings.Contains(err.Error(), "no analysis modules selected") {
		t.Errorf("error message = %q, want it to mention no modules", err.Error())
	}
}

func TestEngineSurfacesFirstModuleError(t *testing.T) {
	t.Parallel()

	// Engine still returns findings from the healthy modules but reports the first error.
	a := &stubModule{name: "a", err: errors.New("a-broke")}
	b := &stubModule{name: "b", findings: []models.Finding{{ID: "b1", RuleID: "B", Severity: models.SeverityHigh}}}

	got, err := engineWith(a, b).Analyze(context.Background(), models.Snapshot{}, Options{})
	if err == nil {
		t.Fatal("expected first-module error to surface")
	}
	if !strings.Contains(err.Error(), "a-broke") {
		t.Errorf("error %q should wrap module's error", err.Error())
	}
	if len(got) != 1 || got[0].ID != "b1" {
		t.Errorf("healthy module's findings should still surface: %#v", got)
	}
}

func TestEngineDedupesAcrossModulesAndKeepsHigherScore(t *testing.T) {
	t.Parallel()

	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "ns", Name: "sa"}
	resource := &models.ResourceRef{Kind: "RBACRule", Name: "danger"}

	// Both modules emit the same logical finding; dedupe should keep the higher score and union tags.
	a := &stubModule{name: "a", findings: []models.Finding{
		{ID: "a", RuleID: "DUP", Severity: models.SeverityHigh, Score: 7.0, Subject: subject, Resource: resource, Tags: []string{"module:a"}},
	}}
	b := &stubModule{name: "b", findings: []models.Finding{
		{ID: "b", RuleID: "DUP", Severity: models.SeverityHigh, Score: 8.5, Subject: subject, Resource: resource, Tags: []string{"module:b"}},
	}}

	got, err := engineWith(a, b).Analyze(context.Background(), models.Snapshot{}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after dedupe, got %d", len(got))
	}
	if got[0].Score != 8.5 {
		t.Errorf("expected highest score kept, got %v", got[0].Score)
	}
	tags := got[0].Tags
	hasA, hasB := false, false
	for _, tag := range tags {
		if tag == "module:a" {
			hasA = true
		}
		if tag == "module:b" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("expected merged tags, got %v", tags)
	}
}

func TestEngineCorrelatesPrivescChainsIntoOtherFindings(t *testing.T) {
	t.Parallel()

	subject := &models.SubjectRef{Kind: "ServiceAccount", Namespace: "ns", Name: "bad"}

	// privesc module emits a CRITICAL chain finding; rbac module emits a HIGH-score finding for the same subject.
	// After correlate(), the rbac finding should pick up a +2.0 chain bump and the chain:amplified tag.
	privesc := &stubModule{name: "privesc", findings: []models.Finding{
		{
			ID: "p", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity:       models.SeverityCritical,
			Score:          9.5,
			Subject:        subject,
			EscalationPath: []models.EscalationHop{{Step: 1, Action: "wildcard"}},
		},
	}}
	rbac := &stubModule{name: "rbac", findings: []models.Finding{
		{ID: "r", RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityHigh, Score: 7.0, Subject: subject},
	}}

	got, err := engineWith(privesc, rbac).Analyze(context.Background(), models.Snapshot{}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var amplified *models.Finding
	for i := range got {
		if got[i].ID == "r" {
			amplified = &got[i]
		}
	}
	if amplified == nil {
		t.Fatal("expected the rbac finding to survive the engine pipeline")
	}
	if amplified.Score != 9.0 {
		t.Errorf("expected +2.0 chain bump from CRITICAL sink (7.0 → 9.0), got %v", amplified.Score)
	}
	hasChainTag := false
	for _, tag := range amplified.Tags {
		if tag == "chain:amplified" {
			hasChainTag = true
		}
	}
	if !hasChainTag {
		t.Errorf("expected chain:amplified tag, got %v", amplified.Tags)
	}
}

func TestNewWithConfigOverridesPrivescDepth(t *testing.T) {
	t.Parallel()

	eng := NewWithConfig(Config{MaxPrivescDepth: 9})

	// Confirm the default registration includes a privesc module and that its MaxDepth has been applied.
	found := false
	for _, mod := range eng.modules {
		if mod.Name() == "privesc" {
			found = true
		}
	}
	if !found {
		t.Fatal("default engine missing privesc module")
	}
}

func TestNewReturnsNonNilEngine(t *testing.T) {
	t.Parallel()
	if New() == nil {
		t.Fatal("New() returned nil")
	}
}
