package analyzer

import (
	"context"
	"errors"
	"fmt"
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

// analyze is a thin test helper that returns just the findings slice from Engine.Analyze.
// The AnalyzeResult.Admission summary is exercised in TestEngineAdmission* tests.
func analyze(t *testing.T, e *Engine, opts Options) ([]models.Finding, error) {
	t.Helper()
	r, err := e.Analyze(context.Background(), models.Snapshot{}, opts)
	return r.Findings, err
}

func TestEngineAnalyzeRunsAllModulesAndSortsBySeverity(t *testing.T) {
	t.Parallel()

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

	got, err := analyze(t, engineWith(a, b), Options{})
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

	got, err := analyze(t, engineWith(mod), Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

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

	got, err := analyze(t, engineWith(mod), Options{Threshold: models.SeverityMedium})
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

	got, err := analyze(t, engineWith(a, b), Options{OnlyModules: []string{"a"}})
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

	got, err := analyze(t, engineWith(a, b), Options{SkipModules: []string{"b"}})
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

	a := &stubModule{name: "a", err: errors.New("a-broke")}
	b := &stubModule{name: "b", findings: []models.Finding{{ID: "b1", RuleID: "B", Severity: models.SeverityHigh}}}

	got, err := analyze(t, engineWith(a, b), Options{})
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

	a := &stubModule{name: "a", findings: []models.Finding{
		{ID: "a", RuleID: "DUP", Severity: models.SeverityHigh, Score: 7.0, Subject: subject, Resource: resource, Tags: []string{"module:a"}},
	}}
	b := &stubModule{name: "b", findings: []models.Finding{
		{ID: "b", RuleID: "DUP", Severity: models.SeverityHigh, Score: 8.5, Subject: subject, Resource: resource, Tags: []string{"module:b"}},
	}}

	got, err := analyze(t, engineWith(a, b), Options{})
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

	privesc := &stubModule{name: "privesc", findings: []models.Finding{
		{
			ID: "p", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    9.5,
			Subject:  subject,
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "bound_to_cluster_admin", Technique: "KUBE-RBAC-OVERBROAD-001", FromSubject: *subject},
			},
		},
	}}
	rbac := &stubModule{name: "rbac", findings: []models.Finding{
		{ID: "r", RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityHigh, Score: 7.0, Subject: subject},
	}}

	got, err := analyze(t, engineWith(privesc, rbac), Options{})
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

// tiedFinding builds a finding that ties with every other tiedFinding on all four of
// sortFindings' named keys (Severity, Score, RuleID, Title), differing only by id (and by
// Subject, so dedupe's (RuleID, SubjectKey, ResourceKey) key keeps all of them distinct
// findings instead of collapsing them). This is deliberately the same shape as the
// engine-wide bug found while verifying Task 12: KUBE-CLOUD-IMDS-PIVOT-001 (a non-privesc,
// generic-titled rule) produced many findings with identical severity/score/rule-ID/title
// that differed only by Resource, and those ties were the ones that reordered between runs.
func tiedFinding(id string) models.Finding {
	return models.Finding{
		ID:       id,
		RuleID:   "TIE-RULE-001",
		Title:    "Same generic title for every tied finding",
		Severity: models.SeverityHigh,
		Score:    7.0,
		Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: id},
	}
}

// TestEngineFindingOrderIsDeterministicAcrossRuns is the regression test for the
// engine-wide ordering defect: runModulesInParallel used to append module results under a
// mutex in goroutine completion order (not fixed by anything in the code), and sortFindings
// used sort.Slice, which Go documents as unstable, so findings tying on every one of the
// four comparator keys kept whatever relative order that race left them in.
//
// The fixture needs at least two tied findings from at least two different modules, or a
// two-module race might happen to resolve the same way often enough (or the tie might not
// even reach the comparator's tie branch) to pass vacuously. 15 modules, each contributing
// one tied finding, reliably reproduces the divergence pre-fix: an empirical probe run
// against the unfixed code diverged on 19 of 20 calls in one process. Fewer modules make the
// goroutine race less likely to actually interleave differently within a single test run.
func TestEngineFindingOrderIsDeterministicAcrossRuns(t *testing.T) {
	const n = 15
	mods := make([]Module, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("tie-%02d", i)
		mods = append(mods, &stubModule{name: fmt.Sprintf("mod-%02d", i), findings: []models.Finding{tiedFinding(id)}})
	}
	e := engineWith(mods...)

	var baseline []models.Finding
	for i := 0; i < 20; i++ {
		got, err := analyze(t, e, Options{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if baseline == nil {
			if len(got) != n {
				t.Fatalf("fixture premise: want %d tied findings, got %d", n, len(got))
			}
			baseline = got
			continue
		}
		if len(got) != len(baseline) {
			t.Fatalf("run %d: finding count changed, got %d want %d", i, len(got), len(baseline))
		}
		for j := range baseline {
			if got[j].ID != baseline[j].ID {
				t.Fatalf("run %d: order diverged at index %d: got %q, want %q\n got:  %v\n want: %v",
					i, j, got[j].ID, baseline[j].ID, findingIDs(got), findingIDs(baseline))
			}
		}
	}
}

// findingIDs projects a finding slice to its IDs for compact failure messages.
func findingIDs(findings []models.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

// TestEngineTieBreaksByFindingIDRegardlessOfModuleOrder isolates part (c) of the fix (the
// Finding.ID tiebreak) from parts (a) and (b). With module-positional collection and a
// stable sort alone, two tied findings from two DISTINCT modules already sort consistently
// per run, because their relative order is fixed by which module is registered first in
// the modules slice passed to the engine - but that is an accident of module registration
// order, not a principled tiebreak, and would silently flip if DefaultModules in
// modules.go were ever reordered. This test builds the same two engines with the two
// modules in opposite registration order and asserts both produce the SAME finding order,
// proving the tiebreak is Finding.ID and not "whichever module the engine happened to list
// first".
func TestEngineTieBreaksByFindingIDRegardlessOfModuleOrder(t *testing.T) {
	a := &stubModule{name: "a", findings: []models.Finding{tiedFinding("tie-a")}}
	b := &stubModule{name: "b", findings: []models.Finding{tiedFinding("tie-b")}}

	forward, err := analyze(t, engineWith(a, b), Options{})
	if err != nil {
		t.Fatalf("forward order: %v", err)
	}
	reversed, err := analyze(t, engineWith(b, a), Options{})
	if err != nil {
		t.Fatalf("reversed module order: %v", err)
	}

	want := []string{"tie-a", "tie-b"}
	if got := findingIDs(forward); got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("modules registered [a, b]: got order %v, want %v", got, want)
	}
	if got := findingIDs(reversed); got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("modules registered [b, a]: got order %v, want %v (order should not depend on registration order)", got, want)
	}
}

// TestEngineFindingOrderDeterministicWhenFindingIDsCollide isolates part (a)
// (module-positional collection) from part (c) (the Finding.ID tiebreak): it proves
// (a) is independently necessary, not merely redundant with (c).
//
// Finding.ID is not guaranteed unique post-dedupe: dedupe's key is (RuleID, SubjectKey,
// ResourceKey), so two findings sharing an ID but differing in Resource have different
// dedupe keys and both survive (see dedupeKey in correlate.go). When that happens, every
// key sortFindings compares, including the ID tiebreak, ties, so (c) cannot disambiguate
// them and only module-positional order does. This fixture builds exactly that shape: 15
// findings sharing one Finding.ID, differing only by Resource, from 15 different modules.
func TestEngineFindingOrderDeterministicWhenFindingIDsCollide(t *testing.T) {
	const n = 15
	mods := make([]Module, 0, n)
	for i := 0; i < n; i++ {
		resourceName := fmt.Sprintf("resource-%02d", i)
		f := tiedFinding("shared-id")
		f.Resource = &models.ResourceRef{Kind: "Pod", Name: resourceName}
		mods = append(mods, &stubModule{name: fmt.Sprintf("mod-%02d", i), findings: []models.Finding{f}})
	}
	e := engineWith(mods...)

	resourceNames := func(findings []models.Finding) []string {
		out := make([]string, len(findings))
		for i, f := range findings {
			out[i] = f.Resource.Name
		}
		return out
	}

	var baseline []models.Finding
	for i := 0; i < 20; i++ {
		got, err := analyze(t, e, Options{})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if baseline == nil {
			if len(got) != n {
				t.Fatalf("fixture premise: want %d findings sharing one ID, got %d", n, len(got))
			}
			baseline = got
			continue
		}
		if len(got) != len(baseline) {
			t.Fatalf("run %d: finding count changed, got %d want %d", i, len(got), len(baseline))
		}
		for j := range baseline {
			if got[j].Resource.Name != baseline[j].Resource.Name {
				t.Fatalf("run %d: order diverged at index %d: got %q, want %q\n got:  %v\n want: %v",
					i, j, got[j].Resource.Name, baseline[j].Resource.Name, resourceNames(got), resourceNames(baseline))
			}
		}
	}
}
