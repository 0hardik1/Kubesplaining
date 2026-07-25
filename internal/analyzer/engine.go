// Package analyzer orchestrates the individual security analysis modules (rbac, podsec,
// network, admission, secrets, serviceaccount, privesc), runs them in parallel against a
// snapshot, filters by severity threshold, and returns a sorted finding list.
package analyzer

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/0hardik1/kubesplaining/internal/analyzer/leastprivilege"
	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	"github.com/0hardik1/kubesplaining/internal/usage"
)

// Module is the contract each analysis module implements.
type Module interface {
	Name() string
	Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}

// Options selects which modules run, sets a severity floor, tunes privesc path depth,
// chooses how the engine reacts to namespace-level admission controls, and threads the
// audit-log-derived usage index into the leastprivilege module.
type Options struct {
	OnlyModules     []string
	SkipModules     []string
	Threshold       models.Severity
	MaxPrivescDepth int
	// AdmissionMode controls the admission-aware reweight stage. Empty defaults to suppress.
	AdmissionMode AdmissionMode
	// UsageIndex carries the audit-log observations consumed by the leastprivilege
	// module. nil disables the module (it emits nothing); the CLI pre-flight in
	// scan.go errors out before we get here when --least-privilege-only is set
	// without --audit-log.
	UsageIndex *usage.UsageIndex
	// RemediationPatches opts into structured remediation hints (kubectl patch,
	// Kyverno / Gatekeeper policy, RBAC diff) on every finding. Default false:
	// analyzers always populate Finding.RemediationHint, but the engine strips
	// the field as a post-process step unless this flag is set. Callers that
	// regenerate reports from JSON (`internal/cli/report.go`) apply the same
	// strip themselves, so the flag's behavior is consistent end-to-end.
	RemediationPatches bool
}

// Engine holds the set of registered analysis modules to run.
type Engine struct {
	modules []Module
}

// New returns an Engine configured with default module settings.
func New() *Engine {
	return NewWithConfig(Config{})
}

// Config tunes engine construction parameters like the privesc graph search depth.
type Config struct {
	MaxPrivescDepth int
	// CustomRulesDir is the directory the CEL-based "custom-rules" module loads
	// *.cel.yaml files from. Empty means "skip loading"; the module remains
	// registered but evaluates to zero findings, keeping the JSON / HTML output
	// byte-identical to a build that never received the flag.
	CustomRulesDir string
}

// NewWithConfig constructs an Engine with the default module set, applying cfg to tunable
// modules. The leastprivilege module is registered with a nil UsageIndex here; Analyze
// rebinds it from opts.UsageIndex on each invocation so the same engine can serve runs
// with and without audit data.
//
// The module set comes from DefaultModules in modules.go — adding a new analyzer requires
// appending one factory entry there, not editing this constructor.
func NewWithConfig(cfg Config) *Engine {
	modules := make([]Module, 0, len(DefaultModules))
	for _, factory := range DefaultModules {
		modules = append(modules, factory(cfg))
	}
	return &Engine{modules: modules}
}

// Analyze runs the selected modules in parallel, applies admission-aware reweighting,
// correlates and dedupes the results, filters at or above the severity threshold, and
// returns them sorted by severity then score along with an AdmissionSummary describing
// what the reweight stage did.
//
// The pipeline is broken into four named stages below so a first-time reader can follow
// the data flow: snapshot → selected modules → raw findings → reweighted/correlated/
// deduped findings → sorted slice ready for the report writer.
func (e *Engine) Analyze(ctx context.Context, snapshot models.Snapshot, opts Options) (AnalyzeResult, error) {
	mode := opts.AdmissionMode
	if mode == "" {
		mode = AdmissionModeSuppress
	}

	selected, err := e.selectModules(opts)
	if err != nil {
		return AnalyzeResult{}, err
	}

	findings, firstErr := runModulesInParallel(ctx, snapshot, selected)

	findings, admissionSummary := postProcess(findings, snapshot, mode)

	if !opts.RemediationPatches {
		findings = stripRemediationHints(findings)
	}

	filtered := filterByThreshold(findings, opts.Threshold)
	sortFindings(filtered)

	return AnalyzeResult{Findings: filtered, Admission: admissionSummary}, firstErr
}

// selectModules applies the --only-modules / --skip-modules filters and rebinds the
// leastprivilege module with the per-call UsageIndex. The engine itself is stateless on
// options; rebinding here keeps the module's audit data scoped to one Analyze call.
func (e *Engine) selectModules(opts Options) ([]Module, error) {
	selected := make([]Module, 0, len(e.modules))
	for _, module := range e.modules {
		if len(opts.OnlyModules) > 0 && !slices.Contains(opts.OnlyModules, module.Name()) {
			continue
		}
		if slices.Contains(opts.SkipModules, module.Name()) {
			continue
		}
		if module.Name() == "leastprivilege" {
			module = leastprivilege.New(opts.UsageIndex)
		}
		selected = append(selected, module)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no analysis modules selected")
	}
	return selected, nil
}

// runModulesInParallel fans out each module to its own goroutine, waits for all of them,
// and returns the merged findings slice concatenated in module order. If any module
// returns an error, only the first one BY MODULE POSITION is reported (not the first to
// arrive): errors are collected into the same positional slots as findings and picked up
// in the same final pass, so a slow module's error can no longer race a fast module's
// error for firstErr. The other modules' findings still come back so a single misbehaving
// analyzer can't blank the whole report.
//
// Results are written into per-index slots (results[i], errs[i]) rather than appended
// under a mutex as goroutines complete, because goroutine completion order is not fixed
// by anything in this function and varies run to run. Concatenating by index after
// wg.Wait() makes the combined findings slice's order depend only on modules' fixed
// position in the slice (itself fixed by DefaultModules in modules.go), not on which
// module happened to finish first. sortFindings's stability then preserves this order
// for any findings that tie on its comparator keys.
func runModulesInParallel(ctx context.Context, snapshot models.Snapshot, modules []Module) ([]models.Finding, error) {
	results := make([][]models.Finding, len(modules))
	errs := make([]error, len(modules))

	var wg sync.WaitGroup
	for i, module := range modules {
		i, module := i, module
		wg.Add(1)
		go func() {
			defer wg.Done()
			moduleFindings, err := module.Analyze(ctx, snapshot)
			results[i] = moduleFindings
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", module.Name(), err)
			}
		}()
	}
	wg.Wait()

	var findings []models.Finding
	var firstErr error
	for i := range modules {
		findings = append(findings, results[i]...)
		if firstErr == nil && errs[i] != nil {
			firstErr = errs[i]
		}
	}
	return findings, firstErr
}

// postProcess runs the cross-module passes that need every module's output in one place:
// admission-aware reweighting, policy-engine presence tagging, chain-amplification
// correlation, and cross-module deduplication. Returns the surviving findings and the
// AdmissionSummary describing what the reweight stage did.
func postProcess(findings []models.Finding, snapshot models.Snapshot, mode AdmissionMode) ([]models.Finding, models.AdmissionSummary) {
	findings, admissionSummary := applyAdmissionMitigations(findings, snapshot, mode)
	findings, admissionSummary = applyPolicyEnginePresenceTags(findings, snapshot, admissionSummary, mode)
	findings = correlate(findings)
	findings = dedupe(findings)
	findings = compliance.Apply(findings)
	return findings, admissionSummary
}

// filterByThreshold drops findings whose severity falls below the operator-supplied
// threshold. We reuse the input slice's backing array (findings[:0]) because the input
// is no longer needed after this point - this avoids an allocation but is only safe
// because no later code reads the pre-filter slice.
func filterByThreshold(findings []models.Finding, threshold models.Severity) []models.Finding {
	filtered := findings[:0]
	for _, finding := range findings {
		if scoring.AboveThreshold(finding, threshold) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// stripRemediationHints zeroes the RemediationHint pointer on every finding.
// Analyzers always populate the hint, so the engine drops it here when the
// operator did not pass --remediation-patches. This keeps the per-analyzer
// remediation generators wired and tested even when the CLI surface defaults
// to off, and avoids gating every per-module call site behind a flag.
func stripRemediationHints(findings []models.Finding) []models.Finding {
	for i := range findings {
		findings[i].RemediationHint = nil
	}
	return findings
}

// sortFindings sorts in place by severity (descending), then score (descending), then
// rule ID (ascending), then title (ascending), with Finding.ID (ascending) as a final
// total tiebreak. Stable ordering matters: tests, golden files, and SARIF consumers all
// depend on the same input yielding the same output. That guarantee now rests on three
// things together: runModulesInParallel collects results by module position rather than
// goroutine completion order, sort.SliceStable (not sort.Slice) preserves that order for
// anything the four named keys don't distinguish, and the Finding.ID tiebreak below stops
// remaining ties from resolving by module registration order, an accident of how
// NewWithConfig happens to list modules in modules.go rather than anything principled.
// Finding.ID is not guaranteed unique post-dedupe (two findings can share an ID while
// differing in Resource, and dedupe's key covers both), so the tiebreak alone is not
// sufficient; positional collection is what covers that residue.
func sortFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Title != findings[j].Title {
			return findings[i].Title < findings[j].Title
		}
		return findings[i].ID < findings[j].ID
	})
}
