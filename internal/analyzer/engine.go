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

	"github.com/0hardik1/kubesplaining/internal/analyzer/admission"
	"github.com/0hardik1/kubesplaining/internal/analyzer/network"
	"github.com/0hardik1/kubesplaining/internal/analyzer/podsec"
	"github.com/0hardik1/kubesplaining/internal/analyzer/privesc"
	"github.com/0hardik1/kubesplaining/internal/analyzer/rbac"
	"github.com/0hardik1/kubesplaining/internal/analyzer/secrets"
	"github.com/0hardik1/kubesplaining/internal/analyzer/serviceaccount"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// Module is the contract each analysis module implements.
type Module interface {
	Name() string
	Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}

// Options selects which modules run, sets a severity floor, tunes privesc path depth,
// and chooses how the engine reacts to namespace-level admission controls.
type Options struct {
	OnlyModules     []string
	SkipModules     []string
	Threshold       models.Severity
	MaxPrivescDepth int
	// AdmissionMode controls the admission-aware reweight stage. Empty defaults to suppress.
	AdmissionMode AdmissionMode
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
}

// NewWithConfig constructs an Engine with the default module set, applying cfg to tunable modules.
func NewWithConfig(cfg Config) *Engine {
	privescMod := privesc.New()
	if cfg.MaxPrivescDepth > 0 {
		privescMod.MaxDepth = cfg.MaxPrivescDepth
	}
	return &Engine{
		modules: []Module{
			rbac.New(),
			podsec.New(),
			network.New(),
			admission.New(),
			secrets.New(),
			serviceaccount.New(),
			privescMod,
		},
	}
}

// Analyze runs the selected modules in parallel, applies admission-aware reweighting,
// correlates and dedupes the results, filters at or above the severity threshold, and
// returns them sorted by severity then score along with an AdmissionSummary describing
// what the reweight stage did.
func (e *Engine) Analyze(ctx context.Context, snapshot models.Snapshot, opts Options) (AnalyzeResult, error) {
	mode := opts.AdmissionMode
	if mode == "" {
		mode = AdmissionModeSuppress
	}

	selected := make([]Module, 0, len(e.modules))
	for _, module := range e.modules {
		if len(opts.OnlyModules) > 0 && !slices.Contains(opts.OnlyModules, module.Name()) {
			continue
		}
		if slices.Contains(opts.SkipModules, module.Name()) {
			continue
		}
		selected = append(selected, module)
	}

	if len(selected) == 0 {
		return AnalyzeResult{}, fmt.Errorf("no analysis modules selected")
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []models.Finding
		firstErr error
	)

	for _, module := range selected {
		module := module
		wg.Add(1)
		go func() {
			defer wg.Done()
			moduleFindings, err := module.Analyze(ctx, snapshot)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", module.Name(), err)
			}
			findings = append(findings, moduleFindings...)
		}()
	}

	wg.Wait()

	findings, admissionSummary := applyAdmissionMitigations(findings, snapshot, mode)
	findings = correlate(findings)
	findings = dedupe(findings)

	filtered := findings[:0]
	for _, finding := range findings {
		if scoring.AboveThreshold(finding, opts.Threshold) {
			filtered = append(filtered, finding)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Severity.Rank() != filtered[j].Severity.Rank() {
			return filtered[i].Severity.Rank() > filtered[j].Severity.Rank()
		}
		if filtered[i].Score != filtered[j].Score {
			return filtered[i].Score > filtered[j].Score
		}
		if filtered[i].RuleID != filtered[j].RuleID {
			return filtered[i].RuleID < filtered[j].RuleID
		}
		return filtered[i].Title < filtered[j].Title
	})

	return AnalyzeResult{Findings: filtered, Admission: admissionSummary}, firstErr
}
