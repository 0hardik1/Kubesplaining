// Package analyzer — module factory registry.
//
// DefaultModules is the canonical, ordered list of constructors for every
// built-in analyzer module the engine knows about. The engine ranges over this
// slice (rather than hard-coding the module slice in NewWithConfig) so:
//
//   - new modules land by appending one factory entry here, not by editing the
//     engine's construction site.
//   - the slice index defines the deterministic registration order, so we don't
//     depend on Go's init() ordering for golden-test stability.
//   - parallel Wave 1 worktrees can add a stub module without conflicting on
//     engine.go (the file each new analyzer owns is its own package, plus a
//     one-line append to this slice).
//
// Each factory receives the engine Config so per-module tuning (e.g. the
// privesc MaxDepth knob) stays inside the factory closure.
package analyzer

import (
	"github.com/0hardik1/kubesplaining/internal/analyzer/admission"
	celmod "github.com/0hardik1/kubesplaining/internal/analyzer/cel"
	"github.com/0hardik1/kubesplaining/internal/analyzer/certificates"
	"github.com/0hardik1/kubesplaining/internal/analyzer/cloud"
	"github.com/0hardik1/kubesplaining/internal/analyzer/containersec"
	"github.com/0hardik1/kubesplaining/internal/analyzer/leastprivilege"
	"github.com/0hardik1/kubesplaining/internal/analyzer/network"
	"github.com/0hardik1/kubesplaining/internal/analyzer/podsec"
	"github.com/0hardik1/kubesplaining/internal/analyzer/privesc"
	"github.com/0hardik1/kubesplaining/internal/analyzer/rbac"
	"github.com/0hardik1/kubesplaining/internal/analyzer/secrets"
	"github.com/0hardik1/kubesplaining/internal/analyzer/serviceaccount"
)

// DefaultModules lists every built-in module factory in the order the engine
// registers them. Adding a new analyzer requires (a) creating the package, (b)
// appending its factory here, (c) registering preset / glossary / e2e wiring
// in the relevant extension points (internal/exclusions/config.go,
// internal/report/glossary.go, testdata/e2e/expectations/<name>.expect).
//
// The leastprivilege module is constructed with nil UsageIndex here; the engine
// rebinds it per-call from Options.UsageIndex in selectModules so the same
// engine instance can serve runs with and without audit data. See engine.go.
var DefaultModules = []func(cfg Config) Module{
	func(_ Config) Module { return rbac.New() },
	func(_ Config) Module { return podsec.New() },
	func(_ Config) Module { return network.New() },
	func(_ Config) Module { return admission.New() },
	func(_ Config) Module { return secrets.New() },
	func(_ Config) Module { return serviceaccount.New() },
	func(cfg Config) Module {
		m := privesc.New()
		if cfg.MaxPrivescDepth > 0 {
			m.MaxDepth = cfg.MaxPrivescDepth
		}
		return m
	},
	func(_ Config) Module { return leastprivilege.New(nil) },
	func(_ Config) Module { return containersec.New() },
	// certificates reads CertificateSigningRequest objects — the evidence that the
	// certificates API was used, complementing the rbac module's KUBE-PRIVESC-011 /
	// -024 rules, which flag the grants that make it usable.
	func(_ Config) Module { return certificates.New() },
	// custom-rules is the CEL-based user rule loader (slot #20). It's a no-op
	// when CustomRulesDir is empty, matching the "registered but silent"
	// pattern the containersec stub above uses.
	func(cfg Config) Module { return celmod.New(cfg.CustomRulesDir) },
	// cloud dispatches per-provider detectors (EKS today; GKE/AKS reserved).
	// Silent when CloudProvider is empty or "none", so the module ships clean
	// for self-managed clusters.
	func(_ Config) Module { return cloud.New() },
}
