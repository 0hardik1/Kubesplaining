package mitigation

import "sort"

// Engine names for the admission:policy-engine-detected:* tag suffix and for
// AdmissionSummary.PolicyEnginesDetected entries. Keep these stable — they
// surface in JSON, CSV, and SARIF outputs.
const (
	EngineKyverno    = "kyverno"
	EngineGatekeeper = "gatekeeper"
	EngineVAP        = "vap"
)

// PolicyEngines records which admission policy engines have observed resources
// in a snapshot. Phase 2 only checks presence; Phase 3 (CEL evaluation of VAP)
// and Phase 4 (operator attestation for Kyverno/Gatekeeper) consume the same
// snapshot fields more deeply.
type PolicyEngines struct {
	Kyverno    bool // any Kyverno (Cluster)Policy observed
	Gatekeeper bool // any Gatekeeper ConstraintTemplate observed
	VAP        bool // any ValidatingAdmissionPolicy observed
}

// Names returns the detected engines as a sorted, deduplicated slice
// (e.g. ["gatekeeper", "kyverno", "vap"]). Suitable for tag emission and
// AdmissionSummary.PolicyEnginesDetected.
func (p PolicyEngines) Names() []string {
	names := make([]string, 0, 3)
	if p.Gatekeeper {
		names = append(names, EngineGatekeeper)
	}
	if p.Kyverno {
		names = append(names, EngineKyverno)
	}
	if p.VAP {
		names = append(names, EngineVAP)
	}
	sort.Strings(names)
	return names
}

// Any reports whether at least one engine was detected.
func (p PolicyEngines) Any() bool {
	return p.Kyverno || p.Gatekeeper || p.VAP
}
