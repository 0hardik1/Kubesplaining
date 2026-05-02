package analyzer

import (
	"github.com/0hardik1/kubesplaining/internal/analyzer/admission/mitigation"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// ruleIDNoPolicyEngine is the cluster-wide posture finding emitted by the
// admission analyzer when no namespace carries a PSA enforce label and no
// policy-engine resources were observed. The engine stage strips this
// finding when --admission-mode=off, since users who opt out of admission
// reasoning don't want it surfaced.
const ruleIDNoPolicyEngine = "KUBE-ADMISSION-NO-POLICY-ENGINE-001"

// applyPolicyEnginePresenceTags is the second admission-aware engine stage,
// running after applyAdmissionMitigations and before correlate/dedupe. It:
//
//  1. Derives the PolicyEngines state from snapshot CRD fields and writes the
//     sorted engine list onto summary.PolicyEnginesDetected.
//  2. Strips the KUBE-ADMISSION-NO-POLICY-ENGINE-001 posture finding when
//     mode == off (the admission analyzer always emits it when conditions are
//     met; the engine decides whether the user wants to see it).
//  3. Tags every surviving pod-security finding with
//     admission:policy-engine-detected:<engine> — one tag per detected engine.
//     Score is unchanged: this is a presence signal, not a mitigation. We tag
//     only survivors of suppression because PSA-suppressed findings are already
//     gone from the slice (the previous stage dropped them) and re-walking the
//     original slice to tag invisible findings adds no value.
//  4. Bumps summary.PolicyEngineTagged once per tagged finding (not once per
//     engine), so a finding that gets both kyverno and vap tags counts as one.
func applyPolicyEnginePresenceTags(
	findings []models.Finding,
	snapshot models.Snapshot,
	summary models.AdmissionSummary,
	mode AdmissionMode,
) ([]models.Finding, models.AdmissionSummary) {
	engines := detectPolicyEngines(snapshot)
	summary.PolicyEnginesDetected = engines.Names()

	if mode == AdmissionModeOff {
		out := findings[:0]
		for _, f := range findings {
			if f.RuleID == ruleIDNoPolicyEngine {
				continue
			}
			out = append(out, f)
		}
		return out, summary
	}

	if !engines.Any() {
		return findings, summary
	}

	names := engines.Names()
	for i := range findings {
		if !isPodSecurityFinding(findings[i]) {
			continue
		}
		for _, name := range names {
			findings[i].Tags = appendUnique(findings[i].Tags, "admission:policy-engine-detected:"+name)
		}
		summary.PolicyEngineTagged++
	}
	return findings, summary
}

// detectPolicyEngines reads the four snapshot fields populated by the collector's
// Phase 2 list operations and reports which engines have at least one observed
// resource. Both Kyverno fields (ClusterPolicies and namespaced Policies) count
// as Kyverno presence; Gatekeeper presence is keyed off ConstraintTemplate
// (the user-facing Constraints are dynamically-typed CRDs deferred to Phase 3/4).
func detectPolicyEngines(snapshot models.Snapshot) mitigation.PolicyEngines {
	return mitigation.PolicyEngines{
		Kyverno: len(snapshot.Resources.KyvernoClusterPolicies) > 0 ||
			len(snapshot.Resources.KyvernoPolicies) > 0,
		Gatekeeper: len(snapshot.Resources.GatekeeperConstraintTemplates) > 0,
		VAP:        len(snapshot.Resources.ValidatingAdmissionPolicies) > 0,
	}
}
