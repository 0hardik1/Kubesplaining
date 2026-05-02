package analyzer

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer/admission/mitigation"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// AdmissionMode controls how the engine reacts when a finding's underlying workload
// would be rejected by Pod Security Admission in its namespace. The default is suppress,
// which drops the finding from the output and counts it on the AdmissionSummary so the
// report header can surface "N findings suppressed by admission controls."
type AdmissionMode string

const (
	// AdmissionModeOff disables admission-aware reweighting; findings are emitted
	// exactly as the analyzer modules produced them.
	AdmissionModeOff AdmissionMode = "off"
	// AdmissionModeAttenuate downweights findings (Score *= scoring.AdmissionMitigationFactor,
	// Severity drops one bucket via scoring.SeverityForScore) and tags them with
	// admission:mitigated-psa-<level>. Use when every residual risk must remain visible.
	AdmissionModeAttenuate AdmissionMode = "attenuate"
	// AdmissionModeSuppress drops findings that admission would block from the output.
	// The default. Counts are still surfaced via AdmissionSummary so the noise
	// reduction is auditable.
	AdmissionModeSuppress AdmissionMode = "suppress"
)

// ParseAdmissionMode normalizes user input. Empty input maps to the default (suppress).
func ParseAdmissionMode(value string) (AdmissionMode, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(AdmissionModeSuppress):
		return AdmissionModeSuppress, true
	case string(AdmissionModeAttenuate):
		return AdmissionModeAttenuate, true
	case string(AdmissionModeOff):
		return AdmissionModeOff, true
	default:
		return "", false
	}
}

// AnalyzeResult is the engine output. Findings is the post-correlate, post-dedupe,
// post-threshold-filter, sorted slice the report layer renders. Admission carries
// the metadata produced by applyAdmissionMitigations so the report can surface
// "X findings suppressed by admission controls."
type AnalyzeResult struct {
	Findings  []models.Finding
	Admission models.AdmissionSummary
}

// applyAdmissionMitigations reweights or filters pod-security findings based on the
// PSA labels of each finding's namespace. Inserted before correlate() so the score
// adjustments feed into chain amplification cleanly. Mode == off short-circuits.
//
// Audit/warn-only labels never trigger suppression or attenuation regardless of
// mode — the controls log but do not block, so the residual risk is real. They
// only contribute admission:audit-psa-<level> / admission:warn-psa-<level> tags.
func applyAdmissionMitigations(findings []models.Finding, snapshot models.Snapshot, mode AdmissionMode) ([]models.Finding, models.AdmissionSummary) {
	summary := models.AdmissionSummary{Mode: string(mode)}
	if mode == AdmissionModeOff || len(findings) == 0 {
		return findings, summary
	}

	psaByNamespace := buildPSAIndex(snapshot)
	if len(psaByNamespace) == 0 {
		return findings, summary
	}

	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		if !isPodSecurityFinding(finding) {
			out = append(out, finding)
			continue
		}
		check := checkTagFromFinding(finding)
		if check == "" {
			out = append(out, finding)
			continue
		}
		state, ok := psaByNamespace[finding.Namespace]
		if !ok {
			out = append(out, finding)
			continue
		}

		// Audit/warn first — these tag the finding but never reweight, so we always
		// emit them regardless of mode.
		if state.Audit != "" && mitigation.WouldPSABlock(check, state.Audit) {
			finding.Tags = appendUnique(finding.Tags, "admission:audit-psa-"+state.Audit)
			summary.AuditOnly++
		}
		if state.Warn != "" && mitigation.WouldPSABlock(check, state.Warn) {
			finding.Tags = appendUnique(finding.Tags, "admission:warn-psa-"+state.Warn)
			summary.WarnOnly++
		}

		// Enforce drives suppression / attenuation.
		if state.Enforce == "" || !mitigation.WouldPSABlock(check, state.Enforce) {
			out = append(out, finding)
			continue
		}

		switch mode {
		case AdmissionModeSuppress:
			summary.Suppressed++
			if summary.SuppressedByNamespace == nil {
				summary.SuppressedByNamespace = map[string]map[string]int{}
			}
			byRule, ok := summary.SuppressedByNamespace[finding.Namespace]
			if !ok {
				byRule = map[string]int{}
				summary.SuppressedByNamespace[finding.Namespace] = byRule
			}
			byRule[finding.RuleID]++
			// Drop the finding by not appending it to out.
		case AdmissionModeAttenuate:
			finding.Severity = finding.Severity.Down()
			finding.Score = scoring.MinScoreForSeverity(finding.Severity)
			finding.Tags = appendUnique(finding.Tags, "admission:mitigated-psa-"+state.Enforce)
			summary.Attenuated++
			out = append(out, finding)
		default:
			out = append(out, finding)
		}
	}
	return out, summary
}

// buildPSAIndex collects PSA labels from every namespace into a map keyed by name.
// Namespaces without any of the three PSA labels are skipped to keep the lookup small.
func buildPSAIndex(snapshot models.Snapshot) map[string]mitigation.PSAState {
	index := make(map[string]mitigation.PSAState, len(snapshot.Resources.Namespaces))
	for _, ns := range snapshot.Resources.Namespaces {
		state := mitigation.PSAStateForLabels(ns.Labels)
		if state == (mitigation.PSAState{}) {
			continue
		}
		index[ns.Name] = state
	}
	return index
}

// isPodSecurityFinding returns true when the finding carries the module:pod_security tag.
func isPodSecurityFinding(f models.Finding) bool {
	for _, tag := range f.Tags {
		if tag == "module:pod_security" {
			return true
		}
	}
	return false
}

// checkTagFromFinding extracts the value of the first "check:<name>" tag, or "" if absent.
func checkTagFromFinding(f models.Finding) string {
	for _, tag := range f.Tags {
		if name, ok := strings.CutPrefix(tag, "check:"); ok {
			return name
		}
	}
	return ""
}

// appendUnique appends value to tags only if it isn't already present, preserving order.
func appendUnique(tags []string, value string) []string {
	for _, existing := range tags {
		if existing == value {
			return tags
		}
	}
	return append(tags, value)
}
