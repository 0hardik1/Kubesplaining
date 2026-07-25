package analyzer

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// leastPrivilegeAdvisoryPrefixes lists rule-ID prefixes that emit *recommendations*, not
// exploitable findings. The correlate pass must not bump these via chain amplification -
// boosting a "consider narrowing this Role" recommendation because the same SA appears
// in a privesc path would distort the priority ordering operators rely on.
var leastPrivilegeAdvisoryPrefixes = []string{
	"KUBE-RBAC-UNUSED-",
	"KUBE-RBAC-WILDCARD-USED-PARTIAL-",
	// Wave 0 stubs: containersec rules that surface workload-hardening
	// recommendations (missing resource limits, missing probes) rather than
	// active exploit primitives. Wave 1 slot #9 fills the rules in; pre-listing
	// the prefixes here keeps chain amplification from inflating their scores
	// the moment they start emitting.
	"KUBE-CONTAINER-LIMITS-",
	"KUBE-CONTAINER-PROBE-",
}

// isLeastPrivilegeAdvisory reports whether ruleID names an advisory (recommendation)
// finding that should bypass the chain-amplification bump.
func isLeastPrivilegeAdvisory(ruleID string) bool {
	for _, p := range leastPrivilegeAdvisoryPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

// pathEdge is one escalation-graph edge a subject actively drives: the technique
// that enabled a hop, plus the severity of the sink the whole chain reaches.
type pathEdge struct {
	technique string
	sink      models.Severity
}

// correlate applies chain-modifier bumps, but only to the findings that are the
// actual edges of an escalation chain - not to every finding that happens to share
// a subject with one. For each hop of every privesc path finding it records
// (hop.FromSubject → technique → chain sink severity); a non-privesc finding is then
// amplified only when its own (Subject, RuleID) matches one of those edges. The bump
// is scoring.ChainModifier of the highest sink severity among the matching edges,
// clamped to [0, 10], and a "chain:amplified" tag is added so report consumers can
// explain it. This keeps a chain's weight on the specific weakness it exploits (the
// impersonate grant, the privileged pod) instead of inflating an unrelated
// misconfiguration on the same ServiceAccount.
func correlate(findings []models.Finding) []models.Finding {
	pathEdges := map[string][]pathEdge{} // subject key → edges that subject drives
	for _, finding := range findings {
		if len(finding.EscalationPath) == 0 {
			continue
		}
		for _, hop := range finding.EscalationPath {
			if hop.FromSubject.Name == "" || hop.Technique == "" {
				// A hop with no source subject or no technique carries no causal
				// signal we can attribute a specific finding to.
				continue
			}
			from := hop.FromSubject.Key()
			pathEdges[from] = append(pathEdges[from], pathEdge{technique: hop.Technique, sink: finding.Severity})
		}
	}
	if len(pathEdges) == 0 {
		return findings
	}

	for i := range findings {
		if len(findings[i].EscalationPath) > 0 {
			continue // privesc findings already reflect chain length in their own scoring
		}
		if findings[i].Subject == nil {
			// Resource-anchored findings (e.g. the podsec pod-escape rules, which set
			// Resource but no Subject) have no subject key to match against a path
			// edge, so they are never amplified. This matches the pre-causal behavior.
			continue
		}
		if isLeastPrivilegeAdvisory(findings[i].RuleID) {
			continue // advisory recommendations skip the amplification bump
		}
		sink, ok := bestSinkForEdge(pathEdges[findings[i].Subject.Key()], findings[i].RuleID)
		if !ok {
			continue // this finding is not an edge of any chain from its subject
		}
		bump := scoring.ChainModifier(sink)
		if bump == 0 {
			continue
		}
		findings[i].Score = scoring.Clamp(findings[i].Score + bump)
		findings[i].Tags = append(findings[i].Tags, "chain:amplified")
	}
	return findings
}

// bestSinkForEdge returns the highest sink severity among the subject's escalation
// edges whose technique matches ruleID, and whether any matched.
func bestSinkForEdge(edges []pathEdge, ruleID string) (models.Severity, bool) {
	var best models.Severity
	found := false
	for _, e := range edges {
		if !techniqueMatchesRule(e.technique, ruleID) {
			continue
		}
		if !found || e.sink.Rank() > best.Rank() {
			best, found = e.sink, true
		}
	}
	return best, found
}

// techniqueMatchesRule reports whether an edge technique identifies the same rule as
// ruleID: an exact match, or a family prefix. The family-prefix form is what lets the
// cloud edge technique "KUBE-CLOUD-IRSA" amplify the concrete, Subject-bearing eks
// findings "KUBE-CLOUD-IRSA-ADMIN-ROLE-001" / "-MISSING-001" (and "KUBE-CLOUD-AWSAUTH"
// its -SYSTEM-MASTERS-001 / -OVERBROAD-001 findings).
//
// The pod-escape edge is also tagged with a family prefix ("KUBE-ESCAPE") for hop
// display, but that one never reaches this matcher: the KUBE-ESCAPE-* findings podsec
// emits are resource-anchored (Subject == nil), so correlate skips them before the
// technique match runs. See TestCorrelateSkipsResourceAnchoredFindings - amplifying
// those would require podsec to carry a Subject, which is out of scope here.
func techniqueMatchesRule(technique, ruleID string) bool {
	return technique == ruleID || strings.HasPrefix(ruleID, technique+"-")
}

// dedupe collapses findings that describe the same (RuleID, Subject, Resource) combination across modules,
// keeping the one with the highest Score and merging tags. Within-module ID collisions are already handled by analyzers.
func dedupe(findings []models.Finding) []models.Finding {
	// indexByKey maps each dedupe key to the index in `out` where its winning finding lives.
	// We keep an index (rather than a *models.Finding) because the slice may grow and
	// reallocate as we append, invalidating any stored pointer.
	indexByKey := map[string]int{}
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		key := dedupeKey(finding)
		if key == "" {
			out = append(out, finding)
			continue
		}
		if prevIdx, ok := indexByKey[key]; ok {
			if finding.Score > out[prevIdx].Score {
				out[prevIdx].Score = finding.Score
				out[prevIdx].Severity = finding.Severity
			}
			out[prevIdx].Tags = mergeTags(out[prevIdx].Tags, finding.Tags)
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, finding)
	}
	// Invariant: "privesc:survives-first-cut" asserts AlternateEscalationPath is
	// non-empty, so a finding that carries the tag without the field is a
	// contradiction - drop the tag rather than let it outlive the field it
	// describes. This used to live inside the collision branch above, repairing
	// tag bleed when two chains to different sinks were wrongly merged under one
	// dedupe key. dedupeKey now keys a chain-bearing finding on its own ID, which
	// already encodes the chain's endpoints, so two privesc findings can no
	// longer collide with each other and that contradiction can no longer arise
	// from a merge. The check still earns its keep as a backstop over every
	// finding dedupe emits, not only merge survivors, so a future finding built
	// with the tag but no alternate route is still caught here before it reaches
	// the report.
	for i := range out {
		if len(out[i].AlternateEscalationPath) == 0 && slices.Contains(out[i].Tags, "privesc:survives-first-cut") {
			out[i].Tags = dropTag(out[i].Tags, "privesc:survives-first-cut")
		}
	}
	return out
}

// dedupeKey returns the cross-module dedup key, or empty when the finding lacks enough context to merge safely.
//
// A finding carrying an escalation chain is identified by that chain's endpoints, so two
// chains from one subject to different sinks are different findings, not duplicates of
// each other - even when they share RuleID, Subject, and a nil Resource, which is exactly
// the shape a confused-deputy finding has for every sink the same controller can reach.
// Finding.ID for a privesc path is "RuleID:subjectKey:target" (plus namespace for
// namespace-scoped sinks; see findingFromPath), so it already distinguishes sinks by
// construction and is used directly instead of the coarser composite key below.
func dedupeKey(f models.Finding) string {
	if len(f.EscalationPath) > 0 && f.ID != "" {
		return f.ID
	}
	if f.Subject == nil && f.Resource == nil {
		return ""
	}
	var subjKey, resKey string
	if f.Subject != nil {
		subjKey = f.Subject.Key()
	}
	if f.Resource != nil {
		resKey = f.Resource.Key()
	}
	return fmt.Sprintf("%s|%s|%s", f.RuleID, subjKey, resKey)
}

// mergeTags unions two tag slices in order, dropping duplicates.
func mergeTags(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, tag := range a {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	for _, tag := range b {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

// dropTag returns tags with every occurrence of victim removed.
func dropTag(tags []string, victim string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag == victim {
			continue
		}
		out = append(out, tag)
	}
	return out
}
