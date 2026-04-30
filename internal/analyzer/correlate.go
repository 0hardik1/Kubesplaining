package analyzer

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// correlate applies chain-modifier bumps to non-privesc findings whose Subject appears as a source in a privilege-escalation path.
// It picks the highest-severity sink reachable from the subject and adds scoring.ChainModifier(sinkSev) to the finding's Score,
// clamped to [0, 10]. A "chain:amplified" tag is added so report consumers can explain the bump.
func correlate(findings []models.Finding) []models.Finding {
	best := map[string]models.Severity{} // subject key → highest-severity sink reachable
	for _, finding := range findings {
		if len(finding.EscalationPath) == 0 || finding.Subject == nil {
			continue
		}
		key := finding.Subject.Key()
		if finding.Severity.Rank() > best[key].Rank() {
			best[key] = finding.Severity
		}
	}
	if len(best) == 0 {
		return findings
	}

	for i := range findings {
		if len(findings[i].EscalationPath) > 0 {
			continue // privesc findings already reflect chain length in their own scoring
		}
		if findings[i].Subject == nil {
			continue
		}
		bump := scoring.ChainModifier(best[findings[i].Subject.Key()])
		if bump == 0 {
			continue
		}
		findings[i].Score = scoring.Clamp(findings[i].Score + bump)
		findings[i].Tags = append(findings[i].Tags, "chain:amplified")
	}
	return findings
}

// dedupe collapses findings that describe the same (RuleID, Subject, Resource) combination across modules,
// keeping the one with the highest Score and merging tags. Within-module ID collisions are already handled by analyzers.
func dedupe(findings []models.Finding) []models.Finding {
	type keyed struct {
		idx int
	}
	seen := map[string]keyed{}
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		key := dedupeKey(finding)
		if key == "" {
			out = append(out, finding)
			continue
		}
		if prev, ok := seen[key]; ok {
			if finding.Score > out[prev.idx].Score {
				out[prev.idx].Score = finding.Score
				out[prev.idx].Severity = finding.Severity
			}
			out[prev.idx].Tags = mergeTags(out[prev.idx].Tags, finding.Tags)
			continue
		}
		seen[key] = keyed{idx: len(out)}
		out = append(out, finding)
	}
	return out
}

// dedupeKey returns the cross-module dedup key, or empty when the finding lacks enough context to merge safely.
func dedupeKey(f models.Finding) string {
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
