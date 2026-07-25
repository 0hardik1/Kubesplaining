// Package report — builder for the "Privilege-Escalation Paths" HTML tab.
//
// The privesc graph the engine computes already emits one KUBE-PRIVESC-PATH-*
// finding per (source subject, sink) pair, each carrying the full ordered hop
// chain on Finding.EscalationPath. buildHeroChains surfaces the worst 3 of these
// above the fold and the interactive Attack Graph draws a capped capability
// slate; this tab is the exhaustive, readable complement: every path, grouped by
// the sink it reaches, sorted worst-first. The sink-priority and label helpers
// (heroSinkSlug / heroSinkLabel / heroSinkPriority / heroChainSummary) are shared
// with the hero panel so both views speak about sinks identically.
package report

import (
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildPrivescPaths assembles the Privilege-Escalation Paths tab from the
// KUBE-PRIVESC-PATH-* findings. Paths are bucketed by the sink they reach
// (cluster_admin, node_escape, ...); groups are ordered by sink danger then
// bucket size, and the cards within each group by severity then score then
// fewest hops, so the most dangerous, most direct chain to each sink surfaces
// first. Returns a zero-value section (empty Groups) when no privesc paths
// exist; the template gates the tab on len(.PrivescPaths.Groups) > 0.
func buildPrivescPaths(findings []models.Finding) PrivescPathsSection {
	var paths []models.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-") {
			paths = append(paths, f)
		}
	}
	if len(paths) == 0 {
		return PrivescPathsSection{}
	}

	// Bucket by sink, remembering first-seen order only as a tiebreaker stand-in;
	// the final group order is set by the explicit sort below.
	bySink := map[string][]models.Finding{}
	sinkOrder := make([]string, 0)
	for _, f := range paths {
		sink := heroSinkSlug(f)
		if _, ok := bySink[sink]; !ok {
			sinkOrder = append(sinkOrder, sink)
		}
		bySink[sink] = append(bySink[sink], f)
	}

	groups := make([]PrivescSinkGroup, 0, len(bySink))
	for _, sink := range sinkOrder {
		group := bySink[sink]
		sort.SliceStable(group, func(i, j int) bool {
			if ri, rj := group[i].Severity.Rank(), group[j].Severity.Rank(); ri != rj {
				return ri > rj
			}
			if group[i].Score != group[j].Score {
				return group[i].Score > group[j].Score
			}
			if hi, hj := len(group[i].EscalationPath), len(group[j].EscalationPath); hi != hj {
				return hi < hj
			}
			return group[i].ID < group[j].ID
		})

		cards := make([]PrivescPathCard, 0, len(group))
		for _, f := range group {
			cards = append(cards, PrivescPathCard{
				Source:      subjectDisplay(f.Subject),
				SinkLabel:   heroSinkLabel(sink),
				Severity:    f.Severity,
				SevClass:    severityClass(f.Severity),
				Score:       f.Score,
				HopCount:    len(f.EscalationPath),
				Summary:     heroChainSummary(f, sink),
				Hops:        f.EscalationPath,
				AltHops:     f.AlternateEscalationPath,
				AltHopCount: len(f.AlternateEscalationPath),
				RuleID:      f.RuleID,
				Anchor:      "finding-" + f.RuleID,
			})
		}

		// Cards are sorted worst-first, so the first card's class is the group's
		// worst severity — drives the group header stripe without a second pass.
		sevClass := "info"
		if len(cards) > 0 {
			sevClass = cards[0].SevClass
		}
		groups = append(groups, PrivescSinkGroup{
			SinkSlug:  sink,
			SinkLabel: heroSinkLabel(sink),
			SevClass:  sevClass,
			Count:     len(group),
			Summary:   BuildSummary(group),
			Cards:     cards,
		})
	}

	sort.SliceStable(groups, func(i, j int) bool {
		if pi, pj := heroSinkPriority(groups[i].SinkSlug), heroSinkPriority(groups[j].SinkSlug); pi != pj {
			return pi < pj
		}
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].SinkLabel < groups[j].SinkLabel
	})

	return PrivescPathsSection{
		Total:   len(paths),
		Summary: BuildSummary(paths),
		Groups:  groups,
	}
}
