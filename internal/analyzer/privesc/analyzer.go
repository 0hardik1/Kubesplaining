// Package privesc builds a privilege-escalation graph from the snapshot and
// searches for paths that reach sensitive sinks like cluster-admin, kube-system
// secrets, or node escape, turning each viable path into a Finding.
package privesc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hardik/kubesplaining/internal/models"
)

// DefaultMaxDepth is the fallback BFS depth used when no explicit MaxDepth is configured.
const DefaultMaxDepth = 5

// Analyzer produces privilege-escalation path findings from a snapshot.
type Analyzer struct {
	MaxDepth int // BFS depth cap for path search; non-positive falls back to DefaultMaxDepth
}

// New returns a new privesc analyzer at the default depth.
func New() *Analyzer {
	return &Analyzer{MaxDepth: DefaultMaxDepth}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "privesc"
}

// Analyze builds the escalation graph, finds paths to any sensitive sink, and emits one Finding per unique source→target pair.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	depth := a.MaxDepth
	if depth <= 0 {
		depth = DefaultMaxDepth
	}

	graph := BuildGraph(snapshot)
	paths := FindPaths(graph, depth)

	findings := make([]models.Finding, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		finding := findingFromPath(path)
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		findings = append(findings, finding)
	}
	return findings, nil
}

// findingFromPath converts an EscalationPath into a Finding describing the chain, its target, and scoring.
func findingFromPath(path models.EscalationPath) models.Finding {
	target := path.Target
	severity, score, ruleID := targetScoring(target, len(path.Hops))
	category := models.CategoryPrivilegeEscalation
	if target == models.TargetKubeSystemSecrets {
		category = models.CategoryDataExfiltration
	}

	content := contentForTarget(path.Source, target, path.Hops)

	evidence, _ := json.Marshal(map[string]any{
		"target":        string(target),
		"hop_count":     len(path.Hops),
		"techniques":    uniqueTechniques(path.Hops),
		"first_action":  firstAction(path.Hops),
		"chain_summary": chainSummary(path.Hops),
	})

	id := fmt.Sprintf("%s:%s:%s", ruleID, path.Source.Key(), target)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}

	subject := path.Source
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidence,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		EscalationPath:   path.Hops,
		Tags:             []string{"module:privesc", "target:" + string(target)},
	}
}

// contentForTarget dispatches to the matching content builder based on the path's terminal sink.
func contentForTarget(source models.SubjectRef, target models.EscalationTarget, hops []models.EscalationHop) ruleContent {
	switch target {
	case models.TargetClusterAdmin:
		return contentClusterAdminPath(source, hops)
	case models.TargetNodeEscape:
		return contentNodeEscapePath(source, hops)
	case models.TargetKubeSystemSecrets:
		return contentKubeSystemSecretsPath(source, hops)
	case models.TargetSystemMasters:
		return contentSystemMastersPath(source, hops)
	default:
		return contentGenericPath(source, target, hops)
	}
}

// targetScoring returns the base severity, score, and rule ID for a target, attenuating by hop distance so shorter paths score higher.
func targetScoring(target models.EscalationTarget, hops int) (models.Severity, float64, string) {
	var base float64
	var severity models.Severity
	var ruleID string
	switch target {
	case models.TargetClusterAdmin:
		base, severity, ruleID = 9.8, models.SeverityCritical, "KUBE-PRIVESC-PATH-CLUSTER-ADMIN"
	case models.TargetNodeEscape:
		base, severity, ruleID = 9.4, models.SeverityCritical, "KUBE-PRIVESC-PATH-NODE-ESCAPE"
	case models.TargetKubeSystemSecrets:
		base, severity, ruleID = 8.6, models.SeverityHigh, "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS"
	case models.TargetSystemMasters:
		base, severity, ruleID = 9.6, models.SeverityCritical, "KUBE-PRIVESC-PATH-SYSTEM-MASTERS"
	default:
		base, severity, ruleID = 7.0, models.SeverityHigh, "KUBE-PRIVESC-PATH-GENERIC"
	}
	score := base
	if hops > 1 {
		score -= 0.5 * float64(hops-1)
	}
	if score < 1 {
		score = 1
	}
	if score > 10 {
		score = 10
	}
	if hops >= 3 {
		severity = downgrade(severity)
	}
	return severity, score, ruleID
}

// downgrade steps a severity down one bucket; used to soften long multi-hop chains.
func downgrade(s models.Severity) models.Severity {
	switch s {
	case models.SeverityCritical:
		return models.SeverityHigh
	case models.SeverityHigh:
		return models.SeverityMedium
	default:
		return s
	}
}

// targetLabel returns a human-readable label for the escalation target.
func targetLabel(target models.EscalationTarget) string {
	switch target {
	case models.TargetClusterAdmin:
		return "cluster-admin equivalent"
	case models.TargetNodeEscape:
		return "node escape"
	case models.TargetKubeSystemSecrets:
		return "kube-system secrets"
	case models.TargetSystemMasters:
		return "system:masters"
	default:
		return string(target)
	}
}

// uniqueTechniques returns the deduplicated list of hop Actions along the path for evidence summaries.
func uniqueTechniques(hops []models.EscalationHop) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, hop := range hops {
		if hop.Action == "" {
			continue
		}
		if _, ok := seen[hop.Action]; ok {
			continue
		}
		seen[hop.Action] = struct{}{}
		out = append(out, hop.Action)
	}
	return out
}

// firstAction returns the Action of the first hop or empty when there are none.
func firstAction(hops []models.EscalationHop) string {
	if len(hops) == 0 {
		return ""
	}
	return hops[0].Action
}

// chainSummary returns a numbered list of "Action [Permission]" strings for evidence output.
func chainSummary(hops []models.EscalationHop) []string {
	summary := make([]string, 0, len(hops))
	for _, hop := range hops {
		summary = append(summary, fmt.Sprintf("%d. %s [%s]", hop.Step, hop.Action, hop.Permission))
	}
	return summary
}
