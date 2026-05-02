// Package report — short labels and severity classes for attack-graph nodes. Pure
// pure-data mapping helpers; no layout, no findings introspection beyond field reads.
package report

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// entryIdentity returns a stable key + display strings for the entity an attacker would target to exercise this finding.
// Preference: Subject (RBAC identity) > Resource (affected object).
func entryIdentity(f models.Finding) (key, title, subtitle string) {
	if f.Subject != nil {
		k := f.Subject.Key()
		return k, shortKindLabel(f.Subject.Kind, f.Subject.Name), k
	}
	if f.Resource != nil {
		k := f.Resource.Key()
		return k, shortKindLabel(f.Resource.Kind, f.Resource.Name), k
	}
	return "", "", ""
}

// shortKindLabel returns a human-friendly short title for an entity reference.
func shortKindLabel(kind, name string) string {
	if kind == "" {
		return name
	}
	return kind + "  " + name
}

// capabilityAriaLabel composes the per-node accessible name for a capability
// (Abused capability lane) <g> element. Generic "Abused capability" labels are
// indistinguishable across nodes — embedding the rule ID, plain title, and
// severity gives screen-reader users enough context to navigate the graph.
func capabilityAriaLabel(f models.Finding) string {
	title := stripMarkdown(f.Title)
	if title == "" {
		return "Abused capability: " + f.RuleID + " (severity " + string(f.Severity) + ")"
	}
	return "Abused capability: " + f.RuleID + " — " + title + " (severity " + string(f.Severity) + ")"
}

// impactLabel is the concise impact-lane heading for a risk category.
func impactLabel(c models.RiskCategory) string {
	switch c {
	case models.CategoryPrivilegeEscalation:
		return "PRIVILEGE ESCALATION"
	case models.CategoryLateralMovement:
		return "LATERAL REACH"
	case models.CategoryDataExfiltration:
		return "DATA EXFILTRATION"
	case models.CategoryInfrastructureModification:
		return "CONTROL BYPASS"
	case models.CategoryDefenseEvasion:
		return "DETECTION EVASION"
	default:
		return strings.ToUpper(categoryLabel(c))
	}
}

// impactSubtitle is the short descriptive line under an impact heading.
func impactSubtitle(c models.RiskCategory) string {
	switch c {
	case models.CategoryPrivilegeEscalation:
		return "Impersonation, container escape, SA takeover"
	case models.CategoryLateralMovement:
		return "Cross-namespace, node-local, egress"
	case models.CategoryDataExfiltration:
		return "Tokens, secrets, application data"
	case models.CategoryInfrastructureModification:
		return "Admission, webhooks, API policies"
	case models.CategoryDefenseEvasion:
		return "Provenance, logging, rollback"
	default:
		return ""
	}
}

// severityClass maps a severity to the short CSS class key used by the template.
func severityClass(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "crit"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "med"
	case models.SeverityLow:
		return "low"
	default:
		return "info"
	}
}
