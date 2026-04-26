// Package models defines the shared data types produced by the collector and consumed by the analyzers, exclusions,
// scoring, and report packages. Snapshot holds cluster state; Finding is the unit analyzers emit; EscalationHop and
// related types describe privilege-escalation chains.
package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is the common output of every analyzer module: a scored, categorized observation tied to a subject or resource.
type Finding struct {
	ID              string          `json:"id"`       // deterministic unique key ("RULE:ns:name")
	RuleID          string          `json:"rule_id"`  // rule identifier, stable across runs
	Severity        Severity        `json:"severity"` // bucketed severity used for filtering and display
	Score           float64         `json:"score"`    // numeric 0–10 score, already clamped
	Category        RiskCategory    `json:"category"` // risk category for grouping in the report
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Subject         *SubjectRef     `json:"subject,omitempty"`  // RBAC subject this finding is about, when applicable
	Resource        *ResourceRef    `json:"resource,omitempty"` // cluster resource this finding is about, when applicable
	Namespace       string          `json:"namespace,omitempty"`
	Evidence        json.RawMessage `json:"evidence,omitempty"` // analyzer-specific JSON payload describing what was found
	Remediation     string          `json:"remediation"`
	References      []string        `json:"references,omitempty"`
	EscalationPath  []EscalationHop `json:"escalation_path,omitempty"` // populated by the privesc module
	Excluded        bool            `json:"excluded"`                  // set post-analysis by the exclusions matcher
	ExclusionReason string          `json:"exclusion_reason,omitempty"`
	Tags            []string        `json:"tags,omitempty"` // free-form labels like "module:rbac", "check:wildcardVerbs"
}

// Severity is the bucketed severity level attached to every Finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ParseSeverity parses a case-insensitive severity string; an empty input is accepted as SeverityInfo.
func ParseSeverity(value string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return SeverityCritical, nil
	case "HIGH":
		return SeverityHigh, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "LOW":
		return SeverityLow, nil
	case "INFO", "":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("unsupported severity %q", value)
	}
}

// Rank returns an integer ordering suitable for sorting (higher = more severe); INFO is 1, CRITICAL is 5.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

// RiskCategory classifies what kind of security impact a Finding represents for use in summaries and dashboards.
type RiskCategory string

const (
	CategoryPrivilegeEscalation        RiskCategory = "privilege_escalation"
	CategoryDataExfiltration           RiskCategory = "data_exfiltration"
	CategoryLateralMovement            RiskCategory = "lateral_movement"
	CategoryInfrastructureModification RiskCategory = "infrastructure_modification"
	CategoryDefenseEvasion             RiskCategory = "defense_evasion"
)

// SubjectRef identifies an RBAC subject (User, Group, or ServiceAccount) and, when applicable, its namespace.
type SubjectRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Key returns the canonical "Kind/[Namespace/]Name" identifier for use in maps and log output.
func (s SubjectRef) Key() string {
	if s.Namespace == "" {
		return fmt.Sprintf("%s/%s", s.Kind, s.Name)
	}
	return fmt.Sprintf("%s/%s/%s", s.Kind, s.Namespace, s.Name)
}

// ResourceRef identifies a Kubernetes object by kind, name, and optional namespace/APIGroup.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	APIGroup  string `json:"api_group,omitempty"`
}

// Key returns the canonical "Kind/[Namespace/]Name" identifier for use in maps and log output.
func (r ResourceRef) Key() string {
	if r.Namespace == "" {
		return fmt.Sprintf("%s/%s", r.Kind, r.Name)
	}
	return fmt.Sprintf("%s/%s/%s", r.Kind, r.Namespace, r.Name)
}

// EscalationHop is one step in a privilege-escalation chain: who moved to whom, which permission enabled it, and why.
type EscalationHop struct {
	Step        int        `json:"step"`   // 1-indexed position in the chain
	Action      string     `json:"action"` // technique identifier, e.g. "pod_exec", "impersonate"
	FromSubject SubjectRef `json:"from_subject"`
	ToSubject   SubjectRef `json:"to_subject"`
	Permission  string     `json:"permission"` // RBAC permission or condition that enables the hop
	Gains       string     `json:"gains"`      // human-readable description of what the attacker obtained
}
