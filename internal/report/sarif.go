package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hardik/kubesplaining/internal/models"
)

// sarifReport models the minimal subset of SARIF 2.1.0 we emit for IDE/CI tooling.
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun is one scanner execution inside a SARIF report; kubesplaining always emits exactly one.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name,omitempty"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription,omitempty"`
	HelpURI string `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Kind       string          `json:"kind,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
	Locations  []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// writeSARIF serializes findings as a SARIF 2.1.0 document with one rule per unique RuleID and one result per finding.
func writeSARIF(path string, findings []models.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create sarif report: %w", err)
	}
	defer file.Close()

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "kubesplaining",
						InformationURI: "https://github.com/hardik/kubesplaining",
						Rules:          sarifRules(findings),
					},
				},
				Results: sarifResults(findings),
			},
		},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode sarif report: %w", err)
	}

	return nil
}

// sarifRules projects unique RuleIDs from findings into SARIF rule metadata, deduplicated by ID.
func sarifRules(findings []models.Finding) []sarifRule {
	seen := map[string]struct{}{}
	rules := make([]sarifRule, 0)
	for _, finding := range findings {
		if _, ok := seen[finding.RuleID]; ok {
			continue
		}
		seen[finding.RuleID] = struct{}{}
		rule := sarifRule{
			ID:   finding.RuleID,
			Name: finding.Title,
		}
		rule.ShortDescription.Text = finding.Description
		if len(finding.References) > 0 {
			rule.HelpURI = finding.References[0]
		}
		rules = append(rules, rule)
	}
	return rules
}

// sarifResults converts findings into SARIF results, attaching subject/resource metadata as properties and logical locations.
func sarifResults(findings []models.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		result := sarifResult{
			RuleID: finding.RuleID,
			Level:  sarifLevel(finding.Severity),
			Kind:   "fail",
			Message: sarifMessage{
				Text: finding.Title + ": " + finding.Description,
			},
			Properties: map[string]any{
				"severity":    finding.Severity,
				"score":       finding.Score,
				"category":    finding.Category,
				"namespace":   finding.Namespace,
				"tags":        finding.Tags,
				"remediation": finding.Remediation,
			},
		}
		if finding.Subject != nil {
			result.Properties["subject"] = finding.Subject
		}
		if finding.Resource != nil {
			result.Properties["resource"] = finding.Resource
			location := sarifLogicalLocation{
				Name:               finding.Resource.Name,
				FullyQualifiedName: finding.Resource.Key(),
				Kind:               finding.Resource.Kind,
			}
			result.Locations = []sarifLocation{{LogicalLocations: []sarifLogicalLocation{location}}}
		}
		results = append(results, result)
	}
	return results
}

// sarifLevel maps our severity buckets to SARIF's "error"/"warning"/"note" levels.
func sarifLevel(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
