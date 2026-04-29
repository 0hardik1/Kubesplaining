// Package report — format writers and graph payload marshaling. writeJSON / writeCSV /
// writeHTML are the per-format outputs dispatched from Write; SARIF lives in sarif.go.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
)

// marshalGraphPayload serializes the GraphPayload for inline embedding in a
// <script type="application/json"> block. encoding/json escapes <, >, & to \uXXXX by default,
// which prevents the JSON from breaking out of the script tag. On the (essentially impossible)
// case of a marshal failure we degrade to "{}" so the page still loads — interactivity is off,
// but the static SVG continues to render.
func marshalGraphPayload(p GraphPayload) template.JS {
	b, err := json.Marshal(p)
	if err != nil {
		return template.JS("{}")
	}
	return template.JS(b)
}

// writeJSON writes findings as an indented JSON array at path.
func writeJSON(path string, findings []models.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create json report: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(findings); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}

	return nil
}

// writeCSV writes findings as a triage-friendly CSV with one row per finding and a fixed column order.
func writeCSV(path string, findings []models.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv report: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{
		"Finding ID",
		"Severity",
		"Score",
		"Category",
		"Scope",
		"Scope Detail",
		"Impact",
		"Subject Kind",
		"Subject Name",
		"Subject Namespace",
		"Resource",
		"Title",
		"Description",
		"Remediation",
		"Reference URL",
	}); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for _, finding := range findings {
		resourceName := ""
		if finding.Resource != nil {
			resourceName = finding.Resource.Key()
		}

		subjectKind := ""
		subjectName := ""
		subjectNamespace := ""
		if finding.Subject != nil {
			subjectKind = finding.Subject.Kind
			subjectName = finding.Subject.Name
			subjectNamespace = finding.Subject.Namespace
		}

		reference := ""
		if len(finding.References) > 0 {
			reference = finding.References[0]
		}

		record := []string{
			finding.ID,
			string(finding.Severity),
			fmt.Sprintf("%.1f", finding.Score),
			string(finding.Category),
			string(finding.Scope.Level),
			finding.Scope.Detail,
			finding.Impact,
			subjectKind,
			subjectName,
			subjectNamespace,
			resourceName,
			finding.Title,
			finding.Description,
			finding.Remediation,
			reference,
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}

	return writer.Error()
}

// writeHTML renders the embedded htmlTemplate with findings-derived data and writes a self-contained report page.
func writeHTML(path string, snapshot models.Snapshot, findings []models.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create html report: %w", err)
	}
	defer file.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": func(value any) string {
			return strings.ToLower(fmt.Sprint(value))
		},
		"sevClass": func(s any) string {
			switch strings.ToUpper(fmt.Sprint(s)) {
			case "CRITICAL":
				return "crit"
			case "HIGH":
				return "high"
			case "MEDIUM":
				return "med"
			case "LOW":
				return "low"
			default:
				return "info"
			}
		},
		"sevShort": func(s any) string {
			return strings.ToUpper(fmt.Sprint(s))
		},
		"subject": func(subject *models.SubjectRef) string {
			if subject == nil {
				return "-"
			}
			if subject.Namespace == "" {
				return fmt.Sprintf("%s/%s", subject.Kind, subject.Name)
			}
			return fmt.Sprintf("%s/%s/%s", subject.Kind, subject.Namespace, subject.Name)
		},
		"resource": func(resource *models.ResourceRef) string {
			if resource == nil {
				return "-"
			}
			if resource.Namespace == "" {
				return fmt.Sprintf("%s/%s", resource.Kind, resource.Name)
			}
			return fmt.Sprintf("%s/%s/%s", resource.Kind, resource.Namespace, resource.Name)
		},
		// subjectCode / resourceCode emit a <code> wrapper annotated with data-glossary-key
		// when the Kind has a Glossary entry. The JS layer reuses the existing .kp-tooltip
		// element to pop the entry on hover. Falls back to a plain <code> when no glossary
		// match exists, so unknown kinds keep their inline-code styling without becoming
		// "hoverable for nothing."
		"subjectCode": func(s *models.SubjectRef) template.HTML {
			if s == nil {
				return template.HTML("<code>-</code>")
			}
			label := template.HTMLEscapeString(subjectDisplay(s))
			if key := GlossaryKeyForSubject(s); key != "" {
				return template.HTML(`<code class="gloss" data-glossary-key="` +
					template.HTMLEscapeString(key) + `">` + label + `</code>`)
			}
			return template.HTML("<code>" + label + "</code>")
		},
		"resourceCode": func(r *models.ResourceRef) template.HTML {
			if r == nil {
				return template.HTML("<code>-</code>")
			}
			label := template.HTMLEscapeString(resourceDisplay(r))
			if key := GlossaryKeyForResource(r); key != "" {
				return template.HTML(`<code class="gloss" data-glossary-key="` +
					template.HTMLEscapeString(key) + `">` + label + `</code>`)
			}
			return template.HTML("<code>" + label + "</code>")
		},
		"json": func(raw json.RawMessage) string {
			if len(raw) == 0 {
				return ""
			}
			var payload any
			if err := json.Unmarshal(raw, &payload); err != nil {
				return string(raw)
			}
			pretty, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				return string(raw)
			}
			return string(pretty)
		},
		"score": func(v float64) string {
			return fmt.Sprintf("%.1f", v)
		},
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"div":      func(a, b int) int { return a / b },
		"midY":     func(n GraphNode) int { return n.Y + n.Height/2 },
		"rightX":   func(n GraphNode) int { return n.X + n.Width },
		"catKey":   func(c models.RiskCategory) string { return categoryCSSKey(c) },
		"catLabel": func(c models.RiskCategory) string { return categoryLabel(c) },
		"scopeLabel": func(level models.ScopeLevel) string {
			return level.Label()
		},
		// scopeDetailHTML renders a scope detail string with backtick-quoted spans wrapped in <code>.
		// Subject/resource keys like `prod/svc-a` become <code>prod/svc-a</code> for visual emphasis
		// without forcing analyzers to ship raw HTML.
		"scopeDetailHTML": func(detail string) template.HTML {
			return template.HTML(renderInlineCode(detail))
		},
		// descriptionHTML splits a description into <p> blocks on blank lines and inline-renders
		// backtick spans as <code>. Analyzers can write 1-3 short paragraphs separated by "\n\n".
		"descriptionHTML": func(description string) template.HTML {
			return template.HTML(renderParagraphs(description))
		},
		// remediationStepHTML inline-renders a single remediation step, allowing backtick code spans.
		"remediationStepHTML": func(step string) template.HTML {
			return template.HTML(renderInlineCode(step))
		},
		// inlineHTML renders any analyzer-supplied single-line text (titles, impact,
		// attack-scenario steps, remediation summary) with the same `code` / **bold**
		// markdown subset as descriptions, so backticks and bold markers don't appear
		// raw in the static Findings tab.
		"inlineHTML": func(text string) template.HTML {
			return template.HTML(renderInlineCode(text))
		},
		// evidenceHTML renders Finding.Evidence as a labeled grid with chips and glossary
		// hints rather than raw JSON. The original payload is still available below in a
		// "Show raw JSON" sub-details emitted by the template.
		"evidenceHTML": func(raw json.RawMessage) template.HTML {
			return renderEvidence(raw)
		},
		// escalationPathHTML renders Finding.EscalationPath as a numbered ordered list of
		// per-hop step cards. Returns "" for empty input so the template gate suppresses
		// the surrounding section on non-privesc findings.
		"escalationPathHTML": func(hops []models.EscalationHop) template.HTML {
			return renderEscalationPath(hops)
		},
		// findingEducationHTML returns a "Background" block of glossary/technique
		// definitions tailored to the finding (subject kind, resource kind, technique).
		// Returns "" when no entries apply, gating the wrapper.
		"findingEducationHTML": func(f models.Finding) template.HTML {
			return renderFindingEducation(f)
		},
		"pluralize": func(n int, singular, plural string) string {
			if n == 1 {
				return singular
			}
			return plural
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	data := BuildHTMLData(snapshot, findings)

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}
