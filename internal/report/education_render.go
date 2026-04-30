// Package report — combined educational block for the static Findings tab.
// renderFindingEducation pulls relevant Glossary entries (subject kind, resource kind)
// and the Techniques entry for the finding, then renders them as a "Background" block
// inside the "How an attacker abuses this" section. This brings the same explanatory
// copy that drives the interactive Attack Graph side-panel into every finding card,
// so a reader does not need to click into the graph to learn what a ServiceAccount is
// or what the impersonate verb does.
//
// All HTML is constructed from in-process Glossary/Techniques values whose Long/Plain
// fields are already template.HTML. Subject/resource keys come from analyzer-supplied
// SubjectRef/ResourceRef but are routed through HTMLEscapeString before composing.
package report

import (
	"html/template"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// renderFindingEducation returns a "Background" HTML block listing the relevant
// glossary/technique definitions for f. Returns "" when nothing applies — the
// template gates the wrapper on this.
//
// Dedupe rule: when the finding has an EscalationPath, the per-hop chain cards
// already render Techniques[hop.Action].Plain for each step; in that case we
// suppress the technique entry here to avoid duplicating it. Non-chain findings
// still get the technique entry up top so RBAC/podsec/admission/etc. findings
// pick up the same educational copy a privesc finding has always had.
func renderFindingEducation(f models.Finding) template.HTML {
	var blocks []string

	// Subject (ServiceAccount, User, Group, system:masters).
	if key := GlossaryKeyForSubject(f.Subject); key != "" {
		if entry, ok := Glossary[key]; ok {
			blocks = append(blocks, educationCard(entry.Title, "Subject", entry.Long, entry.DocURL))
		}
	}

	// Resource (Pod, Secret, ConfigMap, Role, ClusterRoleBinding, ...).
	if key := GlossaryKeyForResource(f.Resource); key != "" {
		if entry, ok := Glossary[key]; ok {
			blocks = append(blocks, educationCard(entry.Title, "Resource", entry.Long, entry.DocURL))
		}
	}

	// Technique — only when the chain section won't already explain it per-hop.
	if len(f.EscalationPath) == 0 {
		if key := TechniqueKeyForFinding(f); key != "" {
			if entry, ok := Techniques[key]; ok {
				blocks = append(blocks, educationCard(entry.Title, "Technique", entry.Plain, ""))
			}
		}
	}

	if len(blocks) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="education"><span class="edu-k">Background</span><div class="edu-cards">`)
	for _, blk := range blocks {
		b.WriteString(blk)
	}
	b.WriteString(`</div></div>`)
	return template.HTML(b.String())
}

// educationCard renders one definition: a label badge, a title, the body HTML, and
// an optional Kubernetes-docs link. Title and label are HTML-escaped; body is already
// trusted template.HTML from the in-process Glossary/Techniques maps.
func educationCard(title, label string, body template.HTML, docURL string) string {
	var b strings.Builder
	b.WriteString(`<div class="edu-card"><div class="edu-hd"><span class="edu-label">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="edu-title">`)
	b.WriteString(template.HTMLEscapeString(title))
	b.WriteString(`</span></div><div class="edu-body">`)
	b.WriteString(string(body))
	b.WriteString(`</div>`)
	if docURL != "" {
		b.WriteString(`<a class="edu-doc" href="`)
		b.WriteString(template.HTMLEscapeString(docURL))
		b.WriteString(`" target="_blank" rel="noopener noreferrer">Kubernetes docs ↗</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}
