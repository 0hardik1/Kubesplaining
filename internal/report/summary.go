// Package report — summary, grouping, and hotspot helpers used to assemble the HTML
// report's high-level views (severity tallies, module/category sections, top namespaces,
// and the resource × category heatmap).
package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"unicode"

	"github.com/hardik/kubesplaining/internal/models"
)

// BuildSummary counts findings by severity to produce a Summary.
func BuildSummary(findings []models.Finding) Summary {
	summary := Summary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case models.SeverityCritical:
			summary.Critical++
		case models.SeverityHigh:
			summary.High++
		case models.SeverityMedium:
			summary.Medium++
		case models.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	return summary
}

// BuildHTMLData groups findings by module, category, namespace, subject, and resource, sorts each grouping by severity-weighted
// importance, and computes the derived visualizations (risk index, heatmap, attack graph, narratives) used by the HTML report.
func BuildHTMLData(snapshot models.Snapshot, findings []models.Finding) htmlReportData {
	moduleOrder := make([]string, 0)
	moduleMap := make(map[string][]models.Finding)
	categoryMap := make(map[models.RiskCategory][]models.Finding)
	namespaceMap := make(map[string][]models.Finding)
	subjectMap := make(map[string][]models.Finding)
	resourceMap := make(map[string][]models.Finding)

	for _, finding := range findings {
		moduleKey := moduleKeyForFinding(finding)
		if _, ok := moduleMap[moduleKey]; !ok {
			moduleOrder = append(moduleOrder, moduleKey)
		}
		moduleMap[moduleKey] = append(moduleMap[moduleKey], finding)
		categoryMap[finding.Category] = append(categoryMap[finding.Category], finding)

		if namespace := namespaceForFinding(finding); namespace != "" {
			namespaceMap[namespace] = append(namespaceMap[namespace], finding)
		}
		if finding.Subject != nil {
			subjectMap[subjectDisplay(finding.Subject)] = append(subjectMap[subjectDisplay(finding.Subject)], finding)
		}
		if finding.Resource != nil {
			resourceMap[resourceDisplay(finding.Resource)] = append(resourceMap[resourceDisplay(finding.Resource)], finding)
		}
	}

	modules := make([]ModuleSection, 0, len(moduleOrder))
	for _, key := range moduleOrder {
		moduleFindings := moduleMap[key]
		modules = append(modules, ModuleSection{
			ID:       slugify(key),
			Label:    moduleLabel(key),
			Summary:  BuildSummary(moduleFindings),
			Findings: moduleFindings,
		})
	}
	sort.Slice(modules, func(i, j int) bool {
		return compareSummaries(modules[i].Summary, modules[j].Summary, modules[i].Label, modules[j].Label)
	})

	categories := make([]CategorySection, 0, len(categoryMap))
	for key, categoryFindings := range categoryMap {
		categories = append(categories, CategorySection{
			Key:     string(key),
			CSSKey:  categoryCSSKey(key),
			Label:   categoryLabel(key),
			Summary: BuildSummary(categoryFindings),
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		return compareSummaries(categories[i].Summary, categories[j].Summary, categories[i].Label, categories[j].Label)
	})

	topNamespaces := topHotspots(namespaceMap)
	topSubjects := topHotspots(subjectMap)
	topResources := topHotspots(resourceMap)

	summary := BuildSummary(findings)
	risk, level, gaugeColor := computeRiskIndex(summary)
	graph, graphPayload := buildAttackGraph(findings)

	// AnchorByFindingID maps Finding.ID → the rule-level anchor ("finding-<RuleID>") on
	// the FIRST occurrence of each rule across all modules in render order. The narrative
	// chips link to these anchors so a click jumps straight to a representative finding.
	// Only the first finding per rule gets the anchor — duplicate ids would break browser
	// jumps.
	anchorByID := map[string]string{}
	seenRule := map[string]bool{}
	for _, m := range modules {
		for _, f := range m.Findings {
			if seenRule[f.RuleID] {
				continue
			}
			seenRule[f.RuleID] = true
			anchorByID[f.ID] = "finding-" + f.RuleID
		}
	}

	// Build the per-group TOC rows after AnchorByID is populated so each TOC row can
	// link to the rule's representative anchor. We attach Entries directly onto the
	// section structs the template already iterates.
	for i := range modules {
		modules[i].Entries = buildTOCEntries(modules[i].Findings, anchorByID)
		modules[i].RuleGroups = buildRuleGroups(modules[i].Findings, anchorByID)
	}
	for i := range categories {
		categories[i].Entries = buildTOCEntries(categoryMap[models.RiskCategory(categories[i].Key)], anchorByID)
	}

	data := htmlReportData{
		Snapshot:      snapshot,
		Summary:       summary,
		Findings:      findings,
		Modules:       modules,
		Categories:    categories,
		TopNamespaces: topNamespaces,
		TopSubjects:   topSubjects,
		TopResources:  topResources,
		RiskIndex:     risk,
		RiskLevel:     level,
		GaugeDash:     gaugeDash(risk),
		GaugeColor:    gaugeColor,
		HeatCats:      heatmapCategories(),
		HeatRows:      buildHeatmap(resourceMap),
		Narratives:    buildNarratives(findings),
		Graph:         graph,
		GraphJSON:     marshalGraphPayload(graphPayload),
		GraphScript:   template.JS(kpGraphScript),
		AnchorByID:    anchorByID,
	}
	if len(findings) > 5 {
		data.TopFindings = append([]models.Finding(nil), findings[:5]...)
	} else {
		data.TopFindings = append([]models.Finding(nil), findings...)
	}
	data.Headline, data.Summaries = buildHeadline(summary, data.Narratives, topNamespaces)
	return data
}

// compareSummaries orders two summaries by severity importance (critical, high, medium, total) with a label tiebreaker.
func compareSummaries(a Summary, b Summary, aLabel string, bLabel string) bool {
	switch {
	case a.Critical != b.Critical:
		return a.Critical > b.Critical
	case a.High != b.High:
		return a.High > b.High
	case a.Medium != b.Medium:
		return a.Medium > b.Medium
	case a.Total != b.Total:
		return a.Total > b.Total
	default:
		return aLabel < bLabel
	}
}

// topHotspots converts a label→findings map into at most 5 Hotspot entries ordered by severity weight.
func topHotspots(groups map[string][]models.Finding) []Hotspot {
	hotspots := make([]Hotspot, 0, len(groups))
	for label, findings := range groups {
		if label == "" {
			continue
		}
		hotspots = append(hotspots, Hotspot{
			Label:   label,
			Summary: BuildSummary(findings),
		})
	}
	sort.Slice(hotspots, func(i, j int) bool {
		return compareSummaries(hotspots[i].Summary, hotspots[j].Summary, hotspots[i].Label, hotspots[j].Label)
	})
	if len(hotspots) > 5 {
		return hotspots[:5]
	}
	return hotspots
}

// moduleKeyForFinding extracts the "module:<name>" tag so findings can be grouped by producing analyzer; falls back to "other".
func moduleKeyForFinding(finding models.Finding) string {
	for _, tag := range finding.Tags {
		if name, ok := strings.CutPrefix(tag, "module:"); ok {
			return name
		}
	}
	return "other"
}

// moduleLabel maps a module key to its human-readable display name used in HTML section headings.
func moduleLabel(key string) string {
	switch key {
	case "rbac":
		return "RBAC"
	case "pod_security":
		return "Pod Security"
	case "network_policy":
		return "Network Policy"
	case "service_account":
		return "Service Accounts"
	case "secrets":
		return "Secrets & ConfigMaps"
	case "admission":
		return "Admission Webhooks"
	default:
		return titleCaseWords(strings.ReplaceAll(key, "_", " "))
	}
}

// categoryLabel maps a RiskCategory to its human-readable display name.
func categoryLabel(category models.RiskCategory) string {
	switch category {
	case models.CategoryPrivilegeEscalation:
		return "Privilege Escalation"
	case models.CategoryDataExfiltration:
		return "Data Exfiltration"
	case models.CategoryLateralMovement:
		return "Lateral Movement"
	case models.CategoryInfrastructureModification:
		return "Infrastructure Modification"
	case models.CategoryDefenseEvasion:
		return "Defense Evasion"
	default:
		return titleCaseWords(strings.ReplaceAll(string(category), "_", " "))
	}
}

// titleCaseWords upper-cases the first rune of each space-separated word; replacement
// for the deprecated strings.Title used to render module/category labels.
func titleCaseWords(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		if p == "" {
			continue
		}
		runes := []rune(p)
		runes[0] = unicode.ToUpper(runes[0])
		parts[i] = string(runes)
	}
	return strings.Join(parts, " ")
}

// categoryCSSKey maps a RiskCategory to the short CSS class suffix used by the heatmap cells and graph nodes.
func categoryCSSKey(c models.RiskCategory) string {
	switch c {
	case models.CategoryPrivilegeEscalation:
		return "privesc"
	case models.CategoryLateralMovement:
		return "lateral"
	case models.CategoryDataExfiltration:
		return "exfil"
	case models.CategoryInfrastructureModification:
		return "infra"
	case models.CategoryDefenseEvasion:
		return "evasion"
	default:
		return "info"
	}
}

// slugify produces an anchor-safe lowercase identifier from an arbitrary label.
func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	// Collapse anything that isn't [a-z0-9-] to a single dash so the result is
	// safe to use as an HTML/SVG id (and inside `url(#…)` clip-path refs).
	var b strings.Builder
	b.Grow(len(value))
	prevDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// namespaceForFinding returns the first non-empty namespace among finding.Namespace, resource, and subject.
func namespaceForFinding(finding models.Finding) string {
	if finding.Namespace != "" {
		return finding.Namespace
	}
	if finding.Resource != nil && finding.Resource.Namespace != "" {
		return finding.Resource.Namespace
	}
	if finding.Subject != nil && finding.Subject.Namespace != "" {
		return finding.Subject.Namespace
	}
	return ""
}

// subjectDisplay formats a SubjectRef as "Kind/[Namespace/]Name", or "-" when nil.
func subjectDisplay(subject *models.SubjectRef) string {
	if subject == nil {
		return "-"
	}
	if subject.Namespace == "" {
		return fmt.Sprintf("%s/%s", subject.Kind, subject.Name)
	}
	return fmt.Sprintf("%s/%s/%s", subject.Kind, subject.Namespace, subject.Name)
}

// resourceDisplay formats a ResourceRef as "Kind/[Namespace/]Name", or "-" when nil.
func resourceDisplay(resource *models.ResourceRef) string {
	if resource == nil {
		return "-"
	}
	if resource.Namespace == "" {
		return fmt.Sprintf("%s/%s", resource.Kind, resource.Name)
	}
	return fmt.Sprintf("%s/%s/%s", resource.Kind, resource.Namespace, resource.Name)
}

// heatmapCategories returns the fixed column order for the Resource × Category heatmap.
func heatmapCategories() []HeatmapCategory {
	return []HeatmapCategory{
		{Key: "privesc", Label: "Priv. escalation"},
		{Key: "lateral", Label: "Lateral movement"},
		{Key: "exfil", Label: "Data exfil"},
		{Key: "infra", Label: "Infra modification"},
		{Key: "evasion", Label: "Defense evasion"},
	}
}

// buildHeatmap computes a Resource × Category matrix for the top resources, showing how each
// high-blast-radius object concentrates findings across attack categories.
func buildHeatmap(resourceMap map[string][]models.Finding) []HeatmapRow {
	keys := heatmapCategories()
	type entry struct {
		label    string
		findings []models.Finding
	}
	entries := make([]entry, 0, len(resourceMap))
	for label, fs := range resourceMap {
		if label == "" || label == "-" {
			continue
		}
		entries = append(entries, entry{label: label, findings: fs})
	}
	sort.Slice(entries, func(i, j int) bool {
		a := BuildSummary(entries[i].findings)
		b := BuildSummary(entries[j].findings)
		return compareSummaries(a, b, entries[i].label, entries[j].label)
	})
	if len(entries) > 10 {
		entries = entries[:10]
	}

	rows := make([]HeatmapRow, 0, len(entries))
	for _, e := range entries {
		row := HeatmapRow{Label: e.label, Total: len(e.findings)}
		counts := map[string]int{}
		var top models.Severity = models.SeverityInfo
		for _, f := range e.findings {
			counts[categoryCSSKey(f.Category)]++
			if f.Severity.Rank() > top.Rank() {
				top = f.Severity
			}
		}
		for _, k := range keys {
			n := counts[k.Key]
			row.Cells = append(row.Cells, HeatmapCell{
				Count:    n,
				CatClass: k.Key,
				Level:    heatLevel(n),
				Resource: e.label,
			})
		}
		switch top {
		case models.SeverityCritical:
			row.SevClass, row.SevLabel = "crit", "CRIT"
		case models.SeverityHigh:
			row.SevClass, row.SevLabel = "high", "HIGH"
		case models.SeverityMedium:
			row.SevClass, row.SevLabel = "med", "MED"
		default:
			row.SevClass, row.SevLabel = "low", "LOW"
		}
		rows = append(rows, row)
	}
	return rows
}

// heatLevel bins a cell count into a 0..5 intensity level for CSS-driven heat coloring.
func heatLevel(n int) int {
	switch {
	case n <= 0:
		return 0
	case n == 1:
		return 1
	case n == 2:
		return 2
	case n == 3:
		return 3
	case n == 4:
		return 4
	default:
		return 5
	}
}

// buildRuleGroups collapses a slice of findings (already in render order) into one RuleGroup
// per RuleID. Each group's first finding becomes the "exemplar" — its Title is used as the
// subject-neutralized rule title, and its MITRE / References / LearnMore become the rule-level
// shared content. TopSeverity / MaxScore / MinScore are computed across the group.
//
// Order of groups preserves the first-occurrence order of the input findings (which is already
// severity-then-score sorted upstream), so the rendered Findings tab still shows the most
// dangerous rules first.
func buildRuleGroups(findings []models.Finding, anchorByID map[string]string) []RuleGroup {
	if len(findings) == 0 {
		return nil
	}
	type acc struct {
		group   RuleGroup
		members []models.Finding
		order   int
	}
	byRule := make(map[string]*acc, len(findings))
	order := 0
	for _, f := range findings {
		entry, ok := byRule[f.RuleID]
		if !ok {
			entry = &acc{
				group: RuleGroup{
					RuleID:          f.RuleID,
					RuleTitle:       ruleTitleForGroup(f),
					TopSeverity:     f.Severity,
					MaxScore:        f.Score,
					MinScore:        f.Score,
					MitreTechniques: f.MitreTechniques,
					LearnMore:       f.LearnMore,
					References:      f.References,
				},
				order: order,
			}
			if a, found := anchorByID[f.ID]; found {
				entry.group.Anchor = a
			} else {
				entry.group.Anchor = "finding-" + f.RuleID
			}
			byRule[f.RuleID] = entry
			order++
		} else {
			if f.Severity.Rank() > entry.group.TopSeverity.Rank() {
				entry.group.TopSeverity = f.Severity
			}
			if f.Score > entry.group.MaxScore {
				entry.group.MaxScore = f.Score
			}
			if f.Score < entry.group.MinScore {
				entry.group.MinScore = f.Score
			}
		}
		entry.members = append(entry.members, f)
	}
	groups := make([]RuleGroup, len(byRule))
	for _, e := range byRule {
		e.group.Findings = e.members
		e.group.InstanceCount = len(e.members)
		groups[e.order] = e.group
	}
	return groups
}

// ruleTitleForGroup returns a subject-neutral version of a finding's Title, suitable as the
// header for a rule card. Many finding titles embed the subject ("`ServiceAccount/X` can reach
// cluster-admin equivalent in 1 hop(s)"); we strip that leading subject and replace it with
// "Subjects" so the title reads as a description of the rule, not a single instance. Falls
// back to the raw title for rules whose titles don't follow that pattern.
func ruleTitleForGroup(f models.Finding) string {
	title := strings.TrimSpace(f.Title)
	if f.Subject == nil || title == "" {
		return title
	}
	subj := subjectDisplay(f.Subject)
	if subj == "" || subj == "-" {
		return title
	}
	for _, prefix := range []string{"`" + subj + "` ", subj + " "} {
		if strings.HasPrefix(title, prefix) {
			rest := strings.TrimPrefix(title, prefix)
			return "Subjects " + rest
		}
	}
	return title
}

// buildTOCEntries collapses a slice of findings into one TOCEntry per RuleID, keeping the
// highest severity seen and counting instances. Sort order: severity rank desc → count desc
// → title asc — matches how the rest of the report orders findings, so the TOC reads top-down
// by importance. Anchor comes from anchorByID, which is keyed on Finding.ID and only set on
// the first occurrence of each rule across all modules; we look up via the first finding we
// see for each RuleID in this group, falling back to "finding-<RuleID>" so the link still
// works even if the lookup misses (defensive — should not happen in practice).
func buildTOCEntries(findings []models.Finding, anchorByID map[string]string) []TOCEntry {
	if len(findings) == 0 {
		return nil
	}
	type acc struct {
		title    string
		severity models.Severity
		anchor   string
		count    int
		order    int // first-seen order, used as a stable tiebreaker
	}
	byRule := make(map[string]*acc, len(findings))
	order := 0
	for _, f := range findings {
		entry, ok := byRule[f.RuleID]
		if !ok {
			entry = &acc{title: f.Title, severity: f.Severity, order: order}
			if a, found := anchorByID[f.ID]; found {
				entry.anchor = a
			} else {
				entry.anchor = "finding-" + f.RuleID
			}
			byRule[f.RuleID] = entry
			order++
		} else if f.Severity.Rank() > entry.severity.Rank() {
			entry.severity = f.Severity
		}
		entry.count++
	}
	entries := make([]TOCEntry, 0, len(byRule))
	for ruleID, e := range byRule {
		entries = append(entries, TOCEntry{
			RuleID:   ruleID,
			Title:    e.title,
			Severity: e.severity,
			Anchor:   e.anchor,
			Count:    e.count,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		ri := entries[i].Severity.Rank()
		rj := entries[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		if entries[i].Title != entries[j].Title {
			return entries[i].Title < entries[j].Title
		}
		return entries[i].RuleID < entries[j].RuleID
	})
	return entries
}
