// Package report — attack-graph layout. Builds the 3-column SVG flow diagram (entries
// → capabilities → impacts) plus the parallel detail payload for the JS interactivity
// layer. All coordinates are precomputed here so the template emits raw SVG without any
// layout logic of its own.
package report

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildAttackGraph composes a 3-column flow diagram (entries → capabilities → impacts) from findings.
// Coordinates are deterministic so the template only emits SVG, no layout computation.
// Returns the cosmetic AttackGraph (for the SVG template) and a detail GraphPayload (for the
// inline JSON block that drives the interactive side panel).
func buildAttackGraph(findings []models.Finding) (AttackGraph, GraphPayload) {
	emptyPayload := GraphPayload{Glossary: Glossary, Techniques: Techniques, Categories: Categories}

	// Select capabilities: critical + high findings, deduplicated by rule_id (keep highest-scoring),
	// then capped at maxCaps. Selection guarantees at least one cap per RiskCategory present in
	// the candidate pool — otherwise a fixture dominated by one category (e.g. 90+ privesc rules)
	// fills the slate and the Impact lane collapses to a single node, hiding the lateral-movement
	// or data-exfiltration impacts the same cluster also has.
	const maxCaps = 10
	byRule := map[string]models.Finding{}
	for _, f := range findings {
		if f.Severity != models.SeverityCritical && f.Severity != models.SeverityHigh {
			continue
		}
		if existing, ok := byRule[f.RuleID]; !ok || f.Score > existing.Score {
			byRule[f.RuleID] = f
		}
	}
	totalCaps := len(byRule)

	capLess := func(a, b models.Finding) bool {
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.RuleID < b.RuleID
	}

	byCategory := map[models.RiskCategory][]models.Finding{}
	for _, f := range byRule {
		byCategory[f.Category] = append(byCategory[f.Category], f)
	}
	for c := range byCategory {
		sort.Slice(byCategory[c], func(i, j int) bool { return capLess(byCategory[c][i], byCategory[c][j]) })
	}

	categoryOrder := []models.RiskCategory{
		models.CategoryPrivilegeEscalation,
		models.CategoryLateralMovement,
		models.CategoryDataExfiltration,
		models.CategoryInfrastructureModification,
		models.CategoryDefenseEvasion,
	}
	caps := make([]models.Finding, 0, maxCaps)
	chosen := map[string]bool{}
	pickTop := func(c models.RiskCategory) {
		cands := byCategory[c]
		if len(cands) == 0 || len(caps) >= maxCaps {
			return
		}
		caps = append(caps, cands[0])
		chosen[cands[0].RuleID] = true
	}
	for _, c := range categoryOrder {
		pickTop(c)
	}
	for c := range byCategory {
		if !slices.Contains(categoryOrder, c) {
			pickTop(c)
		}
	}

	remaining := make([]models.Finding, 0, totalCaps)
	for _, f := range byRule {
		if !chosen[f.RuleID] {
			remaining = append(remaining, f)
		}
	}
	sort.Slice(remaining, func(i, j int) bool { return capLess(remaining[i], remaining[j]) })
	for _, f := range remaining {
		if len(caps) >= maxCaps {
			break
		}
		caps = append(caps, f)
		chosen[f.RuleID] = true
	}

	sort.Slice(caps, func(i, j int) bool { return capLess(caps[i], caps[j]) })
	if len(caps) == 0 {
		return AttackGraph{
			Width: 980, Height: 120,
			Lanes: [3]GraphLane{
				{X: 20, Label: "Entry point", LabelX: 170, LabelW: 110},
				{X: 360, Label: "Abused capability", LabelX: 530, LabelW: 175},
				{X: 720, Label: "Impact", LabelX: 840, LabelW: 80},
			},
		}, emptyPayload
	}

	// Select entry points: the resource/subject each capability is about, deduplicated.
	// Entry key = subject.Key() when present, else resource.Key(). Label reflects source.
	// representative remembers a sample finding so we can later resolve a GlossaryKey from
	// its Subject/Resource without re-walking findings.
	type entryInfo struct {
		Key            string
		Title          string
		Subtitle       string
		Meta           string
		SevClass       string
		topScore       float64
		representative models.Finding
		hasRep         bool
		entryKind      string // "Subject" | "Resource" — used by the JS filter chips.
	}
	entries := map[string]*entryInfo{}
	entryForCap := make([]string, len(caps))
	for i, f := range caps {
		key, title, subtitle := entryIdentity(f)
		if key == "" {
			key, title, subtitle = "cluster", "Cluster-wide", "No subject / resource attributed"
		}
		entryForCap[i] = key
		e, ok := entries[key]
		if !ok {
			kind := ""
			switch {
			case f.Subject != nil:
				kind = "Subject"
			case f.Resource != nil:
				kind = "Resource"
			}
			e = &entryInfo{Key: key, Title: title, Subtitle: subtitle, SevClass: severityClass(f.Severity), entryKind: kind}
			entries[key] = e
		}
		if !e.hasRep {
			e.representative = f
			e.hasRep = true
		}
		if f.Score > e.topScore {
			e.topScore = f.Score
			e.SevClass = severityClass(f.Severity)
		}
	}
	// Count findings attributable to each entry for meta.
	entryCounts := map[string]int{}
	for _, cf := range caps {
		key, _, _ := entryIdentity(cf)
		if key != "" {
			entryCounts[key]++
		}
	}
	for k, e := range entries {
		n := entryCounts[k]
		if n <= 1 {
			e.Meta = "1 critical/high on this entity"
		} else {
			e.Meta = fmt.Sprintf("%d critical/high findings on this entity", n)
		}
	}
	// Order entries by highest capability score descending.
	entryKeys := make([]string, 0, len(entries))
	for k := range entries {
		entryKeys = append(entryKeys, k)
	}
	sort.Slice(entryKeys, func(i, j int) bool {
		ei, ej := entries[entryKeys[i]], entries[entryKeys[j]]
		if ei.topScore != ej.topScore {
			return ei.topScore > ej.topScore
		}
		return ei.Title < ej.Title
	})

	// Select impacts: one per category present in capabilities.
	categoriesPresent := map[models.RiskCategory]bool{}
	for _, f := range caps {
		categoriesPresent[f.Category] = true
	}
	impactOrder := []models.RiskCategory{
		models.CategoryPrivilegeEscalation,
		models.CategoryLateralMovement,
		models.CategoryDataExfiltration,
		models.CategoryInfrastructureModification,
		models.CategoryDefenseEvasion,
	}
	impactKeys := make([]models.RiskCategory, 0, len(categoriesPresent))
	for _, c := range impactOrder {
		if categoriesPresent[c] {
			impactKeys = append(impactKeys, c)
		}
	}

	// Lane geometry. Gaps between lanes (40px entry→cap, 80px cap→impact) give
	// the bezier edges horizontal room to fan out — the cap→impact gap was
	// previously 20px, which made many edges overlap when several capabilities
	// converged on the same impact node.
	const (
		laneEntryX, laneEntryW   = 20, 300
		laneCapX, laneCapW       = 360, 360
		laneImpactX, laneImpactW = 800, 240
		topY                     = 50
		capGap                   = 14
		entryGap                 = 18
		impactGap                = 18
		// Inner text-budget per lane (box width minus left padding minus right breathing room).
		// wrapForWidth uses these to break long strings across multiple lines so the full
		// text shows — this tool is educational, so we never truncate.
		// Entry/cap left padding is 26/22px to clear the severity dot at top-left.
		entryTextPx  = laneEntryW - 26 - 12  // 262
		capTextPx    = laneCapW - 22 - 12    // 326
		impactTextPx = laneImpactW - 16 - 12 // 212
	)

	g := AttackGraph{
		Width: 1080,
		Lanes: [3]GraphLane{
			{X: laneEntryX, Label: "Entry point", LabelX: laneEntryX + laneEntryW/2, LabelW: 110},
			{X: laneCapX, Label: "Abused capability", LabelX: laneCapX + laneCapW/2, LabelW: 175},
			{X: laneImpactX, Label: "Impact", LabelX: laneImpactX + laneImpactW/2, LabelW: 80},
		},
		Shown:     len(caps),
		TotalCaps: totalCaps,
		Truncated: totalCaps > len(caps),
	}

	// Build entry nodes with wrapped text + dynamic height.
	entryNodePos := map[string]GraphNode{}
	entryNodeList := make([]GraphNode, 0, len(entryKeys))
	for _, k := range entryKeys {
		e := entries[k]
		// Per-class avg-glyph widths (px) calibrated to the CSS in the template.
		titleLines := wrapForWidth(e.Title, entryTextPx, 7.2)  // node-title:  13px sans 600
		subLines := wrapForWidth(e.Subtitle, entryTextPx, 6.6) // node-sub:    11px monospace
		metaLines := wrapForWidth(e.Meta, entryTextPx, 5.7)    // node-meta:   10.5px sans
		lines, height := composeLines(26, []textCluster{
			{class: "node-title", lineHeight: 17, leadIn: 22, lines: titleLines},
			{class: "node-sub", lineHeight: 14, leadIn: 18, lines: subLines},
			{class: "node-meta", lineHeight: 14, leadIn: 17, lines: metaLines},
		}, 12)
		entryNodeList = append(entryNodeList, GraphNode{
			ID:       "entry-" + slugify(k),
			Kind:     "entry",
			X:        laneEntryX,
			Width:    laneEntryW,
			Height:   height,
			SevClass: e.SevClass,
			Lines:    lines,
		})
	}

	// Build capability nodes. Strip markdown markers (`, **) from the title
	// before wrapping — SVG <text> can't render <code>/<strong>, so leaving
	// them in shows raw chars in the node. The popup-pane GraphNodeDetail
	// keeps the original Title (with markdown) so its prose renderer can show
	// proper code/bold formatting.
	capNodes := make([]GraphNode, len(caps))
	for i, f := range caps {
		ruleMeta := fmt.Sprintf("%s  ·  score %.1f", f.RuleID, f.Score)
		ruleLines := wrapForWidth(ruleMeta, capTextPx, 6.3)                // rule-id:    10px monospace + letter-spacing
		titleLines := wrapForWidth(stripMarkdown(f.Title), capTextPx, 7.2) // node-title: 13px sans 600
		lines, height := composeLines(22, []textCluster{
			{class: "rule-id", lineHeight: 14, leadIn: 18, lines: ruleLines},
			{class: "node-title", lineHeight: 17, leadIn: 22, lines: titleLines},
		}, 14)
		capNodes[i] = GraphNode{
			ID:       "cap-" + slugify(f.RuleID+"-"+strconv.Itoa(i)),
			Kind:     "capability",
			X:        laneCapX,
			Width:    laneCapW,
			Height:   height,
			SevClass: severityClass(f.Severity),
			Lines:    lines,
		}
	}

	// Build impact nodes.
	impactNodeList := make([]GraphNode, 0, len(impactKeys))
	for _, c := range impactKeys {
		titleLines := wrapForWidth(impactLabel(c), impactTextPx, 8.5)   // impact-title: 13px bold uppercase
		metaLines := wrapForWidth(impactSubtitle(c), impactTextPx, 5.7) // node-meta:    10.5px sans
		lines, height := composeLines(16, []textCluster{
			{class: "impact-title", lineHeight: 18, leadIn: 26, lines: titleLines},
			{class: "node-meta", lineHeight: 14, leadIn: 18, lines: metaLines},
		}, 14)
		impactNodeList = append(impactNodeList, GraphNode{
			ID:       "imp-" + categoryCSSKey(c),
			Kind:     "impact",
			X:        laneImpactX,
			Width:    laneImpactW,
			Height:   height,
			SevClass: "crit", // impacts rendered with the critical accent gradient
			Lines:    lines,
		})
	}

	// Lane vertical totals (heights sum + gaps). Then center each lane independently
	// in the available column space so short lanes don't bunch at the top.
	laneTotal := func(nodes []GraphNode, gap int) int {
		if len(nodes) == 0 {
			return 0
		}
		total := -gap
		for _, n := range nodes {
			total += n.Height + gap
		}
		return total
	}
	entryTotalH := laneTotal(entryNodeList, entryGap)
	capTotalH := laneTotal(capNodes, capGap)
	impactTotalH := laneTotal(impactNodeList, impactGap)

	height := topY + max(capTotalH, entryTotalH, impactTotalH) + 20
	height = max(height, 260)
	g.Height = height

	stack := func(nodes []GraphNode, totalH, gap int) []GraphNode {
		startY := max(topY+(height-topY-20-totalH)/2, topY)
		y := startY
		out := make([]GraphNode, len(nodes))
		for i, n := range nodes {
			n.Y = y
			out[i] = n
			y += n.Height + gap
		}
		return out
	}

	entryNodeList = stack(entryNodeList, entryTotalH, entryGap)
	capNodes = stack(capNodes, capTotalH, capGap)
	impactNodeList = stack(impactNodeList, impactTotalH, impactGap)

	for i, k := range entryKeys {
		entryNodePos[k] = entryNodeList[i]
		g.Nodes = append(g.Nodes, entryNodeList[i])
	}
	g.Nodes = append(g.Nodes, capNodes...)
	impactNodePos := map[models.RiskCategory]GraphNode{}
	for i, c := range impactKeys {
		impactNodePos[c] = impactNodeList[i]
		g.Nodes = append(g.Nodes, impactNodeList[i])
	}

	// Edges: entry → capability (per finding), capability → impact (by category). Each edge gets
	// a stable ID derived from the node IDs so the JS layer can highlight by lookup.
	// edgesByNode tracks which edge IDs touch each node so the side panel can dim everything else
	// when the user hovers/clicks one node.
	edgesByNode := map[string][]string{}
	payload := GraphPayload{Glossary: Glossary, Techniques: Techniques, Categories: Categories}
	for i, f := range caps {
		entryNode, okE := entryNodePos[entryForCap[i]]
		capNode := capNodes[i]
		impNode, okI := impactNodePos[f.Category]
		class := severityClass(f.Severity)
		techKey := TechniqueKeyForFinding(f)
		if okE {
			edgeID := "edge-" + entryNode.ID + "-" + capNode.ID
			g.Edges = append(g.Edges, GraphEdge{
				ID:    edgeID,
				Class: class,
				D:     bezier(entryNode.X+entryNode.Width, entryNode.Y+entryNode.Height/2, capNode.X, capNode.Y+capNode.Height/2),
			})
			payload.Edges = append(payload.Edges, GraphEdgeDetail{
				ID:           edgeID,
				From:         entryNode.ID,
				To:           capNode.ID,
				Class:        class,
				TechniqueKey: techKey,
				ActionLabel:  "abuses",
			})
			edgesByNode[entryNode.ID] = append(edgesByNode[entryNode.ID], edgeID)
			edgesByNode[capNode.ID] = append(edgesByNode[capNode.ID], edgeID)
		}
		if okI {
			edgeID := "edge-" + capNode.ID + "-" + impNode.ID
			g.Edges = append(g.Edges, GraphEdge{
				ID:    edgeID,
				Class: class,
				D:     bezier(capNode.X+capNode.Width, capNode.Y+capNode.Height/2, impNode.X, impNode.Y+impNode.Height/2),
			})
			payload.Edges = append(payload.Edges, GraphEdgeDetail{
				ID:          edgeID,
				From:        capNode.ID,
				To:          impNode.ID,
				Class:       class,
				ActionLabel: "leads to",
			})
			edgesByNode[capNode.ID] = append(edgesByNode[capNode.ID], edgeID)
			edgesByNode[impNode.ID] = append(edgesByNode[impNode.ID], edgeID)
		}
	}

	// Build the per-node detail payload now that edge IDs are known. Glossary keys are derived
	// from the representative finding's Subject/Resource (for entries) or the rule's technique
	// (for capabilities). Categories carry their own explainer copy.
	for _, k := range entryKeys {
		e := entries[k]
		node := entryNodePos[k]
		gloss := ""
		if e.hasRep {
			if key := GlossaryKeyForSubject(e.representative.Subject); key != "" {
				gloss = key
			} else if key := GlossaryKeyForResource(e.representative.Resource); key != "" {
				gloss = key
			}
		}
		payload.Nodes = append(payload.Nodes, GraphNodeDetail{
			ID:          node.ID,
			Kind:        "entry",
			Severity:    e.SevClass,
			Title:       e.Title,
			Subtitle:    e.Subtitle,
			GlossaryKey: gloss,
			EntryKind:   e.entryKind,
			EdgeIDs:     edgesByNode[node.ID],
		})
	}
	for i, f := range caps {
		node := capNodes[i]
		hops := make([]HopView, 0, len(f.EscalationPath))
		for _, h := range f.EscalationPath {
			hops = append(hops, HopView{
				Step:         h.Step,
				From:         h.FromSubject.Key(),
				To:           h.ToSubject.Key(),
				Action:       h.Action,
				TechniqueKey: h.Action, // Techniques map is keyed by the same string
				Permission:   h.Permission,
				Gains:        h.Gains,
			})
		}
		payload.Nodes = append(payload.Nodes, GraphNodeDetail{
			ID:           node.ID,
			Kind:         "capability",
			Severity:     severityClass(f.Severity),
			Title:        f.Title,
			Subtitle:     fmt.Sprintf("score %.1f · %s", f.Score, categoryLabel(f.Category)),
			RuleID:       f.RuleID,
			TechniqueKey: TechniqueKeyForFinding(f),
			Description:  f.Description,
			Remediation:  f.Remediation,
			References:   append([]string(nil), f.References...),
			Hops:         hops,
			RiskCategory: string(f.Category),
			EdgeIDs:      edgesByNode[node.ID],
		})
	}
	for _, c := range impactKeys {
		node := impactNodePos[c]
		payload.Nodes = append(payload.Nodes, GraphNodeDetail{
			ID:           node.ID,
			Kind:         "impact",
			Severity:     "crit",
			Title:        impactLabel(c),
			Subtitle:     impactSubtitle(c),
			RiskCategory: string(c),
			EdgeIDs:      edgesByNode[node.ID],
		})
	}

	return g, payload
}

// bezier returns an SVG cubic-bezier path from (x1,y1) to (x2,y2) with horizontal tangents.
func bezier(x1, y1, x2, y2 int) string {
	dx := max((x2-x1)/2, 20)
	return fmt.Sprintf("M %d %d C %d %d, %d %d, %d %d", x1, y1, x1+dx, y1, x2-dx, y2, x2, y2)
}

// textCluster is one logical text-element (title, subtitle, etc.) inside a graph node.
// composeLines stacks clusters vertically using each cluster's leadIn (gap before its
// first baseline) and lineHeight (gap between baselines within the cluster).
type textCluster struct {
	class      string
	lineHeight int
	leadIn     int
	lines      []string
}

// composeLines flattens a stack of textClusters into rendered GraphTextLines and reports
// the total node height needed to fit them all (top edge to bottom padding).
// offsetX is the left text padding inside the node; bottomPad is the gap below the last baseline.
func composeLines(offsetX int, clusters []textCluster, bottomPad int) ([]GraphTextLine, int) {
	var lines []GraphTextLine
	y := 0
	for _, c := range clusters {
		if len(c.lines) == 0 {
			continue
		}
		y += c.leadIn
		for i, txt := range c.lines {
			if i > 0 {
				y += c.lineHeight
			}
			lines = append(lines, GraphTextLine{
				Class:   c.class,
				Text:    txt,
				OffsetX: offsetX,
				OffsetY: y,
			})
		}
	}
	return lines, y + bottomPad
}

// wrapForWidth splits s into one or more lines that fit within maxPx, using
// avgCharPx as a font-class-specific average glyph width. Lines break preferentially
// after spaces and identifier separators ('/', ':', '-', '.', ',') so wrapped
// resource paths stay readable. Long unbreakable runs are hard-cut at the column
// limit. SVG <text> has no auto-wrap, so this is what keeps long titles inside
// their box without losing characters (this tool is educational — full text matters).
func wrapForWidth(s string, maxPx int, avgCharPx float64) []string {
	if s == "" {
		return []string{""}
	}
	if avgCharPx <= 0 || maxPx <= 0 {
		return []string{s}
	}
	maxChars := max(int(float64(maxPx)/avgCharPx), 1)
	runes := []rune(s)
	if len(runes) <= maxChars {
		return []string{s}
	}
	isBreak := func(r rune) bool {
		switch r {
		case ' ', '/', ':', '-', '.', ',':
			return true
		}
		return false
	}
	var lines []string
	start := 0
	for start < len(runes) {
		if len(runes)-start <= maxChars {
			lines = append(lines, strings.TrimLeft(string(runes[start:]), " "))
			break
		}
		end := start + maxChars
		breakAt := -1
		for i := end; i > start; i-- {
			if isBreak(runes[i-1]) {
				breakAt = i
				break
			}
		}
		if breakAt <= start {
			breakAt = end
		}
		line := strings.TrimRight(string(runes[start:breakAt]), " ")
		lines = append(lines, strings.TrimLeft(line, " "))
		// Skip leading spaces on next line; other separators stay attached to whichever side they belong on.
		for breakAt < len(runes) && runes[breakAt] == ' ' {
			breakAt++
		}
		start = breakAt
	}
	if len(lines) == 0 {
		lines = []string{s}
	}
	return lines
}
