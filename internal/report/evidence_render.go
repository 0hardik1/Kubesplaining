// Package report — humanized rendering of Finding.Evidence and Finding.EscalationPath
// for the static Findings tab. The analyzer-emitted Evidence payload is a small
// `map[string]any` per rule; rather than show it as raw JSON (opaque to a Kubernetes
// newcomer), we walk the known keys and render them as labeled rows with chips and
// glossary hints. Unknown keys fall back to inline JSON, so future analyzers degrade
// gracefully without code changes here.
//
// All HTML is built via html/template's HTMLEscapeString — no template.HTML is ever
// constructed from analyzer-supplied content. This matches the safety pattern in
// renderInlineCode / renderParagraphs.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/0hardik1/kubesplaining/internal/models"
)

var titleCaser = cases.Title(language.English)

// renderEvidence parses Evidence (an analyzer-emitted JSON object) and renders a
// labeled grid with semantic formatting per known key. Returns "" when the payload
// is empty or not a JSON object — the caller still emits a "Show raw JSON" details
// element below this, so structural surprises are still inspectable.
func renderEvidence(raw json.RawMessage) template.HTML {
	if len(raw) == 0 {
		return ""
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	obj, ok := payload.(map[string]any)
	if !ok || len(obj) == 0 {
		return ""
	}

	var rows strings.Builder
	for _, key := range orderedEvidenceKeys(obj) {
		val := obj[key]
		row := renderEvidenceRow(key, val, obj)
		if row != "" {
			rows.WriteString(row)
		}
	}
	if rows.Len() == 0 {
		return ""
	}
	return template.HTML(`<div class="ev-grid">` + rows.String() + `</div>`)
}

// orderedEvidenceKeys returns the keys of obj in a stable, semantically meaningful
// order. Known keys come first in a curated sequence (so the most informative fields
// lead), followed by any unknown keys sorted alphabetically.
func orderedEvidenceKeys(obj map[string]any) []string {
	priority := []string{
		// Subject identity & scope
		"scope", "namespace",
		// RBAC permission shape
		"api_groups", "resources", "verbs",
		// Where the permission came from
		"source_role", "source_binding",
		// Pod-security observations
		"container", "image", "service_account",
		"hostNetwork", "hostPID", "hostIPC", "privileged", "allowPrivilegeEscalation", "runAsNonRoot",
		"volume", "path",
		// Network policy
		"policy", "cidr", "labels",
		// Admission
		"failurePolicy", "objectSelector", "namespaceSelector", "rules",
		// Secrets / configmap
		"type", "matched_keys", "name",
		// ServiceAccount aggregations
		"workloads", "dangerous_permissions",
	}
	// privesc summary keys are deliberately suppressed here — the EscalationPath
	// renderer below is more readable and carries the same information.
	suppressed := map[string]bool{
		"target":        true,
		"hop_count":     true,
		"techniques":    true,
		"first_action":  true,
		"chain_summary": true,
	}

	seen := map[string]bool{}
	var out []string
	for _, k := range priority {
		if _, ok := obj[k]; ok && !suppressed[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range obj {
		if seen[k] || suppressed[k] {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// renderEvidenceRow dispatches on key to a per-key renderer. The full obj is passed
// because some renderers (hostPath / volume) want sibling fields for context.
func renderEvidenceRow(key string, val any, obj map[string]any) string {
	switch key {
	case "verbs":
		return chipRow("Verbs", toStringSlice(val), verbHint, true)
	case "resources":
		return chipRow("Resources", toStringSlice(val), resourceHint, true)
	case "api_groups":
		return apiGroupRow(toStringSlice(val))
	case "source_role":
		return kubectlRow("Source role", asString(val), sourceRoleCmd(asString(val), obj))
	case "source_binding":
		return kubectlRow("Source binding", asString(val), sourceBindingCmd(asString(val), obj))
	case "scope":
		return plainRow("Scope", titleCaser.String(asString(val)), "")
	case "namespace":
		return codeRow("Namespace", asString(val))
	case "container":
		return codeRow("Container", asString(val))
	case "image":
		img := asString(val)
		return plainRow("Image", img, mutableImageHint(img))
	case "service_account":
		return codeRow("ServiceAccount", asString(val))
	case "hostNetwork", "hostPID", "hostIPC", "privileged",
		"allowPrivilegeEscalation", "runAsNonRoot":
		return boolRow(key, val)
	case "volume":
		return codeRow("Volume", asString(val))
	case "path":
		p := asString(val)
		return plainRow("Host path", "<code>"+template.HTMLEscapeString(p)+"</code>", hostPathHint(p))
	case "policy":
		return codeRow("Policy", asString(val))
	case "cidr":
		c := asString(val)
		return plainRow("CIDR", "<code>"+template.HTMLEscapeString(c)+"</code>", cidrHint(c))
	case "labels":
		return labelsRow("Labels", val)
	case "failurePolicy":
		fp := asString(val)
		hint := ""
		if strings.EqualFold(fp, "Ignore") {
			hint = "Webhook failures are silently allowed (admission policy effectively off)"
		}
		return plainRow("failurePolicy", "<code>"+template.HTMLEscapeString(fp)+"</code>", hint)
	case "objectSelector":
		return selectorRow("objectSelector", val)
	case "namespaceSelector":
		return selectorRow("namespaceSelector", val)
	case "rules":
		// Two distinct shapes produce a "rules" key:
		//   - admission webhook RuleWithOperations objects (have apiGroups/operations/resources)
		//   - serviceaccount EffectiveRule summaries (have verbs/resources/api_groups + source_*)
		// We sniff the first element to decide.
		if isEffectiveRuleSlice(val) {
			return effectiveRulesRow(val)
		}
		return admissionRulesRow(val)
	case "type":
		t := asString(val)
		return plainRow("Type", "<code>"+template.HTMLEscapeString(t)+"</code>", secretTypeLabelDelta(t))
	case "matched_keys":
		return chipRow("Matched keys", toStringSlice(val), nil, false)
	case "name":
		return codeRow("Name", asString(val))
	case "workloads":
		return workloadsRow(val)
	case "dangerous_permissions":
		return dangerChipRow("Dangerous permissions", toStringSlice(val))
	}
	return jsonFallbackRow(key, val)
}

// secretTypeLabelDelta returns the friendly label for a Secret type, or "" when the
// type is already self-explanatory (i.e. the lookup returns the input unchanged).
func secretTypeLabelDelta(t string) string {
	label := secretTypeLabel(t)
	if label == t {
		return ""
	}
	return label
}

// renderEscalationPath emits a numbered ordered list of step cards describing the
// per-hop chain from the source subject to the privesc sink. Each card surfaces the
// human-readable technique title and a one-paragraph explainer from the Techniques
// glossary so a reader who has never seen the slug (`impersonate`, `wildcard_permission`)
// learns what it means in place. Returns "" for empty input so the template
// `{{ if … }}` gate can suppress the whole section.
//
// The "Step N of M" prefix is omitted for single-hop chains — there is no chain to
// follow, so numbering reads as ceremony.
func renderEscalationPath(hops []models.EscalationHop) template.HTML {
	if len(hops) == 0 {
		return ""
	}
	total := len(hops)
	var b strings.Builder
	b.WriteString(`<ol class="attack-chain">`)
	for _, hop := range hops {
		b.WriteString(`<li class="attack-step">`)

		expl, hasExpl := Techniques[hop.Action]
		title := expl.Title
		if title == "" {
			title = hop.Action
		}

		b.WriteString(`<div class="step-hd">`)
		if total > 1 {
			b.WriteString(`<span class="step-num">Step `)
			fmt.Fprintf(&b, "%d of %d", hop.Step, total)
			b.WriteString(`</span> `)
		}
		b.WriteString(`<span class="step-title">`)
		b.WriteString(template.HTMLEscapeString(title))
		b.WriteString(`</span>`)
		if hop.Action != "" && hop.Action != title {
			b.WriteString(` <code class="step-action">`)
			b.WriteString(template.HTMLEscapeString(hop.Action))
			b.WriteString(`</code>`)
		}
		b.WriteString(`</div>`)

		if hasExpl && expl.Plain != "" {
			b.WriteString(`<div class="step-explainer">`)
			b.WriteString(string(expl.Plain))
			b.WriteString(`</div>`)
		}

		from := subjectKey(hop.FromSubject)
		to := subjectKey(hop.ToSubject)
		if from != "" || to != "" {
			b.WriteString(`<div class="step-edge">`)
			if from != "" {
				b.WriteString(`From <code>`)
				b.WriteString(template.HTMLEscapeString(from))
				b.WriteString(`</code>`)
			}
			if to != "" {
				if from != "" {
					b.WriteString(` → `)
				}
				b.WriteString(`<code>`)
				b.WriteString(template.HTMLEscapeString(to))
				b.WriteString(`</code>`)
			}
			b.WriteString(`</div>`)
		}

		if hop.Permission != "" {
			b.WriteString(`<div class="step-meta"><span class="k">Permission granted</span> <code>`)
			b.WriteString(template.HTMLEscapeString(hop.Permission))
			b.WriteString(`</code></div>`)
		}
		if hop.Gains != "" {
			b.WriteString(`<div class="step-meta"><span class="k">Gives the attacker</span> <span class="v">`)
			b.WriteString(template.HTMLEscapeString(hop.Gains))
			b.WriteString(`</span></div>`)
		}
		b.WriteString(`</li>`)
	}
	b.WriteString(`</ol>`)
	return template.HTML(b.String())
}

// subjectKey returns "Kind/[namespace/]name" or "" when the SubjectRef is empty.
// Empty subjects show up at the tail of escalation paths where the hop terminates
// at a synthetic sink (cluster_admin, node_escape) rather than another subject.
func subjectKey(s models.SubjectRef) string {
	if s.Kind == "" && s.Name == "" {
		return ""
	}
	if s.Namespace == "" {
		return fmt.Sprintf("%s/%s", s.Kind, s.Name)
	}
	return fmt.Sprintf("%s/%s/%s", s.Kind, s.Namespace, s.Name)
}

// chipRow renders a labeled list of chips. If hint is non-nil and returns a non-empty
// string for a chip's value, that chip gets a tooltip and a small inline hint badge
// below the row. When dangerOnWildcard is true, "*" chips render with the .wild class.
func chipRow(label string, values []string, hint func(string) string, dangerOnWildcard bool) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="ev-val">`)
	var hints []string
	for _, v := range values {
		class := "ev-chip"
		h := ""
		if hint != nil {
			h = hint(v)
		}
		if dangerOnWildcard && v == "*" {
			class += " wild"
			if h == "" {
				h = "Wildcard: every value"
			}
		} else if h != "" {
			class += " danger"
		}
		b.WriteString(`<span class="`)
		b.WriteString(class)
		if h != "" {
			b.WriteString(`" title="`)
			b.WriteString(template.HTMLEscapeString(h))
		}
		b.WriteString(`">`)
		b.WriteString(template.HTMLEscapeString(v))
		b.WriteString(`</span>`)
		if h != "" {
			hints = append(hints, fmt.Sprintf("<code>%s</code>: %s",
				template.HTMLEscapeString(v), template.HTMLEscapeString(h)))
		}
	}
	b.WriteString(`</span>`)
	if len(hints) > 0 {
		b.WriteString(`<div class="ev-hints">`)
		for _, h := range hints {
			b.WriteString(`<div class="ev-hint">`)
			b.WriteString(h)
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// dangerChipRow renders a chip list always styled as "danger" — used for the
// already-pre-flagged "dangerous_permissions" payload from the serviceaccount module.
func dangerChipRow(label string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="ev-val">`)
	for _, v := range values {
		b.WriteString(`<span class="ev-chip danger">`)
		b.WriteString(template.HTMLEscapeString(v))
		b.WriteString(`</span>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

// apiGroupRow special-cases the empty-string core group (renders as "core/v1") and
// adds glossary hints for known sensitive groups.
func apiGroupRow(values []string) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">API groups</span><span class="ev-val">`)
	var hints []string
	for _, v := range values {
		display := v
		if v == "" {
			display = "core/v1"
		}
		class := "ev-chip"
		h := apiGroupHint(v)
		if v == "*" {
			class += " wild"
		} else if h != "" {
			class += " danger"
		}
		b.WriteString(`<span class="`)
		b.WriteString(class)
		if h != "" {
			b.WriteString(`" title="`)
			b.WriteString(template.HTMLEscapeString(h))
		}
		b.WriteString(`">`)
		b.WriteString(template.HTMLEscapeString(display))
		b.WriteString(`</span>`)
		if h != "" {
			hints = append(hints, fmt.Sprintf("<code>%s</code>: %s",
				template.HTMLEscapeString(display), template.HTMLEscapeString(h)))
		}
	}
	b.WriteString(`</span>`)
	if len(hints) > 0 {
		b.WriteString(`<div class="ev-hints">`)
		for _, h := range hints {
			b.WriteString(`<div class="ev-hint">`)
			b.WriteString(h)
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// plainRow emits "Label: value" with an optional hint line below. value is HTML —
// callers must escape any analyzer-supplied content before passing it in.
func plainRow(label, valueHTML, hint string) string {
	if valueHTML == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="ev-val">`)
	b.WriteString(valueHTML)
	b.WriteString(`</span>`)
	if hint != "" {
		b.WriteString(`<div class="ev-hint">`)
		b.WriteString(template.HTMLEscapeString(hint))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// codeRow emits "Label: <code>value</code>" — the default for short identifiers.
func codeRow(label, value string) string {
	if value == "" {
		return ""
	}
	return plainRow(label, "<code>"+template.HTMLEscapeString(value)+"</code>", "")
}

// kubectlRow emits a code-styled value plus a small inline kubectl command the user
// can run to inspect the referenced object. Generated commands are static strings
// over user-controlled names, so we escape the embedded value defensively.
func kubectlRow(label, value, kubectl string) string {
	if value == "" {
		return ""
	}
	hint := ""
	if kubectl != "" {
		hint = "Inspect: " + kubectl
	}
	return plainRow(label, "<code>"+template.HTMLEscapeString(value)+"</code>", hint)
}

// boolRow emits a labeled true/false badge with a one-line meaning hint when known.
func boolRow(key string, val any) string {
	bv, ok := val.(bool)
	if !ok {
		// Some analyzers might emit "true"/"false" strings; coerce.
		if s, isStr := val.(string); isStr {
			bv = strings.EqualFold(s, "true")
			ok = true
		}
	}
	if !ok {
		return jsonFallbackRow(key, val)
	}
	state := "false"
	class := "ev-chip"
	if bv {
		state = "true"
		class += " danger"
	}
	hint := ""
	if bv {
		hint = hostNamespaceHint(key)
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(key))
	b.WriteString(`</span><span class="ev-val"><span class="`)
	b.WriteString(class)
	b.WriteString(`">`)
	b.WriteString(state)
	b.WriteString(`</span></span>`)
	if hint != "" {
		b.WriteString(`<div class="ev-hint">`)
		b.WriteString(template.HTMLEscapeString(hint))
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// labelsRow renders a Kubernetes label map (key → value) as chip pairs.
func labelsRow(label string, val any) string {
	m, ok := val.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="ev-val">`)
	for _, k := range keys {
		v := fmt.Sprint(m[k])
		b.WriteString(`<span class="ev-chip">`)
		b.WriteString(template.HTMLEscapeString(k))
		b.WriteString(`=`)
		b.WriteString(template.HTMLEscapeString(v))
		b.WriteString(`</span>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

// selectorRow translates a Kubernetes LabelSelector (matchLabels / matchExpressions)
// into one or more plain-English sentences. Falls back to JSON if the structure
// doesn't look like a standard selector.
func selectorRow(label string, val any) string {
	m, ok := val.(map[string]any)
	if !ok {
		return jsonFallbackRow(label, val)
	}
	if len(m) == 0 {
		return plainRow(label, "<code>{}</code>", "Empty selector: matches everything")
	}
	var sentences []string
	if ml, ok := m["matchLabels"].(map[string]any); ok && len(ml) > 0 {
		keys := make([]string, 0, len(ml))
		for k := range ml {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sentences = append(sentences, fmt.Sprintf("label <code>%s</code> = <code>%s</code>",
				template.HTMLEscapeString(k), template.HTMLEscapeString(fmt.Sprint(ml[k]))))
		}
	}
	if me, ok := m["matchExpressions"].([]any); ok {
		for _, raw := range me {
			expr, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			key := asString(expr["key"])
			op := asString(expr["operator"])
			values := toStringSlice(expr["values"])
			sentences = append(sentences, expressionSentence(key, op, values))
		}
	}
	if len(sentences) == 0 {
		return jsonFallbackRow(label, val)
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="ev-val ev-stack">`)
	for _, s := range sentences {
		b.WriteString(`<div class="ev-sentence">`)
		b.WriteString(s)
		b.WriteString(`</div>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

// expressionSentence turns a matchExpression {key, operator, values} into prose.
// Values are HTML-escaped; the result is HTML.
func expressionSentence(key, op string, values []string) string {
	keyHTML := "<code>" + template.HTMLEscapeString(key) + "</code>"
	switch strings.ToLower(op) {
	case "exists":
		return "label " + keyHTML + " exists"
	case "doesnotexist":
		return "label " + keyHTML + " is absent"
	case "in":
		return "label " + keyHTML + " is one of [" + chipsInline(values) + "]"
	case "notin":
		return "label " + keyHTML + " is NOT one of [" + chipsInline(values) + "]"
	default:
		return template.HTMLEscapeString(op) + " " + keyHTML + " [" + chipsInline(values) + "]"
	}
}

func chipsInline(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, "<code>"+template.HTMLEscapeString(v)+"</code>")
	}
	return strings.Join(parts, ", ")
}

// admissionRulesRow renders MutatingWebhookConfig RuleWithOperations entries.
func admissionRulesRow(val any) string {
	arr, ok := val.([]any)
	if !ok || len(arr) == 0 {
		return jsonFallbackRow("rules", val)
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">Webhook rules</span><span class="ev-val ev-stack">`)
	for _, raw := range arr {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ops := toStringSlice(m["operations"])
		groups := toStringSlice(m["apiGroups"])
		versions := toStringSlice(m["apiVersions"])
		resources := toStringSlice(m["resources"])
		b.WriteString(`<div class="ev-sentence">`)
		if len(ops) > 0 {
			b.WriteString(`<strong>` + template.HTMLEscapeString(strings.Join(ops, ", ")) + `</strong> on `)
		}
		joined := joinGVR(groups, versions, resources)
		b.WriteString(`<code>` + template.HTMLEscapeString(joined) + `</code>`)
		if scope := asString(m["scope"]); scope != "" {
			b.WriteString(` <span class="ev-mut">(` + template.HTMLEscapeString(scope) + `)</span>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

func joinGVR(groups, versions, resources []string) string {
	g := "*"
	if len(groups) > 0 {
		g = strings.Join(groups, ",")
		if g == "" {
			g = "core"
		}
	}
	v := "*"
	if len(versions) > 0 {
		v = strings.Join(versions, ",")
	}
	r := "*"
	if len(resources) > 0 {
		r = strings.Join(resources, ",")
	}
	return g + "/" + v + ":" + r
}

// isEffectiveRuleSlice sniffs whether a "rules" payload looks like the serviceaccount
// EffectiveRule summary (verbs+resources+source_role) vs the admission RuleWithOperations
// shape (operations+apiGroups+apiVersions).
func isEffectiveRuleSlice(val any) bool {
	arr, ok := val.([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	first, ok := arr[0].(map[string]any)
	if !ok {
		return false
	}
	_, hasVerbs := first["verbs"]
	_, hasSourceRole := first["source_role"]
	return hasVerbs && hasSourceRole
}

// effectiveRulesRow renders the serviceaccount module's EffectiveRule summary as a
// compact permissions table.
func effectiveRulesRow(val any) string {
	arr, ok := val.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">Effective rules</span><span class="ev-val ev-stack">`)
	for _, raw := range arr {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		verbs := toStringSlice(m["verbs"])
		resources := toStringSlice(m["resources"])
		groups := toStringSlice(m["api_groups"])
		ns := asString(m["namespace"])
		role := asString(m["source_role"])
		binding := asString(m["source_binding"])

		b.WriteString(`<div class="ev-rule">`)
		b.WriteString(`<div class="ev-rule-head">`)
		b.WriteString(renderChips(verbs, verbHint, true))
		b.WriteString(` on `)
		b.WriteString(renderChips(resources, resourceHint, true))
		if len(groups) > 0 {
			b.WriteString(` in <code>`)
			b.WriteString(template.HTMLEscapeString(strings.Join(groups, ",")))
			b.WriteString(`</code>`)
		}
		b.WriteString(`</div>`)
		b.WriteString(`<div class="ev-rule-meta">via <code>`)
		b.WriteString(template.HTMLEscapeString(role))
		b.WriteString(`</code> (binding <code>`)
		b.WriteString(template.HTMLEscapeString(binding))
		b.WriteString(`</code>)`)
		if ns != "" {
			b.WriteString(` in namespace <code>`)
			b.WriteString(template.HTMLEscapeString(ns))
			b.WriteString(`</code>`)
		} else {
			b.WriteString(` <span class="ev-mut">(cluster scope)</span>`)
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

// renderChips emits an inline run of chips (no row wrapper) for use inside other rows.
func renderChips(values []string, hint func(string) string, dangerOnWildcard bool) string {
	var b strings.Builder
	for _, v := range values {
		class := "ev-chip"
		h := ""
		if hint != nil {
			h = hint(v)
		}
		if dangerOnWildcard && v == "*" {
			class += " wild"
		} else if h != "" {
			class += " danger"
		}
		b.WriteString(`<span class="`)
		b.WriteString(class)
		if h != "" {
			b.WriteString(`" title="`)
			b.WriteString(template.HTMLEscapeString(h))
		}
		b.WriteString(`">`)
		b.WriteString(template.HTMLEscapeString(v))
		b.WriteString(`</span>`)
	}
	return b.String()
}

// workloadsRow lists workload references with a kubectl inspect hint.
func workloadsRow(val any) string {
	arr, ok := val.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row"><span class="ev-key">Workloads</span><span class="ev-val ev-stack">`)
	for _, raw := range arr {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		kind := asString(m["kind"])
		name := asString(m["name"])
		ns := asString(m["namespace"])
		display := name
		if kind != "" {
			display = kind + "/" + name
		}
		b.WriteString(`<div class="ev-sentence"><code>`)
		b.WriteString(template.HTMLEscapeString(display))
		b.WriteString(`</code>`)
		if ns != "" {
			b.WriteString(` in namespace <code>`)
			b.WriteString(template.HTMLEscapeString(ns))
			b.WriteString(`</code>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</span></div>`)
	return b.String()
}

// jsonFallbackRow prints "Label: <pre>json</pre>" for any unknown shape.
func jsonFallbackRow(key string, val any) string {
	pretty, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="ev-row ev-row-block"><span class="ev-key">`)
	b.WriteString(template.HTMLEscapeString(key))
	b.WriteString(`</span><pre class="ev-json"><code>`)
	b.WriteString(template.HTMLEscapeString(string(pretty)))
	b.WriteString(`</code></pre></div>`)
	return b.String()
}

// asString coerces an interface{} value (string, fmt.Stringer, anything) to string.
func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// toStringSlice coerces a JSON-decoded []any into []string. Non-string elements are
// rendered via fmt.Sprint. Returns nil for non-slice input.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, fmt.Sprint(item))
		}
		return out
	}
	return nil
}

// sourceRoleCmd builds a kubectl command to inspect the role that granted the
// permission. Cluster-scoped (no namespace) → clusterrole, otherwise → role -n ns.
func sourceRoleCmd(name string, obj map[string]any) string {
	if name == "" {
		return ""
	}
	ns := asString(obj["namespace"])
	scope := strings.ToLower(asString(obj["scope"]))
	if scope == "cluster" || ns == "" {
		return "kubectl get clusterrole " + name + " -o yaml"
	}
	return "kubectl get role " + name + " -n " + ns + " -o yaml"
}

// sourceBindingCmd builds the parallel kubectl command for the binding.
func sourceBindingCmd(name string, obj map[string]any) string {
	if name == "" {
		return ""
	}
	ns := asString(obj["namespace"])
	scope := strings.ToLower(asString(obj["scope"]))
	if scope == "cluster" || ns == "" {
		return "kubectl get clusterrolebinding " + name + " -o yaml"
	}
	return "kubectl get rolebinding " + name + " -n " + ns + " -o yaml"
}
