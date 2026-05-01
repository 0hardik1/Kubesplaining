// Package report — auto-generated attack-chain narratives. Detects well-known multi-rule
// chains in the finding set and emits NarrativeCards (plain-English walkthroughs) for the
// HTML report. Also provides the headline copy that summarizes the overall posture.
package report

import (
	"fmt"
	"html/template"
	"slices"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildNarratives auto-detects well-known attack chains from finding rule_ids and returns plain-English
// walkthroughs to help first-time readers see how individual findings compose into exploit paths.
func buildNarratives(findings []models.Finding) []NarrativeCard {
	narratives := make([]NarrativeCard, 0, 4)

	index := map[string][]models.Finding{}
	for _, f := range findings {
		index[f.RuleID] = append(index[f.RuleID], f)
	}

	// Chain 1: Node root / container escape.
	nodeEscapeRules := []string{"KUBE-ESCAPE-001", "KUBE-ESCAPE-006", "KUBE-ESCAPE-004", "KUBE-ESCAPE-005"}
	nodeEscapeHits := map[string]bool{}
	nodeEscapeResources := map[string]bool{}
	for _, rule := range nodeEscapeRules {
		for _, f := range index[rule] {
			nodeEscapeHits[rule] = true
			if f.Resource != nil {
				nodeEscapeResources[f.Resource.Key()] = true
			}
		}
	}
	if len(nodeEscapeHits) > 0 {
		resList := sortedKeys(nodeEscapeResources)
		sev := "HIGH"
		if nodeEscapeHits["KUBE-ESCAPE-001"] || nodeEscapeHits["KUBE-ESCAPE-006"] {
			sev = "CRITICAL"
		}
		steps := []NarrativeStep{
			subjectListStep("An attacker gains code execution in a workload co-scheduled with, or targeting, one of:",
				"An attacker gains code execution in a workload co-scheduled with, or targeting, %s.", resList),
			{Text: "The workload is configured to trust the host in one or more ways. Privileged mode grants all capabilities; a hostPath of / mounts the node's root filesystem; hostPID/hostIPC share the host's process and IPC namespaces."},
			{Text: "Any one of these alone is enough for a straightforward container escape: write into the host filesystem, exec through /proc/1, or interact with the kubelet's unix socket."},
			{Text: "From there, the attacker reads projected tokens for every other pod on the node and pivots into the cluster with those identities."},
		}
		narratives = append(narratives, NarrativeCard{
			Title:    "Privileged workload → node root",
			Severity: sev,
			Steps:    steps,
			RuleIDs:  presentRules(index, nodeEscapeRules),
		})
	}

	// Chain 2: Cluster-admin impersonation via over-permissioned SAs.
	impersonationRules := []string{"KUBE-PRIVESC-001", "KUBE-PRIVESC-005"}
	subjects := map[string]map[string]bool{}
	for _, rule := range impersonationRules {
		for _, f := range index[rule] {
			if f.Subject == nil {
				continue
			}
			key := f.Subject.Key()
			if subjects[key] == nil {
				subjects[key] = map[string]bool{}
			}
			subjects[key][rule] = true
		}
	}
	var dualSubjects []string
	for sub, hits := range subjects {
		if len(hits) == len(impersonationRules) {
			dualSubjects = append(dualSubjects, sub)
		}
	}
	sort.Strings(dualSubjects)
	if len(dualSubjects) > 0 {
		steps := []NarrativeStep{
			subjectListStep("The attacker lands on a workload that mounts one of the following service accounts (or phishes a kubeconfig bound to one):",
				"The attacker lands on a workload that mounts %s, or phishes a kubeconfig bound to it.", dualSubjects),
			{Text: "That identity holds cluster-wide get/list on secrets, which includes service-account tokens in every namespace. The attacker lists kube-system secrets and reads tokens belonging to powerful controllers."},
			{Text: "Even without the token read, the same identity can create pods cluster-wide. The attacker schedules a pod that mounts the target service account, execs in, and acts as it."},
			{Text: "Either path converges on a cluster-admin-equivalent identity; all policies, secrets, and workloads are now under attacker control."},
		}
		narratives = append(narratives, NarrativeCard{
			Title:    "Token theft → cluster-admin impersonation",
			Severity: "CRITICAL",
			Steps:    steps,
			RuleIDs:  presentRules(index, impersonationRules),
		})
	}

	// Chain 3: Admission-gate bypass — enforcement silently missing.
	admissionRules := []string{"KUBE-ADMISSION-001", "KUBE-ADMISSION-002", "KUBE-ADMISSION-003"}
	presentAdmission := presentRules(index, admissionRules)
	if len(presentAdmission) > 0 {
		steps := []NarrativeStep{}
		if slices.Contains(presentAdmission, "KUBE-ADMISSION-001") {
			steps = append(steps, NarrativeStep{Text: "The webhook that should block dangerous pods fails open: failurePolicy: Ignore means any backend outage (or a targeted denial-of-service) silently disables enforcement for the window the attacker needs."})
		}
		if slices.Contains(presentAdmission, "KUBE-ADMISSION-003") {
			steps = append(steps, NarrativeStep{Text: "Its namespace selector excludes at least one sensitive namespace, so workloads placed there skip admission entirely."})
		}
		if slices.Contains(presentAdmission, "KUBE-ADMISSION-002") {
			steps = append(steps, NarrativeStep{Text: "The webhook keys off a workload-controlled label. Omit the label and admission doesn't apply."})
		}
		steps = append(steps, NarrativeStep{Text: "Any one of the above is a full bypass of the admission gate you thought was catching misconfigurations. In practice, this means every other chain in this report becomes easier to execute."})
		narratives = append(narratives, NarrativeCard{
			Title:    "Admission gap → silent enforcement bypass",
			Severity: "HIGH",
			Steps:    steps,
			RuleIDs:  presentAdmission,
		})
	}

	// Chain 4: Flat network → unrestricted lateral reach.
	networkRules := []string{"KUBE-NETPOL-COVERAGE-001", "KUBE-NETPOL-WEAKNESS-001", "KUBE-NETPOL-WEAKNESS-002"}
	presentNetwork := presentRules(index, networkRules)
	if len(presentNetwork) > 0 {
		steps := []NarrativeStep{}
		if slices.Contains(presentNetwork, "KUBE-NETPOL-COVERAGE-001") {
			steps = append(steps, NarrativeStep{Text: "Namespaces with no NetworkPolicies treat every pod as reachable from every other pod. There is no default-deny, so a compromised workload can reach every service on every pod."})
		}
		if slices.Contains(presentNetwork, "KUBE-NETPOL-WEAKNESS-001") {
			steps = append(steps, NarrativeStep{Text: "An allow-from-all-namespaces policy is effectively no policy: traffic from any namespace matches, including attacker-controlled namespaces."})
		}
		if slices.Contains(presentNetwork, "KUBE-NETPOL-WEAKNESS-002") {
			steps = append(steps, NarrativeStep{Text: "Egress 0.0.0.0/0 gives the attacker free outbound reach. Stolen tokens, secrets, and staging data leave the cluster with nothing in the way."})
		}
		steps = append(steps, NarrativeStep{Text: "Combined, the attacker sweeps every pod in the cluster for vulnerable services and exfiltrates data without tripping a segmentation boundary."})
		narratives = append(narratives, NarrativeCard{
			Title:    "Flat network → unrestricted lateral reach",
			Severity: "HIGH",
			Steps:    steps,
			RuleIDs:  presentNetwork,
		})
	}

	return narratives
}

// buildHeadline returns a data-driven h1 string and the short prose that sits under it.
// The prose is returned as template.HTML because it contains safe, pre-escaped <strong> and <code> markup.
func buildHeadline(s Summary, narratives []NarrativeCard, ns []Hotspot) (string, template.HTML) {
	criticalChains := 0
	for _, n := range narratives {
		if n.Severity == "CRITICAL" {
			criticalChains++
		}
	}

	var headline string
	switch {
	case criticalChains >= 2:
		headline = fmt.Sprintf("%d independent paths to full cluster takeover", criticalChains)
	case criticalChains == 1:
		headline = "1 path to full cluster takeover detected"
	case s.Critical > 0:
		headline = fmt.Sprintf("%d critical findings require immediate attention", s.Critical)
	case s.High > 0:
		headline = fmt.Sprintf("%d high-severity findings across the cluster", s.High)
	case s.Total > 0:
		headline = fmt.Sprintf("%d findings across the cluster", s.Total)
	default:
		headline = "No findings in this scan"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d findings across %d %s.", s.Total, len(narratives), pluralizeSimple(len(narratives), "chain", "chains"))
	if len(ns) > 0 {
		fmt.Fprintf(&b, " Concentration: <strong>%d</strong> in <code>%s</code>",
			ns[0].Summary.Total, template.HTMLEscapeString(ns[0].Label))
		if len(ns) > 1 {
			fmt.Fprintf(&b, ", <strong>%d</strong> in <code>%s</code>",
				ns[1].Summary.Total, template.HTMLEscapeString(ns[1].Label))
		}
		b.WriteString(".")
	}
	return headline, template.HTML(b.String())
}

// presentRules returns the subset of wanted rule IDs that actually have findings in index, preserving wanted order.
func presentRules(index map[string][]models.Finding, wanted []string) []string {
	out := make([]string, 0, len(wanted))
	for _, r := range wanted {
		if len(index[r]) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// sortedKeys returns the sorted keys of a string-keyed set.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// subjectListStep renders a narrative step that injects a list of subjects/resources.
// For 1–2 items it stays inline as natural prose (proseFmt is a Sprintf template with one %s).
// For 3+ items it switches to a lead-in sentence (listLead) plus a bulleted sublist, capped
// to keep the card compact even with thousands of subjects in a real cluster.
func subjectListStep(listLead, proseFmt string, items []string) NarrativeStep {
	const cap = 5
	if len(items) <= 2 {
		var inline string
		switch len(items) {
		case 0:
			inline = ""
		case 1:
			inline = items[0]
		case 2:
			inline = items[0] + " or " + items[1]
		}
		return NarrativeStep{Text: fmt.Sprintf(proseFmt, inline)}
	}
	if len(items) <= cap {
		return NarrativeStep{Text: listLead, Items: items}
	}
	out := append([]string{}, items[:cap]...)
	out = append(out, fmt.Sprintf("…and %d more", len(items)-cap))
	return NarrativeStep{Text: listLead, Items: out}
}

// pluralizeSimple picks the right word form by count; used when a template func can't be used.
func pluralizeSimple(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
