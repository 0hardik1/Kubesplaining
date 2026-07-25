package remediation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
)

// ForRBACOverbroad returns the structured remediation for KUBE-RBAC-OVERBROAD-001
// (a wildcard `*:*:*` rule, or a cluster-admin binding equivalent). The fix is
// not deletion of the binding outright (operators almost always have *some*
// permission they actually need), but replacement of the wildcard rule with a
// placeholder allowlist plus a clear comment that the user must populate the
// real verbs / resources their workload needs.
//
// The Patch field is a strategic-merge patch against the (Cluster)Role; the
// RBACDiff field is a hand-rolled unified diff of the same change so the HTML
// report has something to render even when JSON consumers prefer the structured
// patch.
//
// Returns nil when the finding is not a wildcard RBAC finding (RuleID mismatch)
// or when there isn't enough evidence on the finding to identify the role :
// the analyzer might emit a fallback shape and we'd rather degrade gracefully
// than crash on unknown evidence keys.
func ForRBACOverbroad(finding models.Finding, _ models.Snapshot) *models.RemediationHint {
	if finding.RuleID != "KUBE-RBAC-OVERBROAD-001" {
		return nil
	}
	roleKind, roleName, namespace := rbacTargetFromEvidence(finding)
	if roleName == "" {
		return nil
	}
	target := models.PatchTarget{
		Kind:       roleKind,
		APIVersion: "rbac.authorization.k8s.io/v1",
		Name:       roleName,
		Namespace:  namespace,
	}
	body, command := wildcardReplacementPatch(target)
	hint := &models.RemediationHint{
		Patch: &models.KubectlPatch{
			Type:    "strategic",
			Target:  target,
			Body:    body,
			Command: command,
		},
		RBACDiff: wildcardReplacementDiff(roleKind, roleName, namespace),
	}
	return hint
}

// wildcardReplacementPatch returns the JSON body and the pre-rendered kubectl
// command for swapping a wildcard rule out for a placeholder least-privilege
// allowlist. Callers fill in the actual verbs / resources their workload needs;
// we emit `pods get,list` because almost every workload needs at least that
// and it gives the patch a non-trivial worked example.
//
// Note: a strategic-merge patch against `rules:` is *replacive* for the array
// (kubectl replaces the entire rules list rather than merging element-by-
// element). That's what we want here: the goal is to wipe the wildcard, not
// to add a peer rule alongside it.
func wildcardReplacementPatch(_ models.PatchTarget) (json.RawMessage, string) {
	payload := map[string]any{
		"rules": []map[string]any{
			{
				"apiGroups": []string{""},
				"resources": []string{"pods"},
				"verbs":     []string{"get", "list"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	command := "# Replace the placeholder verbs / resources with the minimum your workload actually needs.\n" +
		"kubectl patch clusterrole <role-name> --type=strategic --patch '" + string(body) + "'"
	return body, command
}

// wildcardReplacementDiff renders the YAML-shaped unified diff a user would
// see in `git diff` / `kubectl diff` if they swapped a wildcard rule for the
// placeholder allowlist. The "before" block is the canonical `*:*:*` rule; the
// "after" block is the placeholder plus a comment telling the user this is a
// scaffold to fill in.
//
// We deliberately render this against a freshly-constructed minimal YAML
// document rather than reconstructing the live (Cluster)Role from the
// snapshot: the snapshot already groups all of a binding's effective rules
// together, but the actual `kubectl get role` output may include other rules
// the user wants to keep. The diff is therefore best read as "what your
// wildcard rule should look like instead", not "exactly the change to apply".
func wildcardReplacementDiff(roleKind, roleName, namespace string) string {
	from := buildOverbroadBefore(roleKind, roleName, namespace)
	to := buildOverbroadAfter(roleKind, roleName, namespace)
	path := diffPathFor(roleKind, roleName, namespace)
	return unifiedDiff(path, path, from, to)
}

func buildOverbroadBefore(roleKind, roleName, namespace string) string {
	var b strings.Builder
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: ")
	b.WriteString(roleKind)
	b.WriteString("\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: ")
	b.WriteString(roleName)
	b.WriteString("\n")
	if namespace != "" {
		b.WriteString("  namespace: ")
		b.WriteString(namespace)
		b.WriteString("\n")
	}
	b.WriteString("rules:\n")
	b.WriteString("- apiGroups: [\"*\"]\n")
	b.WriteString("  resources: [\"*\"]\n")
	b.WriteString("  verbs: [\"*\"]\n")
	return b.String()
}

func buildOverbroadAfter(roleKind, roleName, namespace string) string {
	var b strings.Builder
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: ")
	b.WriteString(roleKind)
	b.WriteString("\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: ")
	b.WriteString(roleName)
	b.WriteString("\n")
	if namespace != "" {
		b.WriteString("  namespace: ")
		b.WriteString(namespace)
		b.WriteString("\n")
	}
	b.WriteString("rules:\n")
	b.WriteString("# TODO: replace the placeholder below with the minimum verbs / resources\n")
	b.WriteString("# this principal actually needs. Run `kubectl auth can-i --list ...`\n")
	b.WriteString("# against the workload SA to discover what to keep.\n")
	b.WriteString("- apiGroups: [\"\"]\n")
	b.WriteString("  resources: [\"pods\"]\n")
	b.WriteString("  verbs: [\"get\", \"list\"]\n")
	return b.String()
}

// ForRBACDangerous returns the structured remediation for the dangerous-verb
// RBAC findings emitted by the rbac analyzer (KUBE-PRIVESC-001 through -017,
// excluding the graph-only -PATH-* findings). Each finding identifies a single
// effective rule from a (Cluster)Role; the fix is to remove that one rule. For
// the correlation findings (-002/-007/-016) the finding is anchored to one half
// of the pair, so removing that rule breaks the chain.
//
// The patch we emit is a JSON-patch operation that surgically removes the
// matching rule by re-writing the entire rules array with the offending rule
// dropped. We can't use a JSON-patch `remove` op with an indexed path because
// the snapshot doesn't carry the rule's index inside the original role.
// Instead, the unified diff shows the rule being removed so an operator can
// hand-apply the change. The Patch.Command is wrapped with a comment that
// tells the operator the diff is canonical and the patch JSON is a hint.
//
// Returns nil when the finding's evidence doesn't carry the source role / verbs
// / resources (defensive: the analyzer always populates these today, but a
// future refactor or a manual `findings.json` could miss them).
func ForRBACDangerous(ruleID string, finding models.Finding, _ models.Snapshot) *models.RemediationHint {
	if !isDangerousRBACRule(ruleID) {
		return nil
	}
	roleKind, roleName, namespace := rbacTargetFromEvidence(finding)
	if roleName == "" {
		return nil
	}
	verbs, resources, apiGroups := rbacRuleFromEvidence(finding)
	if len(verbs) == 0 && len(resources) == 0 {
		return nil
	}
	target := models.PatchTarget{
		Kind:       roleKind,
		APIVersion: "rbac.authorization.k8s.io/v1",
		Name:       roleName,
		Namespace:  namespace,
	}
	body, command := removeRulePatch(target, apiGroups, resources, verbs)
	diff := removeRuleDiff(roleKind, roleName, namespace, apiGroups, resources, verbs)
	return &models.RemediationHint{
		Patch: &models.KubectlPatch{
			Type:    "json",
			Target:  target,
			Body:    body,
			Command: command,
		},
		RBACDiff: diff,
	}
}

// isDangerousRBACRule reports whether the given RuleID is one of the
// dangerous-verb findings the rbac analyzer produces. Each of these maps to a
// single rule inside a (Cluster)Role that the operator can remove without
// dropping the (Cluster)Role wholesale (which would break workloads that
// depend on the other rules in the same role).
//
// Kept as a small allowlist rather than a regex because (a) the set is
// stable and small, and (b) it's the only place in the package that has to
// stay in sync with the analyzer's rule-ID inventory: easier to spot the
// drift in code review when it's a literal switch.
func isDangerousRBACRule(ruleID string) bool {
	switch ruleID {
	case "KUBE-PRIVESC-001",
		"KUBE-PRIVESC-002",
		"KUBE-PRIVESC-003",
		"KUBE-PRIVESC-004",
		"KUBE-PRIVESC-005",
		"KUBE-PRIVESC-006",
		"KUBE-PRIVESC-007",
		"KUBE-PRIVESC-008",
		"KUBE-PRIVESC-009",
		"KUBE-PRIVESC-010",
		"KUBE-PRIVESC-012",
		"KUBE-PRIVESC-013",
		"KUBE-PRIVESC-014",
		"KUBE-PRIVESC-015",
		"KUBE-PRIVESC-016",
		"KUBE-PRIVESC-017":
		return true
	}
	return false
}

// removeRulePatch returns the JSON-patch body and pre-rendered kubectl command
// for removing a single matching rule from a (Cluster)Role. The patch shape we
// emit is a `kubectl patch --type=json` test+remove pair, which is the only
// way to express "remove the rule that has these verbs / resources" via the
// imperative kubectl API without round-tripping through `get -o yaml`.
//
// In practice the patch is a hint: a kubectl JSON patch path is index-based,
// not query-based, so the operator usually runs `kubectl edit role X` and
// removes the matching block by hand. The Command string carries both flows
// so the report renders the structured patch as a copy paste fallback and the
// edit command as the recommended path.
func removeRulePatch(target models.PatchTarget, apiGroups, resources, verbs []string) (json.RawMessage, string) {
	// We can't emit a JSON-patch `remove` with a query-based path: JSON pointer
	// only supports numeric indexes. The hint we surface is a test-then-remove
	// at index 0; the user will likely re-shape it after running `kubectl get
	// <role> -o yaml` to find the real index. The Command therefore prioritises
	// `kubectl edit` as the user-facing recipe.
	rule := map[string]any{
		"apiGroups": apiGroups,
		"resources": resources,
		"verbs":     verbs,
	}
	patch := []map[string]any{
		{
			"op":    "test",
			"path":  "/rules/0",
			"value": rule,
		},
		{
			"op":   "remove",
			"path": "/rules/0",
		},
	}
	body, _ := json.Marshal(patch)
	cmd := buildKubectlEditCommand(target)
	cmd += "\n# Alternatively (only if the dangerous rule is index 0 in the rules array):\n"
	cmd += "# kubectl patch " + strings.ToLower(target.Kind) + " " + target.Name
	if target.Namespace != "" {
		cmd += " -n " + target.Namespace
	}
	cmd += " --type=json --patch '" + string(body) + "'"
	return body, cmd
}

// removeRuleDiff renders a unified-diff hunk showing the dangerous rule being
// removed from the (Cluster)Role. The before block reconstructs the rule from
// the finding's evidence; the after block has the same role with that single
// rule stripped. As with the wildcard diff, this is a "what the change looks
// like" hint, not a guaranteed-applyable patch: the live role may have other
// rules we don't surface here.
func removeRuleDiff(roleKind, roleName, namespace string, apiGroups, resources, verbs []string) string {
	from := buildDangerousBefore(roleKind, roleName, namespace, apiGroups, resources, verbs)
	to := buildDangerousAfter(roleKind, roleName, namespace)
	path := diffPathFor(roleKind, roleName, namespace)
	return unifiedDiff(path, path, from, to)
}

func buildDangerousBefore(roleKind, roleName, namespace string, apiGroups, resources, verbs []string) string {
	var b strings.Builder
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: ")
	b.WriteString(roleKind)
	b.WriteString("\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: ")
	b.WriteString(roleName)
	b.WriteString("\n")
	if namespace != "" {
		b.WriteString("  namespace: ")
		b.WriteString(namespace)
		b.WriteString("\n")
	}
	b.WriteString("rules:\n")
	b.WriteString("- apiGroups: ")
	b.WriteString(jsonList(apiGroups))
	b.WriteString("\n")
	b.WriteString("  resources: ")
	b.WriteString(jsonList(resources))
	b.WriteString("\n")
	b.WriteString("  verbs: ")
	b.WriteString(jsonList(verbs))
	b.WriteString("\n")
	return b.String()
}

func buildDangerousAfter(roleKind, roleName, namespace string) string {
	var b strings.Builder
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	b.WriteString("kind: ")
	b.WriteString(roleKind)
	b.WriteString("\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: ")
	b.WriteString(roleName)
	b.WriteString("\n")
	if namespace != "" {
		b.WriteString("  namespace: ")
		b.WriteString(namespace)
		b.WriteString("\n")
	}
	b.WriteString("rules: []  # all dangerous rules removed: re-add only what the workload actually needs\n")
	return b.String()
}

// ForPrivescPath returns the structured remediation for a KUBE-PRIVESC-PATH-*
// finding, or a KUBE-CONFUSED-DEPUTY-001 finding. Both are graph-path findings
// built by the privesc analyzer's findingFromPath: confused-deputy chains are
// a technique overlay on the same EscalationPath shape (a first hop with
// binding provenance, an operator-reconcile bridge, then whatever the
// controller itself reaches), so the same first-hop-binding-cut logic applies
// unchanged. The fix is the *smallest* edit that breaks the escalation chain;
// the algorithm picks the first hop (the closest one to the subject) because
// it's the one the operator has the most control over: it lives in their
// configuration, not the cluster's built-in identity layer.
//
// Two shapes of fix exist:
//
//  1. If the first hop names a binding we can identify by its own provenance
//     (SourceBinding / BindingNamespace), we emit a unified diff of the
//     binding with the subject removed from `subjects:`. This is the
//     cheapest cut because the binding may still be useful for *other*
//     subjects.
//
//  2. Otherwise, we fall back to a generic advisory diff: the subject is
//     annotated with a comment explaining that the chain comes from a
//     workload-level permission, not an RBAC grant. This covers both
//     synthetic edges (pod_host_escape, token mint) that never traced back
//     to a single binding, and the degenerate case where the named binding
//     is somehow absent from the snapshot.
//
// We deliberately never fall back to scanning the snapshot for some other
// binding that merely lists the subject. An earlier version did exactly
// that, and it could name a binding the chain never used: the cut-resilient
// pass (pathfinder.go's edgeCut / alternatesForSource) only ever simulates
// removing the binding named by a hop's own provenance, so any other binding
// we might print was never evaluated. A hop with no provenance describes a
// workload-level primitive (e.g. pod_host_escape from a privileged hostPath
// pod); an unrelated RBAC binding that happens to list the same subject has
// no bearing on that primitive, and printing a confident diff against it
// tells the operator a fix closes the chain when it does nothing of the
// kind.
//
// Either way the Command is a `kubectl edit` invocation against the
// candidate object so the operator can hand-apply the change. Returns nil
// when the finding's path is empty or the subject is missing: the analyzer
// always populates both, but defensively we don't crash on a degenerate input.
func ForPrivescPath(finding models.Finding, snap models.Snapshot) *models.RemediationHint {
	if !strings.HasPrefix(finding.RuleID, "KUBE-PRIVESC-PATH-") && finding.RuleID != "KUBE-CONFUSED-DEPUTY-001" {
		return nil
	}
	if len(finding.EscalationPath) == 0 || finding.Subject == nil {
		return nil
	}
	subject := *finding.Subject
	firstHop := finding.EscalationPath[0]

	// Cut only the binding hop 1's own provenance names: it is the only cut the
	// cut-resilient pass ever simulated for this chain.
	if binding := findBindingByName(snap, firstHop.SourceBinding, firstHop.BindingNamespace); binding != nil {
		return remediationDropSubjectFromBinding(*binding, subject, firstHop)
	}

	// No binding provenance (synthetic edge), or the named binding is somehow
	// absent from the snapshot: emit a generic advisory diff that explains the
	// chain stems from a pod-escape or synthetic edge that doesn't have a
	// single binding to cut. We still set the Command so the report has
	// something actionable.
	return &models.RemediationHint{
		RBACDiff: privescPathAdvisoryDiff(subject, firstHop),
	}
}

// remediationDropSubjectFromBinding builds the RemediationHint for the
// "remove this subject from this binding" branch of ForPrivescPath. We don't
// emit a kubectl patch struct here because (Cluster)RoleBindings are
// immutable on `roleRef` and partial subject-list edits are not strategic-
// merge friendly: the right shape is either a JSON patch `remove` at the
// subject's index (fragile against list-order changes) or `kubectl edit`.
// We surface the edit command as the canonical action and leave the
// structured patch nil so the JSON consumer doesn't get a half-correct hint.
func remediationDropSubjectFromBinding(binding bindingRef, subject models.SubjectRef, _ models.EscalationHop) *models.RemediationHint {
	from := buildBindingBefore(binding)
	to := buildBindingAfter(binding, subject)
	path := diffPathFor(binding.Kind, binding.Name, binding.Namespace)
	diff := unifiedDiff(path, path, from, to)
	cmd := buildBindingEditCommand(binding)
	return &models.RemediationHint{
		RBACDiff: diff,
		Patch: &models.KubectlPatch{
			Type: "json",
			Target: models.PatchTarget{
				Kind:       binding.Kind,
				APIVersion: "rbac.authorization.k8s.io/v1",
				Name:       binding.Name,
				Namespace:  binding.Namespace,
			},
			Command: cmd,
		},
	}
}

// bindingRef is the narrow projection of an (Cluster)RoleBinding the diff
// builders need. We don't pass the live rbacv1 objects around because they
// carry a lot of metadata (ResourceVersion, ManagedFields) that we'd have to
// strip before rendering YAML: and the diff is illustrative, not a literal
// `kubectl diff` capture.
type bindingRef struct {
	Kind          string
	Name          string
	Namespace     string // empty for ClusterRoleBindings
	RoleRefKind   string
	RoleRefName   string
	Subjects      []rbacv1.Subject
	BindingObject any
}

// findBindingByName returns the binding a hop's provenance names. Namespace is
// empty for ClusterRoleBindings, matching how permissions.Aggregate records it,
// so the (kind, name) pair is unambiguous. Returns nil when the snapshot has no
// such binding, which happens on a partial snapshot where the collector could not
// list one of the two binding kinds.
func findBindingByName(snap models.Snapshot, name, namespace string) *bindingRef {
	if name == "" {
		return nil
	}
	for _, b := range collectBindings(snap) {
		if b.Name == name && b.Namespace == namespace {
			return &b
		}
	}
	return nil
}

// collectBindings flattens the snapshot's RoleBindings and ClusterRoleBindings
// into a single ordered slice of bindingRef. ClusterRoleBindings come first so
// the test goldens and the path-fix algorithm consistently prefer the cluster-
// scoped binding when both exist for the same subject (a not-uncommon shape
// when a SA is bound at both scopes).
func collectBindings(snap models.Snapshot) []bindingRef {
	out := make([]bindingRef, 0, len(snap.Resources.ClusterRoleBindings)+len(snap.Resources.RoleBindings))
	for _, b := range snap.Resources.ClusterRoleBindings {
		out = append(out, bindingRef{
			Kind:          "ClusterRoleBinding",
			Name:          b.Name,
			Namespace:     "",
			RoleRefKind:   b.RoleRef.Kind,
			RoleRefName:   b.RoleRef.Name,
			Subjects:      b.Subjects,
			BindingObject: b,
		})
	}
	for _, b := range snap.Resources.RoleBindings {
		out = append(out, bindingRef{
			Kind:          "RoleBinding",
			Name:          b.Name,
			Namespace:     b.Namespace,
			RoleRefKind:   b.RoleRef.Kind,
			RoleRefName:   b.RoleRef.Name,
			Subjects:      b.Subjects,
			BindingObject: b,
		})
	}
	// Stable sort by Kind, then namespace, then name so test goldens don't
	// flap on map-iteration ordering shifts elsewhere.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// subjectsMatch reports whether an rbacv1.Subject from a binding's subject
// list refers to the same identity as a models.SubjectRef. ServiceAccount
// subjects need namespace handling (empty namespace on the binding means the
// binding's own namespace); Users and Groups have no namespace.
func subjectsMatch(s rbacv1.Subject, target models.SubjectRef, bindingNs string) bool {
	if s.Kind != target.Kind {
		return false
	}
	if s.Name != target.Name {
		return false
	}
	if s.Kind == "ServiceAccount" {
		ns := s.Namespace
		if ns == "" {
			ns = bindingNs
		}
		return ns == target.Namespace
	}
	return true
}

// buildBindingBefore renders the binding as YAML with all of its subjects
// listed. The shape is the minimum needed for an operator to recognise the
// binding in their cluster: we don't reproduce metadata.labels /
// annotations / managedFields because the diff is about subjects, not
// metadata, and including them would inflate the diff with noise.
func buildBindingBefore(b bindingRef) string {
	return renderBindingYAML(b, b.Subjects)
}

// buildBindingAfter renders the binding with the named subject removed. If
// removing the subject leaves an empty subjects list, we surface the binding
// with `subjects: []` so the operator can see the binding is now effectively
// inert (a binding with no subjects grants nothing): they should usually
// delete the binding outright in that case, and the diff makes that obvious.
func buildBindingAfter(b bindingRef, subject models.SubjectRef) string {
	kept := make([]rbacv1.Subject, 0, len(b.Subjects))
	for _, s := range b.Subjects {
		if subjectsMatch(s, subject, b.Namespace) {
			continue
		}
		kept = append(kept, s)
	}
	return renderBindingYAML(b, kept)
}

// renderBindingYAML returns a YAML serialisation of the binding with the
// supplied subject list substituted in. Kept hand-rolled (rather than
// `sigs.k8s.io/yaml.Marshal`) so the output is deterministic: Kubernetes'
// YAML marshaller orders map keys by struct-tag declaration order which is
// fine, but it also splatters Status: {} and creationTimestamp: null on every
// object, which would noise up the diff and confuse a reader who isn't
// looking for those fields.
func renderBindingYAML(b bindingRef, subjects []rbacv1.Subject) string {
	var sb strings.Builder
	sb.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
	sb.WriteString("kind: ")
	sb.WriteString(b.Kind)
	sb.WriteString("\n")
	sb.WriteString("metadata:\n")
	sb.WriteString("  name: ")
	sb.WriteString(b.Name)
	sb.WriteString("\n")
	if b.Namespace != "" {
		sb.WriteString("  namespace: ")
		sb.WriteString(b.Namespace)
		sb.WriteString("\n")
	}
	sb.WriteString("roleRef:\n")
	sb.WriteString("  apiGroup: rbac.authorization.k8s.io\n")
	sb.WriteString("  kind: ")
	sb.WriteString(b.RoleRefKind)
	sb.WriteString("\n")
	sb.WriteString("  name: ")
	sb.WriteString(b.RoleRefName)
	sb.WriteString("\n")
	if len(subjects) == 0 {
		sb.WriteString("subjects: []\n")
		return sb.String()
	}
	sb.WriteString("subjects:\n")
	for _, s := range subjects {
		sb.WriteString("- kind: ")
		sb.WriteString(s.Kind)
		sb.WriteString("\n")
		sb.WriteString("  name: ")
		sb.WriteString(s.Name)
		sb.WriteString("\n")
		if s.Kind == "ServiceAccount" {
			ns := s.Namespace
			if ns == "" {
				ns = b.Namespace
			}
			if ns != "" {
				sb.WriteString("  namespace: ")
				sb.WriteString(ns)
				sb.WriteString("\n")
			}
		}
	}
	return sb.String()
}

// correlationRootedActions are the hop actions emitted by the privesc graph's
// correlation edges: edges that fire only when a subject holds TWO separate RBAC
// grants at once, so no single (Cluster)RoleBinding grants the edge and there is
// nothing for ForPrivescPath to cut. They land in the advisory branch for the same
// reason pod-escape edges do (no binding provenance) but for a completely different
// underlying cause, which is why the advisory copy branches on this set.
//
// One entry per builder in internal/analyzer/privesc/graph.go: addSecretMintEdge,
// addNodeMigrateEdge and finalizeCSRApprovals, the three that call cutBreakers. A
// fourth correlation edge added there needs an entry here, or its advisory copy will
// send the operator to the workload layer for a purely RBAC problem.
var correlationRootedActions = map[string]bool{
	"secret_mint_token":  true,
	"node_drain_migrate": true,
	"csr_approve":        true,
}

// privescPathAdvisoryDiff is the fallback we emit when ForPrivescPath can't
// pin the chain to a single binding. The "before" block is the subject as the
// chain represents it; the "after" block is the same with an inline comment
// naming where the mitigation lives. This is rare in practice: most chains pass
// through a binding somewhere: but we'd rather emit an explanatory comment than
// nothing.
//
// Two causes reach here and they need different advice. A synthetic edge (pod
// escape, IMDS pivot) really is a workload-layer problem: no RBAC change closes
// it. A correlation edge is pure RBAC, and telling its operator to remove
// hostPath or revoke `serviceaccounts/token` create is advice that does not apply
// to their finding: for node_drain_migrate, say, the enabler is `delete pods` plus
// node manipulation, both RBAC grants.
func privescPathAdvisoryDiff(subject models.SubjectRef, firstHop models.EscalationHop) string {
	header := fmt.Sprintf("# Subject\n# kind: %s\n# name: %s\n# namespace: %s\n# first-hop action: %s\n",
		subject.Kind, subject.Name, subject.Namespace, firstHop.Action)

	note := "# NOTE: this chain starts at a synthetic edge (pod escape, token mint,\n# or similar) that does not map to a single (Cluster)RoleBinding. Mitigation\n# is at the workload layer: remove hostPath / hostPID / hostNetwork on the\n# offending pod or revoke `serviceaccounts/token` create on the role that\n# enables the mint.\n"
	if correlationRootedActions[firstHop.Action] {
		// Permission names both halves ("delete pods + node scheduling control").
		// Every correlation builder sets it, but the copy still has to read as a
		// sentence if one ever does not.
		halves := "see the first hop's permission"
		if firstHop.Permission != "" {
			halves = firstHop.Permission
		}
		note = fmt.Sprintf("# NOTE: this chain starts at a correlation edge: two RBAC grants that are\n# only dangerous held together (%s), so no single\n# (Cluster)RoleBinding grants it and there is nothing here to cut. Mitigation\n# is RBAC, not workload configuration: revoke EITHER half from this subject.\n# One is enough, since the edge needs both.\n",
			halves)
	}

	path := "subject-" + sanitisePath(subject.Key())
	return unifiedDiff(path, path, header, header+note)
}

// buildKubectlEditCommand returns the canonical `kubectl edit <role>` line so
// the operator can hand-prune the dangerous rule. We lower-case the Kind
// because kubectl accepts both `clusterrole` and `ClusterRole` but the
// lower-case form is what every K8s tutorial shows.
func buildKubectlEditCommand(target models.PatchTarget) string {
	cmd := "# Recommended: edit the role and remove the dangerous rule by hand.\n"
	cmd += "kubectl edit " + strings.ToLower(target.Kind) + " " + target.Name
	if target.Namespace != "" {
		cmd += " -n " + target.Namespace
	}
	return cmd
}

// buildBindingEditCommand returns the canonical `kubectl edit <binding>` line
// for the drop-subject-from-binding remediation. Same lower-case convention
// as buildKubectlEditCommand.
func buildBindingEditCommand(b bindingRef) string {
	cmd := "# Edit the binding and remove the offending subject from `subjects:`.\n"
	cmd += "kubectl edit " + strings.ToLower(b.Kind) + " " + b.Name
	if b.Namespace != "" {
		cmd += " -n " + b.Namespace
	}
	return cmd
}

// diffPathFor returns the synthetic file-path embedded in the unified-diff
// header. It exists only so the diff renders nicely in editors that
// syntax-highlight by extension; we use `.yaml` and prefix with `rbac/` to
// hint at the source. Namespace is included when non-empty so an operator
// scanning multiple diffs in a PR can tell which namespace each comes from.
func diffPathFor(kind, name, namespace string) string {
	parts := []string{"rbac", strings.ToLower(kind)}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	parts = append(parts, name+".yaml")
	return strings.Join(parts, "/")
}

// sanitisePath rewrites a SubjectRef.Key() into a string safe for use inside
// a unified-diff header path. Slashes are the path separator inside the diff
// header so we replace them with dashes.
func sanitisePath(s string) string {
	return strings.ReplaceAll(s, "/", "-")
}

// rbacTargetFromEvidence extracts the (Cluster)Role kind, name, and namespace
// from a Finding's evidence JSON. The rbac analyzer's findingFromContent
// helper consistently emits `source_role`, `source_binding`, and (via
// Finding.Resource) the Role kind, so we look at both Evidence and Resource
// for the most accurate values. Returns ("", "", "") when neither carries the
// info: callers degrade to "no remediation hint" in that case.
func rbacTargetFromEvidence(finding models.Finding) (kind, name, namespace string) {
	// Prefer Finding.Resource: the analyzer sets it to {Kind: "RBACRule", Name:
	// <role-name>, Namespace: <ns>} for the dangerous-verb findings, and to
	// {Kind: "RBACRule", ...} for OVERBROAD. We need to look at evidence to
	// recover the actual Role/ClusterRole distinction.
	if finding.Resource != nil {
		name = finding.Resource.Name
		namespace = finding.Resource.Namespace
	}
	if len(finding.Evidence) == 0 {
		// No evidence to disambiguate; default to ClusterRole because the
		// dangerous-rule findings overwhelmingly fire on cluster-scoped roles
		// (a namespaced Role is rarely granted cluster-wide verbs). Operators
		// applying a wrong-kind patch get a clear "not found" from kubectl and
		// will swap to Role themselves.
		kind = "ClusterRole"
		return
	}
	var ev struct {
		SourceRole      string `json:"source_role"`
		SourceRoleKind  string `json:"source_role_kind"`
		Namespace       string `json:"namespace"`
		SourceBindingNs string `json:"binding_namespace"`
	}
	_ = json.Unmarshal(finding.Evidence, &ev)
	if ev.SourceRole != "" {
		name = ev.SourceRole
	}
	if ev.SourceRoleKind != "" {
		kind = ev.SourceRoleKind
	}
	if kind == "" {
		// The dangerous-verb findings' evidence carries `source_role` (the
		// role's name) but not the kind explicitly. We can infer from
		// namespace: a namespaced source_binding implies a Role, a cluster-
		// scoped one implies a ClusterRole (binding kinds match their roleRef
		// kind by RBAC invariant).
		if ev.Namespace != "" || ev.SourceBindingNs != "" {
			kind = "Role"
		} else {
			kind = "ClusterRole"
		}
	}
	if namespace == "" && kind == "Role" {
		// Carry through the binding namespace as the Role namespace: true
		// because a RoleBinding can only reference a Role in the same namespace.
		if ev.Namespace != "" {
			namespace = ev.Namespace
		} else if ev.SourceBindingNs != "" {
			namespace = ev.SourceBindingNs
		}
	}
	return
}

// rbacRuleFromEvidence extracts the (verbs, resources, apiGroups) triple from
// a Finding's evidence. The rbac analyzer emits these as JSON arrays; we just
// unmarshal. Empty / nil defaults are fine: the caller already checks for
// zero-length verbs and resources before generating the patch.
func rbacRuleFromEvidence(finding models.Finding) (verbs, resources, apiGroups []string) {
	if len(finding.Evidence) == 0 {
		return
	}
	var ev struct {
		APIGroups []string `json:"api_groups"`
		Resources []string `json:"resources"`
		Verbs     []string `json:"verbs"`
	}
	_ = json.Unmarshal(finding.Evidence, &ev)
	return ev.Verbs, ev.Resources, ev.APIGroups
}

// jsonList serialises a string slice as a flow-style YAML list, matching the
// style our hand-rolled YAML uses elsewhere in this file. Nil / empty becomes
// `[]` so the diff is still parseable.
func jsonList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
