// Package serviceaccount joins RBAC permissions with workload usage to flag
// ServiceAccounts that are actively mounted by pods and carry dangerous rights.
package serviceaccount

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// Analyzer produces service-account-focused findings from a snapshot.
type Analyzer struct{}

// workloadRef captures a pod-bearing workload that mounts a given ServiceAccount.
type workloadRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// New returns a new service-account analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "serviceaccount"
}

// Analyze cross-references each ServiceAccount's effective permissions with the workloads that mount it,
// emitting findings when privileges and workload usage combine into meaningful exposure.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	permsBySubject := permissions.Aggregate(snapshot)
	usageBySA := collectUsage(snapshot)

	keys := make([]string, 0)
	for key, perms := range permsBySubject {
		if perms.Subject.Kind == "ServiceAccount" && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	for key := range usageBySA {
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, key := range keys {
		perms := permsBySubject[key]
		subject := models.SubjectRef{Kind: "ServiceAccount"}
		if perms != nil {
			subject = perms.Subject
		} else {
			subject = parseServiceAccountKey(key)
		}

		workloads := usageBySA[key]
		workloadDesc := workloadsSummary(workloads)
		if subject.Name == "default" && perms != nil && len(perms.Rules) > 0 {
			findings = appendUnique(findings, seen, newFinding(subject,
				"KUBE-SA-DEFAULT-002", severityForRules(perms.Rules, true), scoreForRules(perms.Rules, true),
				map[string]any{"workloads": workloads, "rules": summarizeRules(perms.Rules)},
				"defaultServiceAccountPermissions",
				contentSADefault002(subject, workloadDesc, ruleSummaryText(perms.Rules))))
		}

		if perms != nil && hasClusterAdminStyleRule(perms.Rules) {
			findings = appendUnique(findings, seen, newFinding(subject,
				"KUBE-SA-PRIVILEGED-001", models.SeverityCritical, 10,
				map[string]any{"workloads": workloads, "rules": summarizeRules(perms.Rules)},
				"clusterAdminStyle",
				contentSAPrivileged001(subject, workloadDesc, ruleSummaryText(perms.Rules))))
		}

		if perms != nil && len(workloads) > 0 {
			if dangerous := dangerousCapabilities(perms.Rules); len(dangerous) > 0 {
				severity := models.SeverityHigh
				score := 8.3
				if hasDangerousCapability(dangerous, "impersonate", "bind", "escalate", "nodes/proxy") {
					severity = models.SeverityCritical
					score = 9.1
				}
				findings = appendUnique(findings, seen, newFinding(subject,
					"KUBE-SA-PRIVILEGED-002", severity, score,
					map[string]any{"workloads": workloads, "dangerous_permissions": dangerous},
					"dangerousPermissions",
					contentSAPrivileged002(subject, workloadDesc, dangerous)))
			}
		}

		if usedByKind(workloads, "DaemonSet") {
			severity := models.SeverityMedium
			score := 5.9
			hasRules := perms != nil && len(perms.Rules) > 0
			if hasRules {
				severity = models.SeverityHigh
				score = 7.4
			}
			findings = appendUnique(findings, seen, newFinding(subject,
				"KUBE-SA-DAEMONSET-001", severity, score,
				map[string]any{"workloads": workloads, "rules": summarizeRules(maybeRules(perms))},
				"daemonSetUsage",
				contentSADaemonset001(subject, workloadDesc, ruleSummaryText(maybeRules(perms)), hasRules)))
		}
	}

	return findings, nil
}

// collectUsage returns, per ServiceAccount key, the list of workloads that mount it (defaulting missing names to "default").
func collectUsage(snapshot models.Snapshot) map[string][]workloadRef {
	result := make(map[string][]workloadRef)

	add := func(kind, name, namespace, serviceAccount string) {
		if serviceAccount == "" {
			serviceAccount = "default"
		}
		subject := models.SubjectRef{Kind: "ServiceAccount", Name: serviceAccount, Namespace: namespace}
		result[subject.Key()] = append(result[subject.Key()], workloadRef{
			Kind:      kind,
			Name:      name,
			Namespace: namespace,
		})
	}

	for _, pod := range snapshot.Resources.Pods {
		add("Pod", pod.Name, pod.Namespace, pod.Spec.ServiceAccountName)
	}
	for _, deployment := range snapshot.Resources.Deployments {
		add("Deployment", deployment.Name, deployment.Namespace, deployment.Spec.Template.Spec.ServiceAccountName)
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		add("DaemonSet", daemonSet.Name, daemonSet.Namespace, daemonSet.Spec.Template.Spec.ServiceAccountName)
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		add("StatefulSet", statefulSet.Name, statefulSet.Namespace, statefulSet.Spec.Template.Spec.ServiceAccountName)
	}
	for _, job := range snapshot.Resources.Jobs {
		add("Job", job.Name, job.Namespace, job.Spec.Template.Spec.ServiceAccountName)
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		add("CronJob", cronJob.Name, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName)
	}

	return result
}

// parseServiceAccountKey reverses SubjectRef.Key() back into a SubjectRef when no permissions entry exists to carry one.
func parseServiceAccountKey(key string) models.SubjectRef {
	parts := strings.Split(key, "/")
	if len(parts) == 3 {
		return models.SubjectRef{Kind: parts[0], Namespace: parts[1], Name: parts[2]}
	}
	return models.SubjectRef{Kind: "ServiceAccount", Name: key}
}

// summarizeRules converts aggregated rules into a JSON-friendly slice stored as finding evidence.
func summarizeRules(rules []permissions.EffectiveRule) []map[string]any {
	summary := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		summary = append(summary, map[string]any{
			"namespace":      rule.Namespace,
			"resources":      rule.Resources,
			"verbs":          rule.Verbs,
			"source_role":    rule.SourceRole,
			"source_binding": rule.SourceBinding,
		})
	}
	return summary
}

// maybeRules returns the aggregated rules or nil when perms is unset, so callers can safely summarize.
func maybeRules(perms *permissions.EffectivePermissions) []permissions.EffectiveRule {
	if perms == nil {
		return nil
	}
	return perms.Rules
}

// hasClusterAdminStyleRule reports whether any aggregated rule grants wildcard verbs on wildcard resources.
func hasClusterAdminStyleRule(rules []permissions.EffectiveRule) bool {
	for _, rule := range rules {
		if contains(rule.Verbs, "*") && contains(rule.Resources, "*") {
			return true
		}
	}
	return false
}

// dangerousCapabilities returns a deduplicated list of short human-readable labels describing the most risky rights a subject holds.
func dangerousCapabilities(rules []permissions.EffectiveRule) []string {
	found := make([]string, 0)
	for _, rule := range rules {
		if hasResource(rule.Resources, "secrets") && hasAnyVerb(rule.Verbs, "get", "list", "watch") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "secrets"))
		}
		if hasResource(rule.Resources, "pods") && hasAnyVerb(rule.Verbs, "create") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "create pods"))
		}
		if hasAnyResource(rule.Resources, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) && hasAnyVerb(rule.Verbs, "create", "update", "patch") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "mutate workloads"))
		}
		if hasAnyResource(rule.Resources, []string{"rolebindings", "clusterrolebindings"}) && hasAnyVerb(rule.Verbs, "create", "update", "patch") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "bind roles"))
		}
		if hasAnyResource(rule.Resources, []string{"roles", "clusterroles"}) && hasAnyVerb(rule.Verbs, "bind", "escalate") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "bind/escalate"))
		}
		if hasAnyResource(rule.Resources, []string{"users", "groups", "serviceaccounts"}) && hasAnyVerb(rule.Verbs, "impersonate") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "impersonate"))
		}
		if hasResource(rule.Resources, "nodes/proxy") && hasAnyVerb(rule.Verbs, "get") {
			found = appendIfMissing(found, scopedCapability(rule.Namespace, "nodes/proxy"))
		}
	}
	return found
}

// usedByKind reports whether any of the workloads using this ServiceAccount is of the given kind.
func usedByKind(workloads []workloadRef, kind string) bool {
	for _, workload := range workloads {
		if workload.Kind == kind {
			return true
		}
	}
	return false
}

// scoreForRules assigns a base score to a ServiceAccount based on the worst capability it holds, bumping the default SA higher because of blast-radius risk.
func scoreForRules(rules []permissions.EffectiveRule, defaultSA bool) float64 {
	if hasClusterAdminStyleRule(rules) {
		return 10
	}
	dangerous := dangerousCapabilities(rules)
	switch {
	case hasDangerousCapability(dangerous, "impersonate", "bind", "escalate", "nodes/proxy"):
		return 9.0
	case len(dangerous) > 0:
		if defaultSA {
			return 8.1
		}
		return 7.8
	default:
		if defaultSA {
			return 6.2
		}
		return 4.5
	}
}

// severityForRules maps the numeric scoreForRules result to a Severity bucket.
func severityForRules(rules []permissions.EffectiveRule, defaultSA bool) models.Severity {
	score := scoreForRules(rules, defaultSA)
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score >= 2.0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// newFinding materializes a ServiceAccount-scoped finding from a ruleContent.
func newFinding(subject models.SubjectRef, ruleID string, severity models.Severity, score float64, evidence map[string]any, check string, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s", ruleID, subject.Key()),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryPrivilegeEscalation,
		Title:       content.Title,
		Description: content.Description,
		Subject:     &subject,
		Namespace:   subject.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ServiceAccount",
			Name:      subject.Name,
			Namespace: subject.Namespace,
			APIGroup:  "",
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:service_account", "check:" + check},
	}
}

// workloadsSummary renders the list of workloads that mount the SA into a one-line
// human description used in finding descriptions / impact lines.
func workloadsSummary(workloads []workloadRef) string {
	if len(workloads) == 0 {
		return "no workloads currently mount this SA"
	}
	parts := make([]string, 0, len(workloads))
	for _, w := range workloads {
		parts = append(parts, fmt.Sprintf("%s/%s/%s", w.Kind, w.Namespace, w.Name))
	}
	return strings.Join(parts, ", ")
}

// ruleSummaryText renders aggregated rules into a compact text block for finding descriptions.
// Each line is "  - verbs on resources [from binding/role] in namespace".
func ruleSummaryText(rules []permissions.EffectiveRule) string {
	if len(rules) == 0 {
		return "  (no aggregated rules)"
	}
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		ns := rule.Namespace
		if ns == "" {
			ns = "cluster-wide"
		}
		lines = append(lines, fmt.Sprintf("  - verbs %v on resources %v (from %s/%s in %s)", rule.Verbs, rule.Resources, rule.SourceBinding, rule.SourceRole, ns))
	}
	return strings.Join(lines, "\n")
}

// appendUnique deduplicates by Finding.ID before appending.
func appendUnique(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

func appendIfMissing(values []string, value string) []string {
	if !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}

// scopedCapability annotates a capability label with its namespace scope for evidence output.
func scopedCapability(namespace, capability string) string {
	if namespace == "" {
		return capability + " (cluster)"
	}
	return capability + " (" + namespace + ")"
}

// hasDangerousCapability reports whether any capability label contains one of the worst-case fragments like "impersonate" or "bind".
func hasDangerousCapability(values []string, fragments ...string) bool {
	for _, value := range values {
		for _, fragment := range fragments {
			if strings.Contains(value, fragment) {
				return true
			}
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

func hasAnyVerb(values []string, wanted ...string) bool {
	if contains(values, "*") {
		return true
	}
	for _, item := range wanted {
		if contains(values, item) {
			return true
		}
	}
	return false
}

func hasResource(values []string, wanted string) bool {
	if contains(values, "*") {
		return true
	}
	return contains(values, wanted)
}

func hasAnyResource(values []string, wanted []string) bool {
	if contains(values, "*") {
		return true
	}
	for _, item := range wanted {
		if contains(values, item) {
			return true
		}
	}
	return false
}
