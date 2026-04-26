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

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/permissions"
	"github.com/hardik/kubesplaining/internal/scoring"
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
		if subject.Name == "default" && perms != nil && len(perms.Rules) > 0 {
			findings = appendUnique(findings, seen, newFinding(subject, "KUBE-SA-DEFAULT-002", severityForRules(perms.Rules, true), scoreForRules(perms.Rules, true),
				"Default service account has explicit RBAC permissions",
				"This namespace default service account is bound to non-trivial RBAC permissions, increasing risk for any workload that inherits it.",
				map[string]any{"workloads": workloads, "rules": summarizeRules(perms.Rules)},
				"Create dedicated service accounts for workloads and keep the namespace default account minimally privileged or unused.",
				"defaultServiceAccountPermissions"))
		}

		if perms != nil && hasClusterAdminStyleRule(perms.Rules) {
			findings = appendUnique(findings, seen, newFinding(subject, "KUBE-SA-PRIVILEGED-001", models.SeverityCritical, 10,
				"Service account has cluster-admin style permissions",
				"This service account can act broadly across cluster resources and should be treated as a critical identity.",
				map[string]any{"workloads": workloads, "rules": summarizeRules(perms.Rules)},
				"Replace wildcard permissions with tightly scoped roles and bind them only where needed.",
				"clusterAdminStyle"))
		}

		if perms != nil && len(workloads) > 0 {
			if dangerous := dangerousCapabilities(perms.Rules); len(dangerous) > 0 {
				severity := models.SeverityHigh
				score := 8.3
				if hasDangerousCapability(dangerous, "impersonate", "bind", "escalate", "nodes/proxy") {
					severity = models.SeverityCritical
					score = 9.1
				}
				findings = appendUnique(findings, seen, newFinding(subject, "KUBE-SA-PRIVILEGED-002", severity, score,
					"Workload-mounted service account has dangerous permissions",
					"This service account is actively used by workloads and carries permissions that enable privilege escalation or sensitive data access.",
					map[string]any{"workloads": workloads, "dangerous_permissions": dangerous},
					"Split this service account by workload and remove high-risk permissions such as secret reads, pod creation, and RBAC mutation.",
					"dangerousPermissions"))
			}
		}

		if usedByKind(workloads, "DaemonSet") {
			severity := models.SeverityMedium
			score := 5.9
			if perms != nil && len(perms.Rules) > 0 {
				severity = models.SeverityHigh
				score = 7.4
			}
			findings = appendUnique(findings, seen, newFinding(subject, "KUBE-SA-DAEMONSET-001", severity, score,
				"Service account used by a DaemonSet",
				"Tokens for this service account are distributed to a DaemonSet, which places them on every scheduled node the DaemonSet reaches.",
				map[string]any{"workloads": workloads, "rules": summarizeRules(maybeRules(perms))},
				"Use a narrowly scoped service account for node-wide agents and audit its permissions carefully.",
				"daemonSetUsage"))
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

// newFinding materializes a ServiceAccount-scoped finding.
func newFinding(subject models.SubjectRef, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s", ruleID, subject.Key()),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryPrivilegeEscalation,
		Title:       title,
		Description: description,
		Subject:     &subject,
		Namespace:   subject.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ServiceAccount",
			Name:      subject.Name,
			Namespace: subject.Namespace,
			APIGroup:  "",
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
		},
		Tags: []string{"module:service_account", "check:" + check},
	}
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
