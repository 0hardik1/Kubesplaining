// Package rbac analyzes Role/ClusterRole bindings and flags subjects whose
// effective permissions enable privilege escalation or data exfiltration.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Analyzer produces RBAC-focused findings from a snapshot.
type Analyzer struct{}

// effectiveRule is a flattened policy rule tagged with where it came from so findings can point back at it.
//
// SourceRole / SourceBinding hold the raw object names (used in Evidence JSON, where
// machine-readable identifiers are correct). The Kind/Namespace fields let prose
// renderers qualify those names with their resource Kind — e.g. "ClusterRoleBinding
// `crb-nodes-proxy`" instead of an opaque "`crb-nodes-proxy`" — which is what the
// Findings tab needs to be readable for someone who hasn't memorized the cluster.
type effectiveRule struct {
	Namespace              string
	APIGroups              []string
	Resources              []string
	Verbs                  []string
	SourceRole             string
	SourceRoleKind         string
	SourceRoleNamespace    string
	SourceBinding          string
	SourceBindingKind      string
	SourceBindingNamespace string
}

// formattedBinding returns the binding rendered as "ClusterRoleBinding `name`" or
// "RoleBinding `ns/name`" for inclusion in finding prose. See formatBindingRef.
func (r effectiveRule) formattedBinding() string {
	return formatBindingRef(r.SourceBindingKind, r.SourceBindingNamespace, r.SourceBinding)
}

// formattedRole mirrors formattedBinding for the Role/ClusterRole side.
func (r effectiveRule) formattedRole() string {
	return formatRoleRef(r.SourceRoleKind, r.SourceRoleNamespace, r.SourceRole)
}

// effectivePermissions collects every effectiveRule that resolves to a given subject.
type effectivePermissions struct {
	Subject models.SubjectRef
	Rules   []effectiveRule
}

// New returns a new RBAC analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "rbac"
}

// Analyze walks role and cluster role bindings, resolves each subject's effective permissions,
// and emits findings for wildcard access, secret reads, impersonation, bind/escalate, and similar risks.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	roleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.Roles))
	for _, role := range snapshot.Resources.Roles {
		roleRules[fmt.Sprintf("%s/%s", role.Namespace, role.Name)] = role.Rules
	}

	clusterRoleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.ClusterRoles))
	for _, clusterRole := range snapshot.Resources.ClusterRoles {
		clusterRoleRules[clusterRole.Name] = clusterRole.Rules
	}

	subjects := map[string]*effectivePermissions{}

	for _, binding := range snapshot.Resources.RoleBindings {
		rules := referencedRules(binding.RoleRef, binding.Namespace, roleRules, clusterRoleRules)
		// A RoleBinding's RoleRef.Kind is "Role" (same namespace) or "ClusterRole" (cluster-scoped).
		// Roles are always co-located with their RoleBinding, so the role's namespace mirrors
		// binding.Namespace; ClusterRoles have no namespace.
		roleNamespace := ""
		if binding.RoleRef.Kind == "Role" {
			roleNamespace = binding.Namespace
		}
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, binding.Namespace)
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					Namespace:              binding.Namespace,
					APIGroups:              append([]string(nil), rule.APIGroups...),
					Resources:              append([]string(nil), rule.Resources...),
					Verbs:                  append([]string(nil), rule.Verbs...),
					SourceRole:             binding.RoleRef.Name,
					SourceRoleKind:         binding.RoleRef.Kind,
					SourceRoleNamespace:    roleNamespace,
					SourceBinding:          binding.Name,
					SourceBindingKind:      "RoleBinding",
					SourceBindingNamespace: binding.Namespace,
				})
			}
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		rules := referencedRules(binding.RoleRef, "", roleRules, clusterRoleRules)
		// ClusterRoleBindings can only reference ClusterRoles; both are cluster-scoped.
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					APIGroups:         append([]string(nil), rule.APIGroups...),
					Resources:         append([]string(nil), rule.Resources...),
					Verbs:             append([]string(nil), rule.Verbs...),
					SourceRole:        binding.RoleRef.Name,
					SourceRoleKind:    binding.RoleRef.Kind,
					SourceBinding:     binding.Name,
					SourceBindingKind: "ClusterRoleBinding",
				})
			}
		}
	}

	usedServiceAccounts := usedServiceAccounts(snapshot)
	seen := map[string]struct{}{}
	findings := make([]models.Finding, 0)

	for _, perms := range subjects {
		for _, rule := range perms.Rules {
			blastRadius := 1.0
			if rule.Namespace == "" {
				blastRadius = 1.2
			}
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}

			bindingRef := rule.formattedBinding()
			roleRef := rule.formattedRole()

			switch {
			case hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) && hasWildcard(rule.APIGroups):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-017", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scoring.Clamp(9.8*exploitability*blastRadius),
					contentPrivesc017(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "secrets") && hasAnyVerb(rule.Verbs, "get", "list", "watch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-005", models.SeverityHigh, models.CategoryDataExfiltration,
					scoring.Clamp(8.2*exploitability*blastRadius),
					contentPrivesc005(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "pods") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-001", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scoring.Clamp(8.4*exploitability*blastRadius),
					contentPrivesc001(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-003", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scoring.Clamp(8.1*exploitability*blastRadius),
					contentPrivesc003(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"users", "groups", "serviceaccounts"}) && hasAnyVerb(rule.Verbs, "impersonate"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-008", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scoring.Clamp(9.4*exploitability*blastRadius),
					contentPrivesc008(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"roles", "clusterroles"}) && hasAnyVerb(rule.Verbs, "bind", "escalate"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-009", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scoring.Clamp(9.2*exploitability*blastRadius),
					contentPrivesc009(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"rolebindings", "clusterrolebindings"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-010", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scoring.Clamp(9.0*exploitability*blastRadius),
					contentPrivesc010(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "nodes/proxy") && hasAnyVerb(rule.Verbs, "get"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-012", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scoring.Clamp(9.3*exploitability*blastRadius),
					contentPrivesc012(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "serviceaccounts/token") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-014", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scoring.Clamp(8.0*exploitability*blastRadius),
					contentPrivesc014(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			}
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" {
			for _, subject := range binding.Subjects {
				ref := subjectRef(subject, "")
				if strings.HasPrefix(ref.Name, "system:") {
					continue
				}
				findings = appendFinding(findings, seen, findingFromContent(
					ref,
					effectiveRule{
						SourceBinding:     binding.Name,
						SourceBindingKind: "ClusterRoleBinding",
						SourceRole:        binding.RoleRef.Name,
						SourceRoleKind:    binding.RoleRef.Kind,
					},
					"KUBE-RBAC-OVERBROAD-001", models.SeverityCritical, models.CategoryPrivilegeEscalation, 10,
					contentRBACOverbroad001(ref, binding.Name)))
			}
		}
	}

	return findings, nil
}

// appendFinding adds finding to the slice unless its ID has already been seen (deduplication keyed by Finding.ID).
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// findingFromContent materializes a models.Finding using the enriched ruleContent (Scope, Impact,
// AttackScenario, RemediationSteps, LearnMore, MitreTechniques) plus the runtime context (subject,
// originating rule, severity/score/category bucket). Evidence keeps the same shape as before so
// existing consumers continue to work.
func findingFromContent(subject models.SubjectRef, rule effectiveRule, ruleID string, severity models.Severity, category models.RiskCategory, score float64, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(map[string]any{
		"source_role":    rule.SourceRole,
		"source_binding": rule.SourceBinding,
		"api_groups":     rule.APIGroups,
		"resources":      rule.Resources,
		"verbs":          rule.Verbs,
		"namespace":      rule.Namespace,
		"scope":          string(content.Scope.Level),
	})

	resource := &models.ResourceRef{
		Kind:      "RBACRule",
		Name:      rule.SourceRole,
		Namespace: rule.Namespace,
		APIGroup:  "rbac.authorization.k8s.io",
	}

	id := fmt.Sprintf("%s:%s:%s:%s", ruleID, subject.Key(), rule.Namespace, strings.Join(rule.Resources, ","))
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Resource:         resource,
		Namespace:        rule.Namespace,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:rbac"},
	}
}

// referencedRules returns the PolicyRules that roleRef points at, handling both Role and ClusterRole references.
func referencedRules(
	roleRef rbacv1.RoleRef,
	namespace string,
	roleRules map[string][]rbacv1.PolicyRule,
	clusterRoleRules map[string][]rbacv1.PolicyRule,
) []rbacv1.PolicyRule {
	if roleRef.Kind == "Role" {
		return roleRules[fmt.Sprintf("%s/%s", namespace, roleRef.Name)]
	}
	return clusterRoleRules[roleRef.Name]
}

// getSubject fetches or creates the effectivePermissions entry for ref.
func getSubject(subjects map[string]*effectivePermissions, ref models.SubjectRef) *effectivePermissions {
	key := ref.Key()
	if subjects[key] == nil {
		subjects[key] = &effectivePermissions{Subject: ref}
	}
	return subjects[key]
}

// subjectRef normalizes a binding subject into models.SubjectRef, defaulting ServiceAccount namespace when unset.
func subjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
	ref := models.SubjectRef{
		Kind: subject.Kind,
		Name: subject.Name,
	}
	if subject.Kind == "ServiceAccount" {
		ref.Namespace = subject.Namespace
		if ref.Namespace == "" {
			ref.Namespace = fallbackNamespace
		}
	}
	return ref
}

func hasWildcard(values []string) bool {
	return slices.Contains(values, "*")
}

func hasAnyVerb(values []string, wanted ...string) bool {
	if hasWildcard(values) {
		return true
	}
	for _, value := range wanted {
		if slices.Contains(values, value) {
			return true
		}
	}
	return false
}

func hasResource(values []string, wanted string) bool {
	if hasWildcard(values) {
		return true
	}
	return slices.Contains(values, wanted)
}

func hasAnyResource(values []string, wanted []string) bool {
	if hasWildcard(values) {
		return true
	}
	for _, value := range wanted {
		if slices.Contains(values, value) {
			return true
		}
	}
	return false
}

// usedServiceAccounts returns the set of ServiceAccounts actually mounted by pods, used to bump exploitability scoring.
func usedServiceAccounts(snapshot models.Snapshot) map[string]bool {
	result := make(map[string]bool)
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		result[models.SubjectRef{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: pod.Namespace,
		}.Key()] = true
	}
	return result
}
