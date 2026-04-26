// Package rbac analyzes Role/ClusterRole bindings and flags subjects whose
// effective permissions enable privilege escalation or data exfiltration.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/scoring"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Analyzer produces RBAC-focused findings from a snapshot.
type Analyzer struct{}

// effectiveRule is a flattened policy rule tagged with where it came from so findings can point back at it.
type effectiveRule struct {
	Namespace     string
	APIGroups     []string
	Resources     []string
	Verbs         []string
	SourceRole    string
	SourceBinding string
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
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, binding.Namespace)
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					Namespace:     binding.Namespace,
					APIGroups:     append([]string(nil), rule.APIGroups...),
					Resources:     append([]string(nil), rule.Resources...),
					Verbs:         append([]string(nil), rule.Verbs...),
					SourceRole:    binding.RoleRef.Name,
					SourceBinding: binding.Name,
				})
			}
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		rules := referencedRules(binding.RoleRef, "", roleRules, clusterRoleRules)
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					APIGroups:     append([]string(nil), rule.APIGroups...),
					Resources:     append([]string(nil), rule.Resources...),
					Verbs:         append([]string(nil), rule.Verbs...),
					SourceRole:    binding.RoleRef.Name,
					SourceBinding: binding.Name,
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

			switch {
			case hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) && hasWildcard(rule.APIGroups):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-017",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(9.8 * exploitability * blastRadius),
					Title:       "Wildcard cluster-admin style permissions",
					Description: "This subject can act on any resource with any verb, which is effectively cluster-admin access.",
					Remediation: "Replace wildcard verbs/resources with the minimum set of explicit permissions required for the workload.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
					},
				}))
			case hasResource(rule.Resources, "secrets") && hasAnyVerb(rule.Verbs, "get", "list", "watch"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-005",
					Severity:    models.SeverityHigh,
					Category:    models.CategoryDataExfiltration,
					BaseScore:   scoring.Clamp(8.2 * exploitability * blastRadius),
					Title:       "Secret read access",
					Description: "This subject can read Kubernetes secrets, which can expose service account tokens, credentials, and certificates.",
					Remediation: "Restrict secret access to only the namespaces and workloads that require it.",
					References: []string{
						"https://kubernetes.io/docs/concepts/configuration/secret/",
					},
				}))
			case hasResource(rule.Resources, "pods") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-001",
					Severity:    models.SeverityHigh,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(8.4 * exploitability * blastRadius),
					Title:       "Pod creation access can be used for token theft",
					Description: "Creating pods lets an attacker mount another service account and execute code with that identity.",
					Remediation: "Remove direct pod creation rights from broad identities and route deployments through controlled automation.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
					},
				}))
			case hasAnyResource(rule.Resources, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-003",
					Severity:    models.SeverityHigh,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(8.1 * exploitability * blastRadius),
					Title:       "Workload controller modification can create privileged pods",
					Description: "This subject can create or mutate workload controllers that in turn create pods.",
					Remediation: "Restrict workload mutation rights and separate deployment automation from runtime identities.",
					References: []string{
						"https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html",
					},
				}))
			case hasAnyResource(rule.Resources, []string{"users", "groups", "serviceaccounts"}) && hasAnyVerb(rule.Verbs, "impersonate"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-008",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(9.4 * exploitability * blastRadius),
					Title:       "Impersonation permissions",
					Description: "This subject can impersonate other identities and potentially assume more privileged access.",
					Remediation: "Avoid granting impersonation except to tightly controlled admin workflows.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation",
					},
				}))
			case hasAnyResource(rule.Resources, []string{"roles", "clusterroles"}) && hasAnyVerb(rule.Verbs, "bind", "escalate"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-009",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(9.2 * exploitability * blastRadius),
					Title:       "RBAC bind or escalate permission",
					Description: "This subject can bypass RBAC escalation protections or bind itself to higher privileges.",
					Remediation: "Remove `bind` and `escalate` from non-admin identities and scope RBAC write access tightly.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update",
					},
				}))
			case hasAnyResource(rule.Resources, []string{"rolebindings", "clusterrolebindings"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-010",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(9.0 * exploitability * blastRadius),
					Title:       "Role binding modification can self-grant access",
					Description: "This subject can create or modify role bindings and may grant itself stronger permissions.",
					Remediation: "Limit RBAC binding write access to a small administrative boundary and monitor changes.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
					},
				}))
			case hasResource(rule.Resources, "nodes/proxy") && hasAnyVerb(rule.Verbs, "get"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-012",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(9.3 * exploitability * blastRadius),
					Title:       "Node proxy access",
					Description: "Access to `nodes/proxy` can enable kubelet abuse and command execution into pods on the node.",
					Remediation: "Avoid granting kubelet-facing permissions to application identities.",
					References: []string{
						"https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html",
					},
				}))
			case hasResource(rule.Resources, "serviceaccounts/token") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, finding(perms.Subject, rule, findingSpec{
					RuleID:      "KUBE-PRIVESC-014",
					Severity:    models.SeverityHigh,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   scoring.Clamp(8.0 * exploitability * blastRadius),
					Title:       "Service account token creation",
					Description: "This subject can mint service account tokens for other identities in scope.",
					Remediation: "Grant `create` on `serviceaccounts/token` only to trusted control-plane components.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",
					},
				}))
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
				findings = appendFinding(findings, seen, finding(ref, effectiveRule{SourceBinding: binding.Name, SourceRole: binding.RoleRef.Name}, findingSpec{
					RuleID:      "KUBE-RBAC-OVERBROAD-001",
					Severity:    models.SeverityCritical,
					Category:    models.CategoryPrivilegeEscalation,
					BaseScore:   10,
					Title:       "Non-system subject bound to cluster-admin",
					Description: "A non-system subject is directly bound to the `cluster-admin` ClusterRole.",
					Remediation: "Replace cluster-admin with a custom least-privilege role or constrain the binding to a dedicated admin group.",
					References: []string{
						"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles",
					},
				}))
			}
		}
	}

	return findings, nil
}

// findingSpec bundles the static metadata used to materialize a models.Finding for a matched rule.
type findingSpec struct {
	RuleID      string
	Severity    models.Severity
	Category    models.RiskCategory
	BaseScore   float64
	Title       string
	Description string
	Remediation string
	References  []string
	Tags        []string
}

// appendFinding adds finding to the slice unless its ID has already been seen (deduplication keyed by Finding.ID).
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// finding materializes a models.Finding describing subject's exposure through rule using spec's metadata.
func finding(subject models.SubjectRef, rule effectiveRule, spec findingSpec) models.Finding {
	evidenceBytes, _ := json.Marshal(map[string]any{
		"source_role":    rule.SourceRole,
		"source_binding": rule.SourceBinding,
		"api_groups":     rule.APIGroups,
		"resources":      rule.Resources,
		"verbs":          rule.Verbs,
		"namespace":      rule.Namespace,
	})

	resource := &models.ResourceRef{
		Kind:      "RBACRule",
		Name:      rule.SourceRole,
		Namespace: rule.Namespace,
		APIGroup:  "rbac.authorization.k8s.io",
	}

	id := fmt.Sprintf("%s:%s:%s:%s", spec.RuleID, subject.Key(), rule.Namespace, strings.Join(rule.Resources, ","))
	return models.Finding{
		ID:          id,
		RuleID:      spec.RuleID,
		Severity:    spec.Severity,
		Score:       spec.BaseScore,
		Category:    spec.Category,
		Title:       spec.Title,
		Description: spec.Description,
		Subject:     &subject,
		Resource:    resource,
		Namespace:   rule.Namespace,
		Evidence:    evidenceBytes,
		Remediation: spec.Remediation,
		References:  spec.References,
		Tags:        append([]string{"module:rbac"}, spec.Tags...),
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
