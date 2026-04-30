// Package permissions resolves RBAC bindings and roles into a flat "effective permissions" view keyed by subject.
// It does not evaluate at request time; it just unions the rules reachable via all bindings for each subject so
// the analyzers can reason about subject capabilities without re-traversing the graph.
package permissions

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
)

// EffectiveRule is one PolicyRule copy tagged with where it came from (namespace, originating Role/ClusterRole, binding).
type EffectiveRule struct {
	Namespace     string // binding namespace, or empty for cluster-scoped rules
	APIGroups     []string
	Resources     []string
	Verbs         []string
	SourceRole    string
	SourceBinding string
}

// EffectivePermissions is the set of rules effectively granted to a single RBAC subject across all bindings.
type EffectivePermissions struct {
	Subject models.SubjectRef
	Rules   []EffectiveRule
}

// Aggregate walks every RoleBinding and ClusterRoleBinding, resolves their RoleRef to the referenced rules, and
// returns a subject-keyed map of every rule granted to that subject. Missing roles silently contribute no rules.
func Aggregate(snapshot models.Snapshot) map[string]*EffectivePermissions {
	roleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.Roles))
	for _, role := range snapshot.Resources.Roles {
		roleRules[fmt.Sprintf("%s/%s", role.Namespace, role.Name)] = role.Rules
	}

	clusterRoleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.ClusterRoles))
	for _, clusterRole := range snapshot.Resources.ClusterRoles {
		clusterRoleRules[clusterRole.Name] = clusterRole.Rules
	}

	subjects := map[string]*EffectivePermissions{}

	for _, binding := range snapshot.Resources.RoleBindings {
		rules := referencedRules(binding.RoleRef, binding.Namespace, roleRules, clusterRoleRules)
		for _, subject := range binding.Subjects {
			ref := SubjectRef(subject, binding.Namespace)
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, EffectiveRule{
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
			ref := SubjectRef(subject, "")
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, EffectiveRule{
					Namespace:     "",
					APIGroups:     append([]string(nil), rule.APIGroups...),
					Resources:     append([]string(nil), rule.Resources...),
					Verbs:         append([]string(nil), rule.Verbs...),
					SourceRole:    binding.RoleRef.Name,
					SourceBinding: binding.Name,
				})
			}
		}
	}

	return subjects
}

// SubjectRef converts an rbacv1.Subject into a models.SubjectRef, filling in a ServiceAccount namespace from fallbackNamespace when omitted.
func SubjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
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

// referencedRules returns the PolicyRules a RoleRef points at, routing "Role" into the namespace-scoped map and "ClusterRole" into the cluster-scoped one.
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

// getSubject returns (and lazily creates) the EffectivePermissions entry for a subject keyed by its canonical Key().
func getSubject(subjects map[string]*EffectivePermissions, ref models.SubjectRef) *EffectivePermissions {
	key := ref.Key()
	if subjects[key] == nil {
		subjects[key] = &EffectivePermissions{Subject: ref}
	}
	return subjects[key]
}
