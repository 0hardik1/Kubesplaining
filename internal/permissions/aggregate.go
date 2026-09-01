// Package permissions resolves RBAC bindings and roles into a flat "effective permissions" view keyed by subject.
// It does not evaluate at request time; it just unions the rules reachable via all bindings for each subject so
// the analyzers can reason about subject capabilities without re-traversing the graph.
package permissions

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// EffectiveRule is one PolicyRule copy tagged with where it came from (namespace, originating Role/ClusterRole, binding).
type EffectiveRule struct {
	Namespace string // binding namespace, or empty for cluster-scoped rules
	APIGroups []string
	Resources []string
	Verbs     []string
	// ResourceNames is the PolicyRule's optional whitelist of object names the rule
	// applies to. Empty means the rule reaches every object of its resource type; a
	// non-empty list scopes the grant to those named objects, which the shared
	// matcher (matcher.go) honors so name-scoped grants stop firing the broad
	// "read/enumerate/create the whole resource type" checks.
	ResourceNames []string
	// NonResourceURLs is the rule's optional list of non-resource request paths
	// (`/healthz`, `/metrics`, `/*`). Kubernetes rejects a PolicyRule that carries
	// both these and regular resources, so a rule with a non-empty NonResourceURLs
	// always has empty Resources and therefore matches nothing in Grants. It is
	// carried here so aggregation stops discarding it silently; no analyzer reads it
	// yet, and a rule of this shape is a false negative rather than a false positive.
	NonResourceURLs []string
	SourceRole      string
	SourceBinding   string
	// AggregatedFrom names the ClusterRole that actually carries this rule when it
	// reached the subject through another ClusterRole's aggregationRule; it is empty
	// for a rule the referenced role holds directly. It matters for remediation: a
	// rule cannot be deleted from an aggregated ClusterRole, because the aggregation
	// controller rewrites .rules from the contributors on the next sync, so the
	// operator has to edit or relabel the ClusterRole named here instead of the one
	// the binding references.
	AggregatedFrom string
}

// EffectivePermissions is the set of rules effectively granted to a single RBAC subject across all bindings.
type EffectivePermissions struct {
	Subject models.SubjectRef
	Rules   []EffectiveRule
}

// sourcedRule is one PolicyRule plus, when the rule reached the referenced role
// through ClusterRole aggregation, the name of the ClusterRole that carries it.
type sourcedRule struct {
	rule           rbacv1.PolicyRule
	aggregatedFrom string
}

// ownRules wraps a role's literal rules as sourcedRules with no aggregation provenance.
func ownRules(rules []rbacv1.PolicyRule) []sourcedRule {
	out := make([]sourcedRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, sourcedRule{rule: rule})
	}
	return out
}

// resolveClusterRoleRules indexes ClusterRoles by name, expanding aggregationRule.
//
// A ClusterRole with an aggregationRule carries no rules of its own in the manifest
// an author writes: kube-controller-manager's aggregation controller unions the
// rules of every ClusterRole whose labels match one of the selectors and writes the
// result into .rules. A snapshot taken from a live cluster therefore arrives with
// .rules already populated and needs nothing here. A snapshot built from manifests
// (`scan-resource`, or a rendered chart) does not, and reading .rules alone would
// silently treat the aggregate as granting nothing at all.
//
// So: trust .rules whenever it is non-empty, and synthesize the union from the
// selectors only when it is empty. An empty selector is honored rather than skipped,
// because the controller honors it too and a ClusterRole that really does aggregate
// every other one really is that broad. Contributors are read from their literal
// .rules and never from another aggregate's synthesized set, and an aggregate never
// selects itself, so mutually-selecting aggregation rules cannot recurse.
func resolveClusterRoleRules(clusterRoles []rbacv1.ClusterRole) map[string][]sourcedRule {
	resolved := make(map[string][]sourcedRule, len(clusterRoles))
	for _, clusterRole := range clusterRoles {
		resolved[clusterRole.Name] = ownRules(clusterRole.Rules)
	}

	for _, clusterRole := range clusterRoles {
		if clusterRole.AggregationRule == nil || len(clusterRole.Rules) > 0 {
			continue
		}
		var union []sourcedRule
		for _, clusterRoleSelector := range clusterRole.AggregationRule.ClusterRoleSelectors {
			selector, err := metav1.LabelSelectorAsSelector(&clusterRoleSelector)
			if err != nil {
				continue
			}
			for _, candidate := range clusterRoles {
				if candidate.Name == clusterRole.Name || !selector.Matches(labels.Set(candidate.Labels)) {
					continue
				}
				for _, rule := range candidate.Rules {
					union = append(union, sourcedRule{rule: rule, aggregatedFrom: candidate.Name})
				}
			}
		}
		resolved[clusterRole.Name] = union
	}

	return resolved
}

// Aggregate walks every RoleBinding and ClusterRoleBinding, resolves their RoleRef to the referenced rules, and
// returns a subject-keyed map of every rule granted to that subject. Missing roles silently contribute no rules.
func Aggregate(snapshot models.Snapshot) map[string]*EffectivePermissions {
	roleRules := make(map[string][]sourcedRule, len(snapshot.Resources.Roles))
	for _, role := range snapshot.Resources.Roles {
		roleRules[fmt.Sprintf("%s/%s", role.Namespace, role.Name)] = ownRules(role.Rules)
	}

	clusterRoleRules := resolveClusterRoleRules(snapshot.Resources.ClusterRoles)

	subjects := map[string]*EffectivePermissions{}

	for _, binding := range snapshot.Resources.RoleBindings {
		rules := referencedRules(binding.RoleRef, binding.Namespace, roleRules, clusterRoleRules)
		for _, subject := range binding.Subjects {
			ref := SubjectRef(subject, binding.Namespace)
			addRules(getSubject(subjects, ref), rules, binding.Namespace, binding.RoleRef.Name, binding.Name)
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		rules := referencedRules(binding.RoleRef, "", roleRules, clusterRoleRules)
		for _, subject := range binding.Subjects {
			ref := SubjectRef(subject, "")
			addRules(getSubject(subjects, ref), rules, "", binding.RoleRef.Name, binding.Name)
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
	roleRules map[string][]sourcedRule,
	clusterRoleRules map[string][]sourcedRule,
) []sourcedRule {
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

// addRules copies one binding's resolved rules onto a subject, stamping the binding
// namespace and the (role, binding) provenance every analyzer reads back.
func addRules(perms *EffectivePermissions, rules []sourcedRule, namespace, roleName, bindingName string) {
	for _, sourced := range rules {
		perms.Rules = append(perms.Rules, EffectiveRule{
			Namespace:       namespace,
			APIGroups:       append([]string(nil), sourced.rule.APIGroups...),
			Resources:       append([]string(nil), sourced.rule.Resources...),
			Verbs:           append([]string(nil), sourced.rule.Verbs...),
			ResourceNames:   append([]string(nil), sourced.rule.ResourceNames...),
			NonResourceURLs: append([]string(nil), sourced.rule.NonResourceURLs...),
			SourceRole:      roleName,
			SourceBinding:   bindingName,
			AggregatedFrom:  sourced.aggregatedFrom,
		})
	}
}
