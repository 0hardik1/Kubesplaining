package exclusions

import (
	"path"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// MatchResult wraps the (possibly annotated) Finding, whether an exclusion matched, and the matching reason.
type MatchResult struct {
	Finding models.Finding
	Matched bool
	Reason  string
}

// Apply runs Match on each finding, dropping matched entries from the returned slice and returning the excluded count.
func Apply(cfg Config, findings []models.Finding) ([]models.Finding, int) {
	filtered := make([]models.Finding, 0, len(findings))
	excludedCount := 0

	for _, finding := range findings {
		result := Match(cfg, finding)
		if result.Matched {
			excludedCount++
			continue
		}
		filtered = append(filtered, result.Finding)
	}

	return filtered, excludedCount
}

// Match evaluates cfg against a single finding; the first matching section (global/rbac/podsec/network) wins and the finding is annotated.
func Match(cfg Config, finding models.Finding) MatchResult {
	if reason, ok := matchesGlobal(cfg.Global, finding); ok {
		finding.Excluded = true
		finding.ExclusionReason = reason
		return MatchResult{Finding: finding, Matched: true, Reason: reason}
	}

	if reason, ok := matchesRBAC(cfg.RBAC, finding); ok {
		finding.Excluded = true
		finding.ExclusionReason = reason
		return MatchResult{Finding: finding, Matched: true, Reason: reason}
	}

	if reason, ok := matchesPodSecurity(cfg.PodSecurity, finding); ok {
		finding.Excluded = true
		finding.ExclusionReason = reason
		return MatchResult{Finding: finding, Matched: true, Reason: reason}
	}

	if reason, ok := matchesNetwork(cfg.NetworkPolicy, finding); ok {
		finding.Excluded = true
		finding.ExclusionReason = reason
		return MatchResult{Finding: finding, Matched: true, Reason: reason}
	}

	return MatchResult{Finding: finding}
}

// matchesGlobal tests the cross-module exclusions: rule/ID patterns, namespaces, service-account patterns, and cluster-role names.
func matchesGlobal(cfg GlobalConfig, finding models.Finding) (string, bool) {
	for _, pattern := range cfg.ExcludeFindingIDs {
		if matchesPattern(pattern, finding.RuleID) || matchesPattern(pattern, finding.ID) {
			return "matched global.exclude_finding_ids", true
		}
	}

	for _, namespace := range namespacesForFinding(finding) {
		if matchesAny(cfg.ExcludeNamespaces, namespace) {
			return "matched global.exclude_namespaces", true
		}
	}

	if finding.Subject != nil && finding.Subject.Kind == "ServiceAccount" {
		for _, candidate := range []string{
			finding.Subject.Name,
			finding.Subject.Namespace + ":" + finding.Subject.Name,
			finding.Subject.Namespace + "/" + finding.Subject.Name,
		} {
			if matchesAny(cfg.ExcludeServiceAccounts, candidate) {
				return "matched global.exclude_service_accounts", true
			}
		}
	}

	if finding.Subject != nil {
		for _, subject := range cfg.ExcludeSubjects {
			if subject.Kind != "" && subject.Kind != finding.Subject.Kind {
				continue
			}
			if subject.Name != "" && !matchesPattern(subject.Name, finding.Subject.Name) {
				continue
			}
			if subject.Namespace != "" && !matchesPattern(subject.Namespace, finding.Subject.Namespace) {
				continue
			}
			reason := subject.Reason
			if reason == "" {
				reason = "matched global.exclude_subjects"
			}
			return reason, true
		}
	}

	if finding.Resource != nil && finding.Resource.Kind == "RBACRule" && matchesAny(cfg.ExcludeClusterRoles, finding.Resource.Name) {
		return "matched global.exclude_cluster_roles", true
	}

	return "", false
}

// matchesRBAC is module-scoped: it only runs for findings tagged module:rbac and matches on the Subject fields.
func matchesRBAC(cfg RBACConfig, finding models.Finding) (string, bool) {
	if !hasTag(finding.Tags, "module:rbac") {
		return "", false
	}

	for _, subject := range cfg.ExcludeSubjects {
		if finding.Subject == nil {
			continue
		}
		if subject.Kind != "" && subject.Kind != finding.Subject.Kind {
			continue
		}
		if subject.Name != "" && !matchesPattern(subject.Name, finding.Subject.Name) {
			continue
		}
		if subject.Namespace != "" && !matchesPattern(subject.Namespace, finding.Subject.Namespace) {
			continue
		}
		reason := subject.Reason
		if reason == "" {
			reason = "matched rbac.exclude_subjects"
		}
		return reason, true
	}

	return "", false
}

// matchesPodSecurity is module-scoped: it only runs for findings tagged module:pod_security and matches workload identity or check tags.
func matchesPodSecurity(cfg PodSecurityConfig, finding models.Finding) (string, bool) {
	if !hasTag(finding.Tags, "module:pod_security") {
		return "", false
	}

	for _, workload := range cfg.ExcludeWorkloads {
		if finding.Resource == nil {
			continue
		}
		if workload.Kind != "" && workload.Kind != finding.Resource.Kind {
			continue
		}
		if workload.Namespace != "" && !matchesPattern(workload.Namespace, finding.Resource.Namespace) {
			continue
		}
		if workload.Name != "" && !matchesPattern(workload.Name, finding.Resource.Name) {
			continue
		}
		if workload.NamePattern != "" && !matchesPattern(workload.NamePattern, finding.Resource.Name) {
			continue
		}
		reason := workload.Reason
		if reason == "" {
			reason = "matched pod_security.exclude_workloads"
		}
		return reason, true
	}

	for _, check := range cfg.ExcludeChecks {
		if check.Namespace != "" && !matchesPattern(check.Namespace, finding.Namespace) {
			continue
		}
		if check.Check == "" {
			continue
		}
		if finding.RuleID == check.Check || hasTag(finding.Tags, "check:"+check.Check) {
			reason := check.Reason
			if reason == "" {
				reason = "matched pod_security.exclude_checks"
			}
			return reason, true
		}
	}

	return "", false
}

// matchesNetwork is module-scoped: it only runs for findings tagged module:network_policy and excludes by namespace.
func matchesNetwork(cfg NetworkPolicyConfig, finding models.Finding) (string, bool) {
	if !hasTag(finding.Tags, "module:network_policy") {
		return "", false
	}

	for _, namespace := range namespacesForFinding(finding) {
		if matchesAny(cfg.ExcludeNamespaces, namespace) {
			return "matched network_policy.exclude_namespaces", true
		}
	}

	return "", false
}

// namespacesForFinding returns the deduplicated list of namespace strings associated with a finding (top-level, subject, resource).
func namespacesForFinding(finding models.Finding) []string {
	candidates := []string{finding.Namespace}
	if finding.Subject != nil {
		candidates = append(candidates, finding.Subject.Namespace)
	}
	if finding.Resource != nil {
		candidates = append(candidates, finding.Resource.Namespace)
	}

	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate != "" && !slices.Contains(result, candidate) {
			result = append(result, candidate)
		}
	}
	return result
}

// matchesAny reports whether any of the patterns matches candidate via matchesPattern.
func matchesAny(patterns []string, candidate string) bool {
	for _, pattern := range patterns {
		if matchesPattern(pattern, candidate) {
			return true
		}
	}
	return false
}

// matchesPattern supports shell-style globs via path.Match and falls back to exact equality; empty inputs never match.
func matchesPattern(pattern string, candidate string) bool {
	pattern = strings.TrimSpace(pattern)
	candidate = strings.TrimSpace(candidate)
	if pattern == "" || candidate == "" {
		return false
	}
	ok, err := path.Match(pattern, candidate)
	if err == nil && ok {
		return true
	}
	return pattern == candidate
}

// hasTag reports whether wanted appears in the finding's tag slice.
func hasTag(tags []string, wanted string) bool {
	return slices.Contains(tags, wanted)
}
