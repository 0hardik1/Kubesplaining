// Package network analyzes NetworkPolicy coverage and permissiveness so that
// unprotected namespaces, uncovered workloads, and overly-broad policies surface as findings.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Analyzer produces network-policy-focused findings from a snapshot.
type Analyzer struct{}

// workload is a label-bearing reference used for matching against NetworkPolicy pod selectors.
type workload struct {
	Kind      string
	Name      string
	Namespace string
	Labels    map[string]string
}

// New returns a new network-policy analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "network"
}

// Analyze checks namespace-wide coverage, per-workload policy selection, and
// loose ingress/egress rules like "any namespace" or 0.0.0.0/0 egress.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}
	workloads := collectWorkloads(snapshot)
	namespaces := collectNamespaces(snapshot, workloads)
	policiesByNamespace := policiesByNamespace(snapshot.Resources.NetworkPolicies)

	for _, namespace := range namespaces {
		policies := policiesByNamespace[namespace]
		if len(policies) == 0 && !isSystemNamespace(namespace) {
			findings = appendUnique(findings, seen, namespaceFinding(namespace, "KUBE-NETPOL-COVERAGE-001", models.SeverityHigh, scoring.Clamp(7.4),
				"Namespace has no NetworkPolicies",
				"No NetworkPolicies were found for this namespace, so workloads are unrestricted by default.",
				map[string]any{"namespace": namespace},
				"Add default-deny ingress and egress policies, then explicitly open only the traffic each workload needs.",
				"noNetworkPolicies"))
			continue
		}

		if len(policies) > 0 && namespaceHasIngressButNoEgress(policies) {
			findings = appendUnique(findings, seen, namespaceFinding(namespace, "KUBE-NETPOL-COVERAGE-003", models.SeverityMedium, scoring.Clamp(5.8),
				"Ingress policies present but egress remains open",
				"This namespace has ingress-focused policies but no egress controls, so workloads can still connect out broadly.",
				map[string]any{"namespace": namespace},
				"Add explicit egress policies or a namespace-level default deny egress policy.",
				"noEgressPolicies"))
		}
	}

	for _, workload := range workloads {
		policies := policiesByNamespace[workload.Namespace]
		if len(policies) == 0 || isSystemNamespace(workload.Namespace) {
			continue
		}
		if !selectedByAnyPolicy(policies, workload.Labels) {
			findings = appendUnique(findings, seen, workloadFinding(workload, "KUBE-NETPOL-COVERAGE-002", models.SeverityMedium, scoring.Clamp(6.2),
				"Workload is not selected by any NetworkPolicy",
				"No NetworkPolicy selects this workload, leaving it unrestricted within the namespace defaults.",
				map[string]any{"labels": workload.Labels},
				"Ensure at least one policy selects this workload, even if the policy only applies a default-deny baseline.",
				"uncoveredWorkload"))
		}
	}

	for _, policy := range snapshot.Resources.NetworkPolicies {
		for _, ingress := range policy.Spec.Ingress {
			for _, peer := range ingress.From {
				if isAllNamespaces(peer.NamespaceSelector) {
					findings = appendUnique(findings, seen, policyFinding(policy, "KUBE-NETPOL-WEAKNESS-001", models.SeverityMedium, scoring.Clamp(5.5),
						"NetworkPolicy allows ingress from all namespaces",
						"This policy uses an empty namespace selector, effectively allowing traffic from any namespace.",
						map[string]any{"policy": policy.Name},
						"Replace broad namespace selectors with explicit namespace labels or tighter pod selectors.",
						"allNamespacesIngress"))
				}
			}
		}

		for _, egress := range policy.Spec.Egress {
			for _, peer := range egress.To {
				if peer.IPBlock != nil && (peer.IPBlock.CIDR == "0.0.0.0/0" || peer.IPBlock.CIDR == "::/0") {
					findings = appendUnique(findings, seen, policyFinding(policy, "KUBE-NETPOL-WEAKNESS-002", models.SeverityHigh, scoring.Clamp(7.6),
						"NetworkPolicy permits internet egress",
						"This policy explicitly allows outbound traffic to the entire internet.",
						map[string]any{"policy": policy.Name, "cidr": peer.IPBlock.CIDR},
						"Restrict egress to the specific CIDRs, services, or namespaces the workload genuinely needs.",
						"internetEgress"))
				}
			}
		}
	}

	return findings, nil
}

// collectWorkloads flattens the workload types in the snapshot into label-bearing references.
func collectWorkloads(snapshot models.Snapshot) []workload {
	workloads := make([]workload, 0, len(snapshot.Resources.Pods)+len(snapshot.Resources.Deployments))

	for _, pod := range snapshot.Resources.Pods {
		if isControlledPod(pod.ObjectMeta) {
			continue
		}
		workloads = append(workloads, workload{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels:    pod.Labels,
		})
	}
	for _, deployment := range snapshot.Resources.Deployments {
		workloads = append(workloads, workload{
			Kind:      "Deployment",
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
			Labels:    deployment.Spec.Template.Labels,
		})
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		workloads = append(workloads, workload{
			Kind:      "DaemonSet",
			Name:      daemonSet.Name,
			Namespace: daemonSet.Namespace,
			Labels:    daemonSet.Spec.Template.Labels,
		})
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		workloads = append(workloads, workload{
			Kind:      "StatefulSet",
			Name:      statefulSet.Name,
			Namespace: statefulSet.Namespace,
			Labels:    statefulSet.Spec.Template.Labels,
		})
	}
	for _, job := range snapshot.Resources.Jobs {
		workloads = append(workloads, workload{
			Kind:      "Job",
			Name:      job.Name,
			Namespace: job.Namespace,
			Labels:    job.Spec.Template.Labels,
		})
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		workloads = append(workloads, workload{
			Kind:      "CronJob",
			Name:      cronJob.Name,
			Namespace: cronJob.Namespace,
			Labels:    cronJob.Spec.JobTemplate.Spec.Template.Labels,
		})
	}

	return workloads
}

// collectNamespaces unions explicit Namespace objects with any namespace observed via workloads or policies so nothing slips through.
func collectNamespaces(snapshot models.Snapshot, workloads []workload) []string {
	namespaces := make([]string, 0, len(snapshot.Resources.Namespaces))
	for _, ns := range snapshot.Resources.Namespaces {
		namespaces = append(namespaces, ns.Name)
	}
	for _, workload := range workloads {
		if workload.Namespace != "" && !slices.Contains(namespaces, workload.Namespace) {
			namespaces = append(namespaces, workload.Namespace)
		}
	}
	for _, policy := range snapshot.Resources.NetworkPolicies {
		if policy.Namespace != "" && !slices.Contains(namespaces, policy.Namespace) {
			namespaces = append(namespaces, policy.Namespace)
		}
	}
	return namespaces
}

// policiesByNamespace indexes NetworkPolicies by their namespace for O(1) lookup.
func policiesByNamespace(policies []networkingv1.NetworkPolicy) map[string][]networkingv1.NetworkPolicy {
	result := make(map[string][]networkingv1.NetworkPolicy, len(policies))
	for _, policy := range policies {
		result[policy.Namespace] = append(result[policy.Namespace], policy)
	}
	return result
}

// namespaceHasIngressButNoEgress reports whether the namespace controls inbound traffic but leaves egress unrestricted.
func namespaceHasIngressButNoEgress(policies []networkingv1.NetworkPolicy) bool {
	hasIngress := false
	hasEgress := false
	for _, policy := range policies {
		for _, policyType := range effectivePolicyTypes(policy) {
			switch policyType {
			case networkingv1.PolicyTypeIngress:
				hasIngress = true
			case networkingv1.PolicyTypeEgress:
				hasEgress = true
			}
		}
	}
	return hasIngress && !hasEgress
}

// selectedByAnyPolicy reports whether at least one policy's pod selector matches the given labels.
func selectedByAnyPolicy(policies []networkingv1.NetworkPolicy, workloadLabels map[string]string) bool {
	for _, policy := range policies {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(workloadLabels)) {
			return true
		}
	}
	return false
}

// effectivePolicyTypes returns the PolicyTypes a NetworkPolicy effectively enforces, inferring the default when unset per the Kubernetes spec.
func effectivePolicyTypes(policy networkingv1.NetworkPolicy) []networkingv1.PolicyType {
	if len(policy.Spec.PolicyTypes) > 0 {
		return policy.Spec.PolicyTypes
	}

	types := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	if len(policy.Spec.Egress) > 0 {
		types = append(types, networkingv1.PolicyTypeEgress)
	}
	return types
}

// isAllNamespaces reports whether a namespace selector is empty, which in NetworkPolicy semantics means "every namespace".
func isAllNamespaces(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	return len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0
}

// isControlledPod reports whether a pod is controller-owned so the workload type is analyzed instead of the pod itself.
func isControlledPod(meta metav1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// isSystemNamespace reports whether the namespace is one of the standard control-plane namespaces that should not trip coverage findings.
func isSystemNamespace(namespace string) bool {
	return namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease"
}

// appendUnique deduplicates by Finding.ID before appending.
func appendUnique(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// namespaceFinding materializes a namespace-scoped network-policy finding.
func namespaceFinding(namespace, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:Namespace:%s", ruleID, namespace),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       score,
		Category:    models.CategoryLateralMovement,
		Title:       title,
		Description: description,
		Namespace:   namespace,
		Resource: &models.ResourceRef{
			Kind:      "Namespace",
			Name:      namespace,
			Namespace: namespace,
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Tags:        []string{"module:network_policy", "check:" + check},
	}
}

// workloadFinding materializes a workload-scoped network-policy finding.
func workloadFinding(workload workload, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s:%s", ruleID, workload.Kind, workload.Namespace, workload.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       score,
		Category:    models.CategoryLateralMovement,
		Title:       title,
		Description: description,
		Namespace:   workload.Namespace,
		Resource: &models.ResourceRef{
			Kind:      workload.Kind,
			Name:      workload.Name,
			Namespace: workload.Namespace,
			APIGroup:  workloadAPIGroup(workload.Kind),
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Tags:        []string{"module:network_policy", "check:" + check},
	}
}

// policyFinding materializes a finding pointing at a specific NetworkPolicy that is too permissive.
func policyFinding(policy networkingv1.NetworkPolicy, ruleID string, severity models.Severity, score float64, title, description string, evidence map[string]any, remediation, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s", ruleID, policy.Namespace, policy.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       score,
		Category:    models.CategoryLateralMovement,
		Title:       title,
		Description: description,
		Namespace:   policy.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "NetworkPolicy",
			Name:      policy.Name,
			Namespace: policy.Namespace,
			APIGroup:  networkingv1.GroupName,
		},
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Tags:        []string{"module:network_policy", "check:" + check},
	}
}

// workloadAPIGroup returns the Kubernetes API group for a workload kind.
func workloadAPIGroup(kind string) string {
	switch kind {
	case "Deployment", "DaemonSet", "StatefulSet":
		return appsv1.GroupName
	case "Job", "CronJob":
		return batchv1.GroupName
	default:
		return ""
	}
}
