package privesc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	sinkClusterAdmin      = "sink:cluster_admin"
	sinkKubeSystemSecrets = "sink:kube_system_secrets"
	sinkNodeEscape        = "sink:node_escape"
)

// nodeID returns the canonical graph-node ID for a subject.
func nodeID(ref models.SubjectRef) string {
	return "subject:" + ref.Key()
}

// BuildGraph constructs the privilege-escalation graph: subjects become nodes,
// sensitive outcomes become sinks, and permissions or pod escape conditions become edges.
func BuildGraph(snapshot models.Snapshot) *models.EscalationGraph {
	graph := &models.EscalationGraph{
		Nodes: map[string]*models.EscalationNode{},
	}

	addSink(graph, sinkClusterAdmin, models.TargetClusterAdmin)
	addSink(graph, sinkKubeSystemSecrets, models.TargetKubeSystemSecrets)
	addSink(graph, sinkNodeEscape, models.TargetNodeEscape)

	subjectsByNs := serviceAccountsByNamespace(snapshot)
	podSAsByNs := podServiceAccountsByNamespace(snapshot)

	effective := permissions.Aggregate(snapshot)
	for _, perms := range effective {
		ensureSubjectNode(graph, perms.Subject)
		for _, rule := range perms.Rules {
			addEdgesForRule(graph, perms.Subject, rule, subjectsByNs, podSAsByNs)
		}
	}

	for _, pod := range snapshot.Resources.Pods {
		addPodEscapeEdges(graph, pod)
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			if ref.Name == "" {
				continue
			}
			ensureSubjectNode(graph, ref)
			addEdge(graph, nodeID(ref), sinkClusterAdmin, &models.EscalationEdge{
				Technique:   "KUBE-RBAC-OVERBROAD-001",
				Action:      "bound_to_cluster_admin",
				Permission:  "cluster-admin",
				Description: fmt.Sprintf("bound to cluster-admin via %s", binding.Name),
			})
		}
	}

	return graph
}

// addEdgesForRule inspects one aggregated RBAC rule and emits the graph edges it enables (to sinks or to impersonable subjects).
func addEdgesForRule(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rule permissions.EffectiveRule,
	subjectsByNs map[string][]models.SubjectRef,
	podSAsByNs map[string][]models.SubjectRef,
) {
	from := nodeID(subject)
	clusterScope := rule.Namespace == ""

	if hasAll(rule.Verbs, "*") && hasAll(rule.Resources, "*") && hasAll(rule.APIGroups, "*") {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-017",
			Action:      "wildcard_permission",
			Permission:  "*:*:*",
			Description: "wildcard verbs on wildcard resources in wildcard API groups",
		})
		return
	}

	if matchesResourceVerb(rule, []string{"rolebindings", "clusterrolebindings"}, []string{"create", "update", "patch"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-010",
			Action:      "modify_role_binding",
			Permission:  verbResource(rule, "rolebindings|clusterrolebindings"),
			Description: "can create or mutate role bindings to grant itself any role",
		})
	}

	if matchesResourceVerb(rule, []string{"roles", "clusterroles"}, []string{"bind", "escalate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-009",
			Action:      "bind_or_escalate",
			Permission:  verbResource(rule, "roles|clusterroles"),
			Description: "can bypass RBAC escalation checks via bind/escalate",
		})
	}

	if matchesResourceVerb(rule, []string{"users", "groups", "serviceaccounts"}, []string{"impersonate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-008",
			Action:      "impersonate",
			Permission:  verbResource(rule, "users|groups|serviceaccounts"),
			Description: "can impersonate another identity",
		})
	}

	if matchesResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch"}) {
		if clusterScope || rule.Namespace == "kube-system" {
			addEdge(graph, from, sinkKubeSystemSecrets, &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-005",
				Action:      "read_secrets",
				Permission:  verbResource(rule, "secrets"),
				Description: "can read secrets in kube-system or cluster-wide",
			})
		}
	}

	if matchesResourceVerb(rule, []string{"nodes/proxy"}, []string{"get"}) {
		addEdge(graph, from, sinkNodeEscape, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-012",
			Action:      "nodes_proxy",
			Permission:  "get nodes/proxy",
			Description: "can reach kubelet API via nodes/proxy WebSocket verb confusion",
		})
	}

	if matchesResourceVerb(rule, []string{"pods"}, []string{"create"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, subjectsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-001",
				Action:      "pod_create_token_theft",
				Permission:  "create pods",
				Description: fmt.Sprintf("can create pods that mount ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}

	if matchesResourceVerb(rule, []string{"pods/exec", "pods/attach"}, []string{"create", "get"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, podSAsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-004",
				Action:      "pod_exec",
				Permission:  verbResource(rule, "pods/exec|pods/attach"),
				Description: fmt.Sprintf("can exec into pods running as ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}

	if matchesResourceVerb(rule, []string{"serviceaccounts/token"}, []string{"create"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, subjectsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-014",
				Action:      "token_request",
				Permission:  "create serviceaccounts/token",
				Description: fmt.Sprintf("can mint tokens for ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}
}

// addPodEscapeEdges links a pod's ServiceAccount to the node-escape sink when the pod has host-escape-enabling settings.
func addPodEscapeEdges(graph *models.EscalationGraph, pod corev1.Pod) {
	reasons := podEscapeReasons(pod)
	if len(reasons) == 0 {
		return
	}
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	ref := models.SubjectRef{Kind: "ServiceAccount", Name: saName, Namespace: pod.Namespace}
	ensureSubjectNode(graph, ref)
	addEdge(graph, nodeID(ref), sinkNodeEscape, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE",
		Action:      "pod_host_escape",
		Permission:  strings.Join(reasons, ","),
		Description: fmt.Sprintf("runs in pod %s/%s with %s", pod.Namespace, pod.Name, strings.Join(reasons, ", ")),
	})
}

// podEscapeReasons lists the reasons a pod could be used to escape to the node (host namespaces, privileged, sensitive hostPath).
func podEscapeReasons(pod corev1.Pod) []string {
	var reasons []string
	if pod.Spec.HostPID {
		reasons = append(reasons, "hostPID")
	}
	if pod.Spec.HostNetwork {
		reasons = append(reasons, "hostNetwork")
	}
	if pod.Spec.HostIPC {
		reasons = append(reasons, "hostIPC")
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			reasons = append(reasons, "privileged")
			break
		}
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath == nil {
			continue
		}
		if isSensitiveHostPath(volume.HostPath.Path) {
			reasons = append(reasons, "hostPath:"+volume.HostPath.Path)
		}
	}
	return reasons
}

// isSensitiveHostPath reports whether a hostPath value is one of the well-known escape-enabling mounts.
func isSensitiveHostPath(path string) bool {
	sensitive := []string{
		"/",
		"/etc",
		"/etc/kubernetes",
		"/var/run/docker.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
		"/var/lib/kubelet",
		"/var/lib/etcd",
		"/var/log",
	}
	for _, s := range sensitive {
		if path == s {
			return true
		}
	}
	return false
}

// addSink registers a terminal target node in the graph.
func addSink(graph *models.EscalationGraph, id string, target models.EscalationTarget) {
	graph.Nodes[id] = &models.EscalationNode{ID: id, IsSink: true, Target: target}
}

// ensureSubjectNode inserts a subject node into the graph if it does not already exist.
func ensureSubjectNode(graph *models.EscalationGraph, ref models.SubjectRef) {
	id := nodeID(ref)
	if _, ok := graph.Nodes[id]; ok {
		return
	}
	graph.Nodes[id] = &models.EscalationNode{
		ID:       id,
		Subject:  ref,
		IsSystem: isSystemSubject(ref),
	}
}

// isSystemSubject flags built-in control-plane subjects so path search does not traverse them.
func isSystemSubject(ref models.SubjectRef) bool {
	if strings.HasPrefix(ref.Name, "system:") {
		return true
	}
	if ref.Kind == "ServiceAccount" && (ref.Namespace == "kube-system" || ref.Namespace == "kube-public" || ref.Namespace == "kube-node-lease") {
		return true
	}
	return false
}

// addEdge sets the endpoints on edge and appends it to the graph.
func addEdge(graph *models.EscalationGraph, from, to string, edge *models.EscalationEdge) {
	edge.From = from
	edge.To = to
	graph.Edges = append(graph.Edges, edge)
}

// podCreateTargets returns the candidate service accounts a subject can mount by creating pods: all SAs when cluster-scoped, or namespace-local otherwise.
func podCreateTargets(clusterScope bool, namespace string, subjectsByNs map[string][]models.SubjectRef) []models.SubjectRef {
	if clusterScope {
		var all []models.SubjectRef
		for _, refs := range subjectsByNs {
			all = append(all, refs...)
		}
		return all
	}
	return subjectsByNs[namespace]
}

// serviceAccountsByNamespace indexes known ServiceAccounts and guarantees each namespace has a "default" entry.
func serviceAccountsByNamespace(snapshot models.Snapshot) map[string][]models.SubjectRef {
	result := map[string][]models.SubjectRef{}
	for _, sa := range snapshot.Resources.ServiceAccounts {
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace}
		result[sa.Namespace] = append(result[sa.Namespace], ref)
	}
	for _, ns := range snapshot.Resources.Namespaces {
		if !containsSubject(result[ns.Name], "default") {
			result[ns.Name] = append(result[ns.Name], models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: ns.Name})
		}
	}
	return result
}

// podServiceAccountsByNamespace indexes the distinct ServiceAccounts that pods actually mount, used as exec-target candidates.
func podServiceAccountsByNamespace(snapshot models.Snapshot) map[string][]models.SubjectRef {
	result := map[string][]models.SubjectRef{}
	seen := map[string]struct{}{}
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: sa, Namespace: pod.Namespace}
		if _, ok := seen[ref.Key()]; ok {
			continue
		}
		seen[ref.Key()] = struct{}{}
		result[pod.Namespace] = append(result[pod.Namespace], ref)
	}
	return result
}

// containsSubject reports whether the slice already has a SubjectRef with the given name.
func containsSubject(refs []models.SubjectRef, name string) bool {
	for _, ref := range refs {
		if ref.Name == name {
			return true
		}
	}
	return false
}

// matchesResourceVerb reports whether a rule covers any of the given resources and any of the given verbs (wildcards match all).
func matchesResourceVerb(rule permissions.EffectiveRule, resources, verbs []string) bool {
	return hasAnyValue(rule.Resources, resources) && hasAnyValue(rule.Verbs, verbs)
}

// hasAnyValue reports whether values contains any of the wanted tokens, treating "*" in values as a match-all wildcard.
func hasAnyValue(values []string, wanted []string) bool {
	if slices.Contains(values, "*") {
		return true
	}
	for _, w := range wanted {
		if slices.Contains(values, w) {
			return true
		}
	}
	return false
}

// hasAll reports whether every expected value is present in values (or values contains a wildcard).
func hasAll(values []string, expected ...string) bool {
	if slices.Contains(values, "*") {
		return true
	}
	for _, e := range expected {
		if !slices.Contains(values, e) {
			return false
		}
	}
	return true
}

// verbResource formats a rule's verbs together with a resource label for display in edge Permission strings.
func verbResource(rule permissions.EffectiveRule, resourceLabel string) string {
	verbs := strings.Join(rule.Verbs, ",")
	return fmt.Sprintf("%s %s", verbs, resourceLabel)
}

// subjectRef converts an rbacv1.Subject to a SubjectRef, defaulting an empty ServiceAccount namespace to fallbackNamespace.
func subjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
	ref := models.SubjectRef{Kind: subject.Kind, Name: subject.Name}
	if subject.Kind == "ServiceAccount" {
		ref.Namespace = subject.Namespace
		if ref.Namespace == "" {
			ref.Namespace = fallbackNamespace
		}
	}
	return ref
}
