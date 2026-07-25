package privesc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	sinkClusterAdmin         = "sink:cluster_admin"
	sinkKubeSystemSecrets    = "sink:kube_system_secrets"
	sinkNodeEscape           = "sink:node_escape"
	sinkSystemMasters        = "sink:system_masters"
	sinkTokenMint            = "sink:token_mint"
	sinkNamespaceAdminPrefix = "sink:namespace_admin:"
)

// csrAnnotation tags a subject with one of the two halves of the CSR-approval
// privesc primitive. A subject that accumulates both halves (after every rule
// has been processed) gets an edge to the system_masters sink in finalizeCSRApprovals.
type csrAnnotation int

const (
	csrAnnotationCreate csrAnnotation = 1 << iota
	csrAnnotationApprove
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
	addSink(graph, sinkSystemMasters, models.TargetSystemMasters)
	addSink(graph, sinkTokenMint, models.TargetTokenMint)

	subjectsByNs := serviceAccountsByNamespace(snapshot)
	podSAsByNs := podServiceAccountsByNamespace(snapshot)

	// csrCapabilities accumulates the two CSR-approval halves (create CSRs +
	// approve at the /approval subresource) per subject. Both verbs across the
	// subject's effective rules are required before an edge to system_masters is
	// emitted, so collection runs across the per-rule loop and the finalize step
	// emits the edge once both halves are present.
	csrCapabilities := map[string]csrAnnotation{}

	privilegedNamespaces := namespacesAllowingPrivileged(snapshot)

	effective := permissions.Aggregate(snapshot)
	for _, perms := range effective {
		ensureSubjectNode(graph, perms.Subject)
		for _, rule := range perms.Rules {
			addEdgesForRule(graph, perms.Subject, rule, subjectsByNs, podSAsByNs, csrCapabilities)
		}
		// Correlation edges that need the subject's full rule set at once
		// (two RBAC verbs held together), rather than one rule at a time.
		addSecretMintEdge(graph, perms.Subject, perms.Rules)
		addNodeMigrateEdge(graph, perms.Subject, perms.Rules)
		addPrivilegedPodCreateEdges(graph, perms.Subject, perms.Rules, privilegedNamespaces)
	}

	finalizeCSRApprovals(graph, csrCapabilities)

	// Runs after the per-subject loop so every namespace-admin sink that any
	// subject reaches already exists as a node.
	addNamespaceAdminTokenTheftEdges(graph, subjectsByNs)

	// Confused-deputy bridges need every controller SA node to already exist, and a
	// controller holding no RBAC of its own never appears in permissions.Aggregate.
	// Materialize every known ServiceAccount first, then bridge in a second pass.
	for _, refs := range subjectsByNs {
		for _, ref := range refs {
			ensureSubjectNode(graph, ref)
		}
	}
	for _, perms := range effective {
		addConfusedDeputyEdges(graph, perms.Subject, perms.Rules)
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

	addControlPlaneEscapeEdges(graph, snapshot)

	addCloudEdges(graph, snapshot)

	return graph
}

// finalizeCSRApprovals emits a csr_approve edge from any subject that holds both
// halves of the CSR-mint primitive (create on certificatesigningrequests AND
// update/patch on certificatesigningrequests/approval, both cluster-scoped) to
// the system_masters sink. The CSR mint primitive is the only one in the model
// today that requires correlating two separate RBAC rules on the same subject,
// hence the two-pass build.
func finalizeCSRApprovals(graph *models.EscalationGraph, caps map[string]csrAnnotation) {
	const both = csrAnnotationCreate | csrAnnotationApprove
	for subjectKey, ann := range caps {
		if ann&both != both {
			continue
		}
		from := "subject:" + subjectKey
		// Defensive: the subject node may not yet exist if the caller stored an
		// annotation without first walking effective rules. ensureSubjectNode is
		// keyed on SubjectRef, so we parse the key back; the graph builder is
		// the only writer of caps, so this branch is effectively unreachable but
		// kept simple in case future code paths short-circuit.
		if _, ok := graph.Nodes[from]; !ok {
			continue
		}
		addEdge(graph, from, sinkSystemMasters, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-011",
			Action:      "csr_approve",
			Permission:  "create certificatesigningrequests + update certificatesigningrequests/approval",
			Description: "can submit a CSR with system:masters in its Subject and self-approve it, minting a kubelet-signed cluster-admin client cert",
		})
	}
}

// annotateSubjectCSR records that subject holds one of the two CSR-approval halves.
// Stored on a side map (passed in by BuildGraph) because addEdgesForRule sees one
// rule at a time; the edge is only safe to emit once we've confirmed both halves
// landed across the subject's full effective rule set.
func annotateSubjectCSR(caps map[string]csrAnnotation, subject models.SubjectRef, half csrAnnotation) {
	caps[subject.Key()] |= half
}

// addEdgesForRule inspects one aggregated RBAC rule and emits the graph edges it enables (to sinks or to impersonable subjects).
// csrCapabilities accumulates the per-subject CSR-mint halves across rules so finalizeCSRApprovals
// can emit the csr_approve edge once both halves are present.
func addEdgesForRule(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rule permissions.EffectiveRule,
	subjectsByNs map[string][]models.SubjectRef,
	podSAsByNs map[string][]models.SubjectRef,
	csrCapabilities map[string]csrAnnotation,
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

	// modify_role_binding: cluster-scoped grants reach cluster-admin (write to any (Cluster)RoleBinding
	// → bind to any role anywhere). Namespace-scoped grants on `rolebindings` reach namespace-admin in
	// the binding's namespace (the subject can RoleBind itself to any ClusterRole, scoped to that ns).
	// Namespace-scoped grants on `clusterrolebindings` are dead RBAC (clusterrolebindings is a
	// cluster-scoped resource and the authorizer never allows the verb to succeed via a RoleBinding).
	if clusterScope && matchesResourceVerb(rule, []string{"rolebindings", "clusterrolebindings"}, []string{"create", "update", "patch"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-010",
			Action:      "modify_role_binding",
			Permission:  verbResource(rule, "rolebindings|clusterrolebindings"),
			Description: "can create or mutate role bindings to grant itself any role",
		})
	}
	if !clusterScope && matchesResourceVerb(rule, []string{"rolebindings"}, []string{"create", "update", "patch"}) {
		sink := ensureNamespaceAdminSink(graph, rule.Namespace)
		addEdge(graph, from, sink, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-010",
			Action:      "modify_role_binding",
			Permission:  verbResource(rule, "rolebindings"),
			Description: fmt.Sprintf("can create or mutate RoleBindings in namespace %s to grant itself any role within %s", rule.Namespace, rule.Namespace),
		})
	}

	// bind/escalate on (cluster)roles: same scope reasoning as modify_role_binding. Namespace-scoped
	// grants on `roles` let the subject bind any ClusterRole inside the binding's namespace; on
	// `clusterroles` they're dead RBAC.
	if clusterScope && matchesResourceVerb(rule, []string{"roles", "clusterroles"}, []string{"bind", "escalate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-009",
			Action:      "bind_or_escalate",
			Permission:  verbResource(rule, "roles|clusterroles"),
			Description: "can bypass RBAC escalation checks via bind/escalate",
		})
	}
	if !clusterScope && matchesResourceVerb(rule, []string{"roles"}, []string{"bind", "escalate"}) {
		sink := ensureNamespaceAdminSink(graph, rule.Namespace)
		addEdge(graph, from, sink, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-009",
			Action:      "bind_or_escalate",
			Permission:  verbResource(rule, "roles"),
			Description: fmt.Sprintf("can bypass RBAC escalation checks via bind/escalate within namespace %s", rule.Namespace),
		})
	}

	// impersonate users/groups: users and groups are not namespaced K8s objects, so a RoleBinding
	// granting these verbs is dead RBAC (the authorizer never lets it succeed). Only emit the
	// cluster-admin edge for cluster-scoped grants.
	if clusterScope && matchesResourceVerb(rule, []string{"users", "groups"}, []string{"impersonate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-008",
			Action:      "impersonate",
			Permission:  verbResource(rule, "users|groups"),
			Description: "can impersonate another identity",
		})
	}

	if clusterScope && matchesResourceVerb(rule, []string{"groups"}, []string{"impersonate"}) {
		addEdge(graph, from, sinkSystemMasters, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-008",
			Action:      "impersonate_system_masters",
			Permission:  verbResource(rule, "groups"),
			Description: "can impersonate the system:masters group, bypassing all RBAC",
		})
	}

	// impersonate serviceaccounts: cluster-scoped grants reach any SA cluster-wide (including
	// kube-system controllers), so we treat that as cluster-admin. Namespace-scoped grants only
	// reach SAs in the binding's namespace — model those as per-target edges so multi-hop chains
	// can still surface a real path if one of those SAs reaches a sink.
	if matchesResourceVerb(rule, []string{"serviceaccounts"}, []string{"impersonate"}) {
		if clusterScope {
			addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-008",
				Action:      "impersonate",
				Permission:  verbResource(rule, "serviceaccounts"),
				Description: "can impersonate any ServiceAccount cluster-wide",
			})
		} else {
			for _, target := range podCreateTargets(false, rule.Namespace, subjectsByNs) {
				if target.Key() == subject.Key() {
					continue
				}
				ensureSubjectNode(graph, target)
				addEdge(graph, from, nodeID(target), &models.EscalationEdge{
					Technique:   "KUBE-PRIVESC-008",
					Action:      "impersonate_serviceaccount",
					Permission:  verbResource(rule, "serviceaccounts"),
					Description: fmt.Sprintf("can impersonate ServiceAccount %s/%s", target.Namespace, target.Name),
				})
			}
		}
	}

	// read_secrets reaches the kube_system_secrets sink only from an unrestricted
	// grant: the sink means "compromise the kube-system secret store", which a
	// resourceNames-scoped grant (a get on a fixed set of named secrets) cannot
	// achieve. list/watch are already dropped for a name-scoped rule by the matcher;
	// this guard additionally suppresses the surviving name-scoped `get` so a
	// least-privilege "get one specific secret" grant no longer produces a spurious
	// kube-system-secrets escalation path. (Inspecting whether a named secret is
	// itself sensitive is the resourceName-aware enhancement tracked in the research
	// doc; until then we prefer no false positive here.)
	if !rule.NameScoped() && matchesResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch"}) {
		if clusterScope || rule.Namespace == "kube-system" {
			// Label the edge with the technique of the strongest verb held so the
			// correlation pass amplifies the matching rbac finding: list/watch
			// (enumerate everything) is KUBE-PRIVESC-005, a get-only grant is -006.
			technique := "KUBE-PRIVESC-006"
			if matchesResourceVerb(rule, []string{"secrets"}, []string{"list", "watch"}) {
				technique = "KUBE-PRIVESC-005"
			}
			addEdge(graph, from, sinkKubeSystemSecrets, &models.EscalationEdge{
				Technique:   technique,
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

	if matchesResourceVerb(rule, []string{"pods/ephemeralcontainers"}, []string{"update", "patch"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, podSAsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-013",
				Action:      "ephemeral_container_inject",
				Permission:  verbResource(rule, "pods/ephemeralcontainers"),
				Description: fmt.Sprintf("can inject an ephemeral container into pods running as ServiceAccount %s/%s", target.Namespace, target.Name),
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

	if clusterScope && matchesResourceVerb(rule, []string{"serviceaccounts/token"}, []string{"create"}) {
		addEdge(graph, from, sinkTokenMint, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-014",
			Action:      "mint_arbitrary_token",
			Permission:  "create serviceaccounts/token (cluster-wide)",
			Description: "can mint a service-account token for any ServiceAccount in any namespace",
		})
	}

	// CSR approval → system:masters. A subject that can both `create
	// certificatesigningrequests` AND `update certificatesigningrequests/approval`
	// can issue a client cert whose Subject carries `O=system:masters` (or any
	// principal it chooses) and authenticate as cluster-admin. CSRs are cluster-
	// scoped, so this edge requires cluster-scoped grants for both verbs.
	//
	// We need to see both verbs across the same subject's effective rules, but
	// addEdgesForRule sees one rule at a time. The simplest correct treatment is
	// to emit a candidate edge whenever EITHER verb is held cluster-scoped, then
	// drop the candidate in a graph-wide pass if the other verb is missing. That
	// pass lives in BuildGraph after every rule has been processed.
	if clusterScope && matchesResourceVerb(rule, []string{"certificatesigningrequests"}, []string{"create"}) {
		annotateSubjectCSR(csrCapabilities, subject, csrAnnotationCreate)
	}
	if clusterScope && matchesResourceVerb(rule, []string{"certificatesigningrequests/approval"}, []string{"update", "patch"}) {
		annotateSubjectCSR(csrCapabilities, subject, csrAnnotationApprove)
	}
}

// addNamespaceAdminTokenTheftEdges links each namespace-admin sink onward to every
// ServiceAccount living in that namespace. Namespace-admin over X means the holder
// can create a pod as any SA in X, exec into its pods, or read its token Secret, so
// every co-located identity is effectively theirs. This is what turns a bounded
// namespace grant into a cluster-wide path when X co-hosts a privileged controller.
//
// Iteration runs over a sorted key list so edge order stays deterministic across runs.
func addNamespaceAdminTokenTheftEdges(graph *models.EscalationGraph, subjectsByNs map[string][]models.SubjectRef) {
	sinkIDs := make([]string, 0, len(graph.Nodes))
	for id, node := range graph.Nodes {
		if node.IsSink && node.Target == models.TargetNamespaceAdmin {
			sinkIDs = append(sinkIDs, id)
		}
	}
	sort.Strings(sinkIDs)

	for _, sinkID := range sinkIDs {
		namespace := graph.Nodes[sinkID].TargetNamespace
		for _, target := range subjectsByNs[namespace] {
			ensureSubjectNode(graph, target)
			addEdge(graph, sinkID, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-010",
				Action:      "colocated_sa_token_theft",
				Permission:  "namespace-admin in " + namespace,
				Description: fmt.Sprintf("can steal the token of co-located ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}
}

// addSecretMintEdge emits the KUBE-PRIVESC-007 edge: a subject that holds BOTH
// cluster-scoped `create secrets` and `get secrets` can create a legacy
// ServiceAccount-token Secret and read the controller-populated token, minting
// a token for any ServiceAccount. We model only the cluster-scoped (mint-any)
// case in the graph (-> sinkTokenMint); narrower namespaced create+get still
// surfaces as the standalone KUBE-PRIVESC-007 rbac finding.
func addSecretMintEdge(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule) {
	hasCreate, hasGet := false, false
	for _, r := range rules {
		if r.Namespace != "" {
			continue
		}
		if matchesResourceVerb(r, []string{"secrets"}, []string{"create"}) {
			hasCreate = true
		}
		if matchesResourceVerb(r, []string{"secrets"}, []string{"get"}) {
			hasGet = true
		}
	}
	if !hasCreate || !hasGet {
		return
	}
	ensureSubjectNode(graph, subject)
	addEdge(graph, nodeID(subject), sinkTokenMint, &models.EscalationEdge{
		Technique:   "KUBE-PRIVESC-007",
		Action:      "secret_mint_token",
		Permission:  "create + get secrets (cluster-wide)",
		Description: "can create a legacy ServiceAccount-token Secret and read the minted token for any ServiceAccount",
	})
}

// addNodeMigrateEdge emits the KUBE-PRIVESC-016 edge: a subject that can
// `delete pods` AND manipulate node scheduling cluster-wide (`update`/`patch`
// on nodes/status, or `delete nodes`) can evict sensitive pods and steer their
// reschedule onto an attacker-controlled node, then steal their tokens.
func addNodeMigrateEdge(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule) {
	hasDeletePods, hasNodeManip := false, false
	for _, r := range rules {
		if matchesResourceVerb(r, []string{"pods"}, []string{"delete"}) {
			hasDeletePods = true
		}
		if r.Namespace != "" {
			continue
		}
		if matchesResourceVerb(r, []string{"nodes/status"}, []string{"update", "patch"}) ||
			matchesResourceVerb(r, []string{"nodes"}, []string{"delete"}) {
			hasNodeManip = true
		}
	}
	if !hasDeletePods || !hasNodeManip {
		return
	}
	ensureSubjectNode(graph, subject)
	addEdge(graph, nodeID(subject), sinkNodeEscape, &models.EscalationEdge{
		Technique:   "KUBE-PRIVESC-016",
		Action:      "node_drain_migrate",
		Permission:  "delete pods + node scheduling control",
		Description: "can migrate sensitive pods onto an attacker-controlled node via eviction + node manipulation",
	})
}

// addPrivilegedPodCreateEdges emits the KUBE-PRIVESC-002 edge: a subject that
// can `create pods` in a namespace whose Pod Security Admission posture does
// not block privileged pods can launch a privileged pod and escape to the node.
// Full wildcards are already cluster-admin (-017), so they are skipped.
func addPrivilegedPodCreateEdges(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule, privilegedNamespaces map[string]bool) {
	for _, r := range rules {
		if !matchesResourceVerb(r, []string{"pods"}, []string{"create"}) {
			continue
		}
		if hasAll(r.Verbs, "*") && hasAll(r.Resources, "*") && hasAll(r.APIGroups, "*") {
			continue
		}
		if !podCreateAllowsPrivileged(r.Namespace == "", r.Namespace, privilegedNamespaces) {
			continue
		}
		ensureSubjectNode(graph, subject)
		addEdge(graph, nodeID(subject), sinkNodeEscape, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-002",
			Action:      "pod_create_privileged_escape",
			Permission:  "create pods (Pod Security Admission does not block privileged)",
			Description: "can create a privileged pod that escapes to the node",
		})
		return // one node-escape edge per subject is sufficient
	}
}

// podCreateAllowsPrivileged reports whether a pod-create grant can land a
// privileged pod: a cluster-scoped grant succeeds if any namespace allows
// privileged; a namespaced grant only if its own namespace does.
func podCreateAllowsPrivileged(clusterScope bool, namespace string, privilegedNamespaces map[string]bool) bool {
	if clusterScope {
		return len(privilegedNamespaces) > 0
	}
	return privilegedNamespaces[namespace]
}

// namespacesAllowingPrivileged mirrors the rbac analyzer helper of the same
// name: non-system namespaces whose Pod Security Admission `enforce` label is
// absent or "privileged" (baseline/restricted block privileged). Duplicated
// here rather than shared because privesc and rbac do not import each other.
func namespacesAllowingPrivileged(snapshot models.Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, ns := range snapshot.Resources.Namespaces {
		switch ns.Name {
		case "kube-system", "kube-public", "kube-node-lease":
			continue
		}
		switch ns.Labels["pod-security.kubernetes.io/enforce"] {
		case "", "privileged":
			out[ns.Name] = true
		}
	}
	return out
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

// controlPlaneRoleLabels are the node labels that mark a control-plane node. The
// legacy "master" label is still present on clusters upgraded from pre-1.24.
var controlPlaneRoleLabels = []string{
	"node-role.kubernetes.io/control-plane",
	"node-role.kubernetes.io/master",
}

// clusterHasSchedulableControlPlaneNode reports whether the snapshot contains a
// control-plane node that ordinary workloads can land on, meaning it carries no
// NoSchedule taint for its control-plane role. This gates the node-escape
// continuation: on a properly tainted multi-node cluster an escaping tenant pod
// reaches a worker node, where no cluster PKI lives, so continuing to
// system:masters would be a false positive. Single-node clusters (kind, k3s,
// minikube, many dev clusters) leave the control-plane node schedulable, and
// there node root really is cluster-admin.
func clusterHasSchedulableControlPlaneNode(snapshot models.Snapshot) bool {
	for _, node := range snapshot.Resources.Nodes {
		if !isControlPlaneNode(node) {
			continue
		}
		if !hasControlPlaneNoScheduleTaint(node) {
			return true
		}
	}
	return false
}

// isControlPlaneNode reports whether a node carries a control-plane role label.
func isControlPlaneNode(node corev1.Node) bool {
	for _, label := range controlPlaneRoleLabels {
		if _, ok := node.Labels[label]; ok {
			return true
		}
	}
	return false
}

// hasControlPlaneNoScheduleTaint reports whether a node repels ordinary workloads
// via a NoSchedule (or NoExecute) taint on its control-plane role key.
func hasControlPlaneNoScheduleTaint(node corev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if !slices.Contains(controlPlaneRoleLabels, taint.Key) {
			continue
		}
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			return true
		}
	}
	return false
}

// addControlPlaneEscapeEdges makes the node_escape sink traversable and links it
// onward, but only when a schedulable control-plane node exists. Root on such a
// node reads /etc/kubernetes/pki/ca.key (forge an O=system:masters client cert
// offline) and sa.key (forge a token for any ServiceAccount), and can drop a file
// into /etc/kubernetes/manifests to run a static pod that no admission controller
// ever sees.
func addControlPlaneEscapeEdges(graph *models.EscalationGraph, snapshot models.Snapshot) {
	if !clusterHasSchedulableControlPlaneNode(snapshot) {
		return
	}
	node, ok := graph.Nodes[sinkNodeEscape]
	if !ok {
		return
	}
	node.Traversable = true

	addEdge(graph, sinkNodeEscape, sinkSystemMasters, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE-CONTROLPLANE-001",
		Action:      "control_plane_pki_theft",
		Permission:  "root on a schedulable control-plane node",
		Description: "can read /etc/kubernetes/pki/ca.key and forge an O=system:masters client certificate offline",
	})
	addEdge(graph, sinkNodeEscape, sinkTokenMint, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE-CONTROLPLANE-001",
		Action:      "static_pod_admission_bypass",
		Permission:  "write access to /etc/kubernetes/manifests",
		Description: "can read sa.key to forge any ServiceAccount token, and drop static pods that bypass all admission control",
	})
}

// addSink registers a terminal target node in the graph.
func addSink(graph *models.EscalationGraph, id string, target models.EscalationTarget) {
	graph.Nodes[id] = &models.EscalationNode{ID: id, IsSink: true, Target: target}
}

// ensureNamespaceAdminSink lazily registers (and returns the ID of) the per-namespace
// "namespace-admin in <ns>" sink. Each namespace gets its own sink node so a subject
// with namespace-scoped grants in multiple namespaces produces one finding per namespace.
func ensureNamespaceAdminSink(graph *models.EscalationGraph, namespace string) string {
	id := sinkNamespaceAdminPrefix + namespace
	if _, ok := graph.Nodes[id]; !ok {
		graph.Nodes[id] = &models.EscalationNode{
			ID:     id,
			IsSink: true,
			// Namespace-admin is not a dead end: it implies control over every
			// identity co-located in the namespace. See addNamespaceAdminTokenTheftEdges.
			Traversable:     true,
			Target:          models.TargetNamespaceAdmin,
			TargetNamespace: namespace,
		}
	}
	return id
}

// ensureSubjectNode inserts a subject node into the graph if it does not already exist.
func ensureSubjectNode(graph *models.EscalationGraph, ref models.SubjectRef) {
	id := nodeID(ref)
	if _, ok := graph.Nodes[id]; ok {
		return
	}
	graph.Nodes[id] = &models.EscalationNode{
		ID:             id,
		Subject:        ref,
		IsSystem:       isSystemSubject(ref),
		IsControlPlane: isControlPlaneSubject(ref),
	}
}

// isSystemSubject flags built-in control-plane identities by name prefix. These are
// neither traversed nor seeded: laundering a chain through the control plane's own
// built-in identities is a modeling artifact rather than an attack.
//
// Note: external cloud-IAM nodes carry IDs prefixed "external:aws-iam:" (see
// cloud_edges.go) and never flow through ensureSubjectNode, so isSystemSubject
// is never asked about them. The "external:" prefix is therefore non-system by
// construction; the pathfinder skips them by checking node.IsExternal directly.
func isSystemSubject(ref models.SubjectRef) bool {
	return strings.HasPrefix(ref.Name, "system:")
}

// isControlPlaneSubject flags a non-built-in ServiceAccount in a control-plane
// namespace. These are traversable intermediates but not path-search sources; see
// the IsControlPlane doc comment on models.EscalationNode for the reasoning.
func isControlPlaneSubject(ref models.SubjectRef) bool {
	if isSystemSubject(ref) || ref.Kind != "ServiceAccount" {
		return false
	}
	switch ref.Namespace {
	case "kube-system", "kube-public", "kube-node-lease":
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

// resourceAPIGroup maps a bare resource (or subresource) name to the API group it
// belongs to, so the graph's edge matchers can enforce the correct (apiGroup,
// resource) pair without every call site spelling the group out. Every resource the
// edge builders test is listed here; an unlisted resource defaults to the core group.
var resourceAPIGroup = map[string]string{
	// core group ("")
	"pods":                     "",
	"pods/exec":                "",
	"pods/attach":              "",
	"pods/ephemeralcontainers": "",
	"pods/portforward":         "",
	"secrets":                  "",
	"serviceaccounts":          "",
	"serviceaccounts/token":    "",
	"nodes":                    "",
	"nodes/proxy":              "",
	"nodes/status":             "",
	"users":                    "",
	"groups":                   "",
	// rbac.authorization.k8s.io
	"roles":               "rbac.authorization.k8s.io",
	"clusterroles":        "rbac.authorization.k8s.io",
	"rolebindings":        "rbac.authorization.k8s.io",
	"clusterrolebindings": "rbac.authorization.k8s.io",
	// certificates.k8s.io
	"certificatesigningrequests":          "certificates.k8s.io",
	"certificatesigningrequests/approval": "certificates.k8s.io",
}

// matchesResourceVerb reports whether a rule authorizes any of the given verbs on
// any of the given resources, honoring the resource's API group and the rule's
// resourceNames (see permissions.Grants). Call sites keep passing bare resource
// names; the group is resolved from resourceAPIGroup.
func matchesResourceVerb(rule permissions.EffectiveRule, resources, verbs []string) bool {
	targets := make([]permissions.ResourceTarget, 0, len(resources))
	for _, r := range resources {
		targets = append(targets, permissions.ResourceTarget{Group: resourceAPIGroup[r], Resource: r})
	}
	return rule.Grants(targets, verbs...)
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
