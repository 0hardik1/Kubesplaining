// Package privesc - cloud_edges.go layers cloud-IAM privilege-escalation edges
// onto the in-cluster RBAC graph built by graph.go. Three edge shapes live here:
//
//   - IRSA: cluster ServiceAccount -> external AWS IAM role node, surfaced for
//     each CloudIdentity with a populated IRSABinding. The external node is a
//     non-sink, non-system EscalationNode tagged IsExternal=true; the
//     pathfinder treats it as a natural terminal when no outbound edges exist
//     (and as an intermediate hop when aws-auth maps the same ARN onward).
//
//   - aws-auth: external AWS IAM principal -> cluster-admin / system:masters
//     sinks, derived from CloudIdentity.MappedGroups. system:masters is wired
//     directly; arbitrary group names are followed through
//     ClusterRoleBindings whose roleRef is cluster-admin.
//
//   - IMDS-pivot: cluster ServiceAccount -> sinkNodeEscape, fired when a pod
//     using the SA has IMDS reachable, no IRSA annotation on the SA, provider
//     is "eks", and the pod is not Fargate-scheduled. This depends on the
//     exported network.IMDSReachable helper.
//
// The cloud identity slice is sourced from cloud.CloudIdentitiesForSnapshot,
// which is the only place that parses IRSA annotations + aws-auth ConfigMap
// data. We do not re-parse those here.
package privesc

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer/cloud"
	"github.com/0hardik1/kubesplaining/internal/analyzer/network"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
)

// irsaAnnotation is the EKS annotation that binds a ServiceAccount to an IAM
// role. Mirrored here from cloud/eks.IRSAAnnotation so the privesc package
// doesn't take a build dependency on the cloud/eks package (cloud/* is owned
// by other units in this feature branch). When the cloud/eks package
// stabilizes, this can be re-pointed at cloudeks.IRSAAnnotation.
const irsaAnnotation = "eks.amazonaws.com/role-arn"

// fargateNodeLabel is the AWS-managed label that distinguishes Fargate nodes
// from EC2-backed managed nodes. Value "fargate" means Fargate; "ec2" or
// missing means EC2. The label is user-mutable, so the analyzer also checks
// node.Spec.ProviderID, which the EKS control plane sets and which users with
// `nodes/patch` cannot rewrite.
const (
	fargateNodeLabel        = "eks.amazonaws.com/compute-type"
	fargateProviderIDPrefix = "aws:///fargate/"
)

// addCloudEdges augments the graph with IRSA, aws-auth, and IMDS-pivot edges.
// Safe to call on any snapshot: when no cloud identities are present (and no
// IMDS pivot conditions apply) the graph is unchanged.
func addCloudEdges(graph *models.EscalationGraph, snapshot models.Snapshot) {
	identities := cloud.CloudIdentitiesForSnapshot(snapshot)
	for _, identity := range identities {
		if identity.IRSA != nil {
			addIRSAEdge(graph, identity)
		}
		if len(identity.MappedGroups) > 0 {
			addAWSAuthEdges(graph, snapshot, identity)
		}
	}

	addIMDSPivotEdges(graph, snapshot)
}

// externalAWSIAMNodeID returns the canonical graph-node ID for an external AWS
// IAM identity. The "external:aws-iam:" prefix keeps these IDs disjoint from
// the "subject:" namespace used by Kubernetes RBAC subjects so isSystemSubject
// and the pathfinder source loop can distinguish them by ID alone.
func externalAWSIAMNodeID(arn string) string {
	return "external:aws-iam:" + sanitizeARN(arn)
}

// sanitizeARN replaces "/" and ":" with "_" so the ARN can be embedded in a
// node ID without colliding with the "external:aws-iam:" prefix separator or
// breaking parsers that split on ":". Alphanumerics and underscores pass
// through; every other character is replaced too, conservatively.
func sanitizeARN(arn string) string {
	var b strings.Builder
	b.Grow(len(arn))
	for _, r := range arn {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// ensureExternalAWSIAMNode inserts the external AWS IAM node into the graph if
// missing. setTarget=true tags the node with Target=TargetAWSIAMRole so
// terminal-path consumers can recognize the identity shape; for nodes that
// will only ever be an intermediate hop (aws-auth without IRSA), the caller
// passes setTarget=false to avoid signalling a terminal that isn't.
func ensureExternalAWSIAMNode(graph *models.EscalationGraph, arn string, setTarget bool) string {
	id := externalAWSIAMNodeID(arn)
	if existing, ok := graph.Nodes[id]; ok {
		// Promote Target if this caller has more information: an aws-auth-only
		// entry created the node first (setTarget=false), then an IRSA edge
		// arrived for the same ARN (setTarget=true). The Target field is the
		// only thing the pathfinder uses for terminal-shape annotation.
		if setTarget && existing.Target == "" {
			existing.Target = models.TargetAWSIAMRole
		}
		return id
	}
	// External IAM nodes are marked IsSink=true so the BFS captures any path
	// that reaches them (the "SA can assume this role" terminal), and Traversable
	// so it also continues past them. Chains that pass THROUGH an external IAM
	// node (e.g. SA -> IRSA -> aws-auth -> system:masters) therefore still surface
	// as separate, longer paths to their downstream cluster sinks.
	node := &models.EscalationNode{
		ID:          id,
		Subject:     models.SubjectRef{Kind: "User", Name: arn},
		IsExternal:  true,
		IsSink:      true,
		Traversable: true,
	}
	if setTarget {
		node.Target = models.TargetAWSIAMRole
	}
	graph.Nodes[id] = node
	return id
}

// addIRSAEdge wires SA -> external IAM role for one CloudIdentity with an
// IRSA binding. The external node is created with Target=TargetAWSIAMRole so
// a path that terminates here is reported as an aws_iam_role path.
func addIRSAEdge(graph *models.EscalationGraph, identity models.CloudIdentity) {
	saRef := identity.IRSA.ServiceAccountRef
	if saRef.Name == "" {
		return
	}
	ensureSubjectNode(graph, saRef)
	externalID := ensureExternalAWSIAMNode(graph, identity.ARN, true)
	addEdge(graph, nodeID(saRef), externalID, &models.EscalationEdge{
		// Family prefix (not a full rule ID) so the correlation pass amplifies the
		// concrete IRSA findings the eks analyzer emits (KUBE-CLOUD-IRSA-ADMIN-ROLE-001,
		// KUBE-CLOUD-IRSA-MISSING-001) via techniqueMatchesRule's prefix rule.
		Technique:   "KUBE-CLOUD-IRSA",
		Action:      "irsa_assume_role",
		Permission:  identity.ARN,
		Description: "ServiceAccount can assume " + identity.ARN + " via IRSA",
	})
}

// addAWSAuthEdges wires external IAM principal -> cluster sinks for the
// aws-auth-derived MappedGroups list. system:masters is hard-coded; other
// groups are followed through ClusterRoleBindings whose roleRef points at the
// built-in cluster-admin ClusterRole OR at any custom ClusterRole with a
// triple-wildcard rule (verbs:[*], resources:[*], apiGroups:[*]).
func addAWSAuthEdges(graph *models.EscalationGraph, snapshot models.Snapshot, identity models.CloudIdentity) {
	if identity.ARN == "" {
		return
	}
	externalID := ensureExternalAWSIAMNode(graph, identity.ARN, false)
	for _, group := range identity.MappedGroups {
		if group == "" {
			continue
		}
		if group == "system:masters" {
			addEdge(graph, externalID, sinkSystemMasters, &models.EscalationEdge{
				Technique:   "KUBE-CLOUD-AWSAUTH",
				Action:      "aws_auth_admin",
				Permission:  "system:masters via aws-auth",
				Description: "external IAM principal " + identity.ARN + " is mapped to system:masters via aws-auth",
			})
			continue
		}
		roleName, ok := groupBoundToAdminEquivalentRole(snapshot, group)
		if !ok {
			continue
		}
		addEdge(graph, externalID, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-CLOUD-AWSAUTH",
			Action:      "aws_auth_admin",
			Permission:  fmt.Sprintf("mapped to group %s bound to ClusterRole %s", group, roleName),
			Description: fmt.Sprintf("external IAM principal %s is mapped to group %s, which is bound to ClusterRole %s (admin-equivalent) via a ClusterRoleBinding", identity.ARN, group, roleName),
		})
	}
}

// groupBoundToAdminEquivalentRole reports whether any ClusterRoleBinding lists
// the given group as a subject and points at an admin-equivalent ClusterRole.
// "Admin-equivalent" means either the built-in `cluster-admin` or any custom
// ClusterRole that has a `verbs:[*], resources:[*], apiGroups:[*]` rule. The
// returned roleName is the actual ClusterRole the binding points at, so the
// edge description can disambiguate built-in from custom admin paths.
func groupBoundToAdminEquivalentRole(snapshot models.Snapshot, group string) (string, bool) {
	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind != "ClusterRole" {
			continue
		}
		if !permissions.IsAdminEquivalentClusterRole(binding.RoleRef.Name, snapshot.Resources.ClusterRoles) {
			continue
		}
		for _, subject := range binding.Subjects {
			if subject.Kind == "Group" && subject.Name == group {
				return binding.RoleRef.Name, true
			}
		}
	}
	return "", false
}

// addIMDSPivotEdges wires SA -> sinkNodeEscape for every pod that meets all of:
// (1) snapshot is EKS, (2) the pod can reach IMDS per network.IMDSReachable,
// (3) the pod's SA has no IRSA annotation, (4) the pod is not scheduled to a
// Fargate node. Each (SA, pod) pairing emits at most one edge (deduplicated
// by SA-key + reason). Calling network.IMDSReachable here keeps the
// network-policy semantics in one place rather than re-implementing them.
func addIMDSPivotEdges(graph *models.EscalationGraph, snapshot models.Snapshot) {
	if strings.ToLower(snapshot.Metadata.CloudProvider) != "eks" {
		return
	}

	// Build a node-name -> Fargate? lookup so per-pod Fargate detection is O(1).
	// Prefer the kubelet-supplied providerID (set by the EKS control plane and
	// not user-patchable) over the label (which any nodes/patch holder can
	// flip). When providerID is set to a non-Fargate shape, the label is
	// ignored entirely so an attacker who can patch node labels cannot
	// silence the IMDS-pivot rule on a real EC2 node.
	fargateNodes := map[string]bool{}
	for _, node := range snapshot.Resources.Nodes {
		if strings.HasPrefix(node.Spec.ProviderID, fargateProviderIDPrefix) {
			fargateNodes[node.Name] = true
			continue
		}
		if node.Spec.ProviderID != "" {
			continue
		}
		if node.Labels[fargateNodeLabel] == "fargate" {
			fargateNodes[node.Name] = true
		}
	}

	// SA-key + permission string dedupe so we don't emit duplicate edges when
	// a Deployment scales to many replicas (each Pod fires the same condition).
	seen := map[string]struct{}{}

	for _, pod := range snapshot.Resources.Pods {
		if fargateNodes[pod.Spec.NodeName] {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		if saHasIRSAAnnotation(snapshot, saName, pod.Namespace) {
			continue
		}
		reachable, reason, _, _ := network.IMDSReachable(snapshot, "Pod", pod.Name, pod.Namespace, podLabels(pod), pod.Spec.HostNetwork)
		if !reachable {
			continue
		}
		saRef := models.SubjectRef{Kind: "ServiceAccount", Name: saName, Namespace: pod.Namespace}
		ensureSubjectNode(graph, saRef)
		key := saRef.Key() + "|" + reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		addEdge(graph, nodeID(saRef), sinkNodeEscape, &models.EscalationEdge{
			Technique:   "KUBE-CLOUD-IMDS-PIVOT-001",
			Action:      "imds_node_role_pivot",
			Permission:  "IMDS reachable, IRSA unbound",
			Description: fmt.Sprintf("pod %s/%s falls back to node IAM role via IMDS", pod.Namespace, pod.Name),
		})
	}
}

// saHasIRSAAnnotation reports whether the named ServiceAccount in the
// snapshot carries the IRSA role-arn annotation. A missing SA is treated as
// "no annotation" so the IMDS-pivot edge still fires for default SAs.
func saHasIRSAAnnotation(snapshot models.Snapshot, name, namespace string) bool {
	for _, sa := range snapshot.Resources.ServiceAccounts {
		if sa.Name != name || sa.Namespace != namespace {
			continue
		}
		if arn, ok := sa.Annotations[irsaAnnotation]; ok && arn != "" {
			return true
		}
		return false
	}
	return false
}

// podLabels returns the pod's labels map for the network.IMDSReachable
// selector evaluation. Returns nil safely when the pod has no labels.
func podLabels(pod corev1.Pod) map[string]string {
	if pod.Labels == nil {
		return nil
	}
	return pod.Labels
}
