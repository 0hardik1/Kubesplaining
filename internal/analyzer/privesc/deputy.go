// Package privesc: confused-deputy edges. A subject that cannot escalate directly
// may still be able to write a custom resource that a privileged controller then
// reconciles on its behalf. The controller is the deputy: it holds the permissions,
// the attacker supplies the instructions.
package privesc

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// operatorEntry maps one attacker-writable custom resource to the controller
// ServiceAccount that reconciles it.
type operatorEntry struct {
	group       string
	resources   []string
	saNamespace string
	saName      string
	// gains describes, in one clause, what the reconciler will do on the
	// attacker's behalf. Used verbatim in the edge description.
	gains string
}

// operatorCatalog lists controllers whose custom resources are attacker-steerable:
// the CR names a source of manifests, a script, a file path, or a target identity
// that the controller then acts on with its own (usually cluster-wide) permissions.
//
// Kept RBAC-only on purpose: a grant on these (group, resource) pairs is visible in
// permissions.Aggregate without collecting CRDs or the custom resources themselves.
// The precision gate is addConfusedDeputyEdges requiring the controller SA to exist.
var operatorCatalog = []operatorEntry{
	{group: "kustomize.toolkit.fluxcd.io", resources: []string{"kustomizations"}, saNamespace: "flux-system", saName: "kustomize-controller",
		gains: "applies arbitrary manifests from an attacker-controlled source"},
	{group: "helm.toolkit.fluxcd.io", resources: []string{"helmreleases"}, saNamespace: "flux-system", saName: "helm-controller",
		gains: "installs an attacker-authored Helm chart"},
	{group: "source.toolkit.fluxcd.io", resources: []string{"gitrepositories", "ocirepositories"}, saNamespace: "flux-system", saName: "source-controller",
		gains: "fetches an attacker-controlled manifest source"},
	{group: "argoproj.io", resources: []string{"applications", "applicationsets"}, saNamespace: "argocd", saName: "argocd-application-controller",
		gains: "syncs an attacker-controlled Git repository into the cluster"},
	{group: "argoproj.io", resources: []string{"workflows"}, saNamespace: "argo", saName: "argo-workflow-controller",
		gains: "runs an attacker-authored workflow pod, optionally under a chosen ServiceAccount"},
	{group: "cert-manager.io", resources: []string{"certificates"}, saNamespace: "cert-manager", saName: "cert-manager",
		gains: "issues a certificate with an attacker-chosen subject and writes it to a Secret"},
	{group: "external-secrets.io", resources: []string{"externalsecrets"}, saNamespace: "external-secrets", saName: "external-secrets",
		gains: "materializes an attacker-chosen external secret into a Kubernetes Secret"},
	{group: "velero.io", resources: []string{"restores"}, saNamespace: "velero", saName: "velero",
		gains: "restores attacker-selected objects, including RBAC, from a backup"},
	{group: "tekton.dev", resources: []string{"pipelineruns"}, saNamespace: "tekton-pipelines", saName: "tekton-pipelines-controller",
		gains: "runs an attacker-authored pipeline step"},
	{group: "monitoring.coreos.com", resources: []string{"servicemonitors"}, saNamespace: "monitoring", saName: "prometheus-operator",
		gains: "scrapes an attacker-chosen bearerTokenFile, exfiltrating a mounted ServiceAccount token (GHSA-cxh2-4639-vmc5)"},
}

// deputyVerbs are the write verbs that let a subject steer a reconciler.
var deputyVerbs = []string{"create", "update", "patch"}

// addConfusedDeputyEdges emits an operator_reconcile bridge from a subject that can
// write a catalogued custom resource to the controller ServiceAccount that reconciles
// it. The controller supplies its own outbound edges, which is where the escalation
// actually lands, so this bridge only ever lengthens an existing chain.
//
// The edge is emitted only when the controller SA exists as a node in the graph,
// meaning the operator is genuinely installed. A stray Role granting verbs on a CRD
// that nothing serves produces no edge.
func addConfusedDeputyEdges(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule) {
	for _, entry := range operatorCatalog {
		controller := models.SubjectRef{Kind: "ServiceAccount", Name: entry.saName, Namespace: entry.saNamespace}
		if controller.Key() == subject.Key() {
			continue
		}
		if _, installed := graph.Nodes[nodeID(controller)]; !installed {
			continue
		}

		targets := make([]permissions.ResourceTarget, 0, len(entry.resources))
		for _, resource := range entry.resources {
			targets = append(targets, permissions.ResourceTarget{Group: entry.group, Resource: resource})
		}

		for _, rule := range rules {
			if !rule.Grants(targets, deputyVerbs...) {
				continue
			}
			addEdge(graph, nodeID(subject), nodeID(controller), &models.EscalationEdge{
				Technique:   "KUBE-CONFUSED-DEPUTY-001",
				Action:      "operator_reconcile",
				Permission:  fmt.Sprintf("write %s.%s", entry.resources[0], entry.group),
				Description: fmt.Sprintf("can steer %s/%s, which %s", entry.saNamespace, entry.saName, entry.gains),
			})
			break // one bridge per (subject, controller) is enough
		}
	}
}
