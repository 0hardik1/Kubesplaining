package models

import (
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Snapshot is the in-memory representation of everything the collector pulled from a cluster;
// analyzers consume Snapshot and never talk to the API server themselves.
type Snapshot struct {
	Metadata  SnapshotMetadata  `json:"metadata"`
	Resources SnapshotResources `json:"resources"`
}

// SnapshotMetadata records provenance and collection-time context so downstream consumers can reason about what is/isn't present.
type SnapshotMetadata struct {
	KubesplainingVersion     string   `json:"kubesplaining_version"`
	SnapshotTimestamp        string   `json:"snapshot_timestamp"`
	ClusterName              string   `json:"cluster_name,omitempty"`
	ClusterVersion           string   `json:"cluster_version,omitempty"`
	APIServerURL             string   `json:"api_server_url,omitempty"`
	CloudProvider            string   `json:"cloud_provider,omitempty"`
	CollectorIdentity        string   `json:"collector_identity,omitempty"`
	PermissionsAvailable     []string `json:"permissions_available,omitempty"`
	PermissionsMissing       []string `json:"permissions_missing,omitempty"`
	CollectionWarnings       []string `json:"collection_warnings,omitempty"`
	NamespacesScanned        []string `json:"namespaces_scanned,omitempty"`
	CollectionDurationSecond float64  `json:"collection_duration_seconds,omitempty"`
}

// SnapshotResources holds the collected Kubernetes objects grouped by kind; empty slices are allowed and common.
type SnapshotResources struct {
	Roles                    []rbacv1.Role                                            `json:"roles,omitempty"`
	ClusterRoles             []rbacv1.ClusterRole                                     `json:"cluster_roles,omitempty"`
	RoleBindings             []rbacv1.RoleBinding                                     `json:"role_bindings,omitempty"`
	ClusterRoleBindings      []rbacv1.ClusterRoleBinding                              `json:"cluster_role_bindings,omitempty"`
	ServiceAccounts          []corev1.ServiceAccount                                  `json:"service_accounts,omitempty"`
	Pods                     []corev1.Pod                                             `json:"pods,omitempty"`
	Deployments              []appsv1.Deployment                                      `json:"deployments,omitempty"`
	DaemonSets               []appsv1.DaemonSet                                       `json:"daemon_sets,omitempty"`
	StatefulSets             []appsv1.StatefulSet                                     `json:"stateful_sets,omitempty"`
	Jobs                     []batchv1.Job                                            `json:"jobs,omitempty"`
	CronJobs                 []batchv1.CronJob                                        `json:"cron_jobs,omitempty"`
	SecretsMetadata          []SecretMetadata                                         `json:"secrets_metadata,omitempty"`
	ConfigMaps               []ConfigMapSnapshot                                      `json:"config_maps,omitempty"`
	Namespaces               []corev1.Namespace                                       `json:"namespaces,omitempty"`
	Nodes                    []corev1.Node                                            `json:"nodes,omitempty"`
	Services                 []corev1.Service                                         `json:"services,omitempty"`
	NetworkPolicies          []networkingv1.NetworkPolicy                             `json:"network_policies,omitempty"`
	ValidatingWebhookConfigs []admissionregistrationv1.ValidatingWebhookConfiguration `json:"validating_webhook_configs,omitempty"`
	MutatingWebhookConfigs   []admissionregistrationv1.MutatingWebhookConfiguration   `json:"mutating_webhook_configs,omitempty"`
	// ValidatingAdmissionPolicies and ValidatingAdmissionPolicyBindings are the in-tree
	// CEL-based admission policies (GA in Kubernetes v1.30). Phase 2 collects them for
	// presence detection; Phase 3 will evaluate the CEL expressions offline.
	ValidatingAdmissionPolicies       []admissionregistrationv1.ValidatingAdmissionPolicy        `json:"validating_admission_policies,omitempty"`
	ValidatingAdmissionPolicyBindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding `json:"validating_admission_policy_bindings,omitempty"`
	// KyvernoClusterPolicies and KyvernoPolicies hold Kyverno (Cluster)Policies as
	// unstructured.Unstructured so we don't take a typed dependency on Kyverno's CRDs.
	// Split mirrors the (Cluster)Role precedent so consumers preserve scope.
	KyvernoClusterPolicies []unstructured.Unstructured `json:"kyverno_cluster_policies,omitempty"`
	KyvernoPolicies        []unstructured.Unstructured `json:"kyverno_policies,omitempty"`
	// GatekeeperConstraintTemplates are the cluster's OPA Gatekeeper templates. Phase 2
	// uses presence as a "Gatekeeper installed" signal; per-constraint instances are
	// dynamically-typed CRDs and are deferred to Phase 3/4.
	GatekeeperConstraintTemplates []unstructured.Unstructured `json:"gatekeeper_constraint_templates,omitempty"`
}

// SecretMetadata stores Secret identifying info and labels/annotations only; raw data is intentionally never collected.
type SecretMetadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Type        corev1.SecretType `json:"type,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// ConfigMapSnapshot is a ConfigMap with its data redacted by the collector but keys preserved, so analyzers can still inspect key names.
type ConfigMapSnapshot struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
}

// NewSnapshot returns a Snapshot seeded with the current UTC timestamp and a neutral CloudProvider default.
func NewSnapshot() Snapshot {
	return Snapshot{
		Metadata: SnapshotMetadata{
			SnapshotTimestamp: time.Now().UTC().Format(time.RFC3339),
			CloudProvider:     "none",
		},
	}
}
