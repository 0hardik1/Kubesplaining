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
	Roles               []rbacv1.Role                `json:"roles,omitempty"`
	ClusterRoles        []rbacv1.ClusterRole         `json:"cluster_roles,omitempty"`
	RoleBindings        []rbacv1.RoleBinding         `json:"role_bindings,omitempty"`
	ClusterRoleBindings []rbacv1.ClusterRoleBinding  `json:"cluster_role_bindings,omitempty"`
	ServiceAccounts     []corev1.ServiceAccount      `json:"service_accounts,omitempty"`
	Pods                []corev1.Pod                 `json:"pods,omitempty"`
	Deployments         []appsv1.Deployment          `json:"deployments,omitempty"`
	DaemonSets          []appsv1.DaemonSet           `json:"daemon_sets,omitempty"`
	StatefulSets        []appsv1.StatefulSet         `json:"stateful_sets,omitempty"`
	Jobs                []batchv1.Job                `json:"jobs,omitempty"`
	CronJobs            []batchv1.CronJob            `json:"cron_jobs,omitempty"`
	SecretsMetadata     []SecretMetadata             `json:"secrets_metadata,omitempty"`
	ConfigMaps          []ConfigMapSnapshot          `json:"config_maps,omitempty"`
	Namespaces          []corev1.Namespace           `json:"namespaces,omitempty"`
	Nodes               []corev1.Node                `json:"nodes,omitempty"`
	Services            []corev1.Service             `json:"services,omitempty"`
	NetworkPolicies     []networkingv1.NetworkPolicy `json:"network_policies,omitempty"`
	// PersistentVolumes and PersistentVolumeClaims power the PV-hostPath bypass check
	// (KUBE-PV-HOSTPATH-001): a Pod can mount a PVC whose backing PV uses a sensitive
	// hostPath (`/`, `/etc`, `/var/run/docker.sock`, `/var/lib/kubelet`, ...). PSA cannot
	// see through PVCs, so this is a real Baseline bypass. Both fields are populated by
	// the collector; missing-permission errors degrade them to empty (warning, not fatal).
	PersistentVolumes      []corev1.PersistentVolume      `json:"persistent_volumes,omitempty"`
	PersistentVolumeClaims []corev1.PersistentVolumeClaim `json:"persistent_volume_claims,omitempty"`
	// CertificateSigningRequests are the cluster's pending / approved CSRs. They are
	// the evidence side of the certificates API, consumed by the `certificates`
	// analyzer (KUBE-CSR-001 / -002): who asked for a client certificate, against
	// which signer, and whether it was approved. The permission side — who *could*
	// mint one — is KUBE-PRIVESC-011 / -024 in the rbac analyzer and is derived
	// entirely from RBAC, not from these objects.
	CertificateSigningRequests []CSR                                                    `json:"certificate_signing_requests,omitempty"`
	ValidatingWebhookConfigs   []admissionregistrationv1.ValidatingWebhookConfiguration `json:"validating_webhook_configs,omitempty"`
	MutatingWebhookConfigs     []admissionregistrationv1.MutatingWebhookConfiguration   `json:"mutating_webhook_configs,omitempty"`
	// ValidatingAdmissionPolicies and ValidatingAdmissionPolicyBindings are the in-tree
	// CEL-based admission policies (GA in Kubernetes v1.30). Phase 2 collects them for
	// presence detection; Phase 3 will evaluate the CEL expressions offline.
	ValidatingAdmissionPolicies       []admissionregistrationv1.ValidatingAdmissionPolicy        `json:"validating_admission_policies,omitempty"`
	ValidatingAdmissionPolicyBindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding `json:"validating_admission_policy_bindings,omitempty"`
	// MutatingAdmissionPolicies and MutatingAdmissionPolicyBindings are the in-tree
	// CEL/JSONPatch mutating counterpart of VAP (GA in Kubernetes v1.36). A mutating
	// policy rewrites objects at admission with no external webhook: it can flip
	// `privileged`, add a `hostPath`, or inject a sidecar into every future pod, so
	// write access to the pair is a cluster-takeover primitive the privesc graph draws
	// (KUBE-PRIVESC-019). Collected for that graph edge and for presence reporting.
	MutatingAdmissionPolicies       []admissionregistrationv1.MutatingAdmissionPolicy        `json:"mutating_admission_policies,omitempty"`
	MutatingAdmissionPolicyBindings []admissionregistrationv1.MutatingAdmissionPolicyBinding `json:"mutating_admission_policy_bindings,omitempty"`
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

// CSR is the minimal projection of a certificates.k8s.io/v1 CertificateSigningRequest the
// analyzers need. The raw CSR PEM is omitted (we never inspect signing-request payloads),
// but SignerName + Usages + the approval Conditions are kept so detectors can identify
// the kube-apiserver-client signers that lead to cluster-admin via system:masters.
type CSR struct {
	Name        string            `json:"name"`
	SignerName  string            `json:"signer_name,omitempty"`
	Username    string            `json:"username,omitempty"`   // identity that submitted the CSR
	Usages      []string          `json:"usages,omitempty"`     // x509 key usages requested
	Groups      []string          `json:"groups,omitempty"`     // groups asserted by the submitting identity
	Conditions  []CSRCondition    `json:"conditions,omitempty"` // status conditions: Approved / Denied / Failed
	Approved    bool              `json:"approved,omitempty"`   // convenience: true when any Approved condition is present
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// CSRCondition mirrors certificatesv1.CertificateSigningRequestCondition for the
// minimal CSR snapshot view: type, status, and optional reason / message.
type CSRCondition struct {
	Type    string `json:"type"`             // "Approved", "Denied", "Failed"
	Status  string `json:"status,omitempty"` // "True", "False", "Unknown"
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
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
