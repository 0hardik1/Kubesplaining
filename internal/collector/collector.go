// Package collector snapshots a live Kubernetes cluster into a models.Snapshot,
// listing RBAC, workload, network, admission, and secret-related resources in parallel.
package collector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Well-known kube-system ConfigMaps whose payloads must be preserved verbatim:
//   - aws-auth maps IAM principals to Kubernetes RBAC subjects on EKS clusters; its
//     mappingRoles/mapUsers contents are needed for accurate impersonation analysis.
//   - coredns carries the cluster DNS Corefile, which is useful when reasoning about
//     name-resolution shortcuts an attacker might abuse.
//
// Every other ConfigMap goes through redactConfigMapValues so keys (which are searched
// for credential-looking names) survive but payloads never enter the snapshot.
const (
	configMapAWSAuth = "aws-auth"
	configMapCoreDNS = "coredns"
)

// Options controls namespace filtering, managedFields retention, and API concurrency for a collection run.
type Options struct {
	Namespaces           []string
	ExcludeNamespaces    []string
	IncludeManagedFields bool // when false, strip managedFields to keep snapshots small
	Parallelism          int  // max concurrent list requests against the API server
	BuildVersion         string
}

// Collector lists cluster resources and produces a models.Snapshot.
type Collector struct {
	client  kubernetes.Interface
	dynamic dynamic.Interface
	config  *rest.Config
	opts    Options
}

// New constructs a Collector with defaulted options (parallelism defaults to 10 when unset or non-positive).
// dyn may be nil; when nil, dynamic-client list operations (Kyverno/Gatekeeper CRDs) are skipped
// and recorded as warnings rather than failing.
func New(client kubernetes.Interface, dyn dynamic.Interface, config *rest.Config, opts Options) *Collector {
	if opts.Parallelism <= 0 {
		opts.Parallelism = 10
	}

	return &Collector{
		client:  client,
		dynamic: dyn,
		config:  config,
		opts:    opts,
	}
}

// Collect concurrently lists every supported resource, recording forbidden/unauthorized errors
// as missing-permission warnings rather than fatal failures so partial snapshots still produce useful output.
func (c *Collector) Collect(ctx context.Context) (models.Snapshot, error) {
	start := time.Now()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.KubesplainingVersion = c.opts.BuildVersion
	snapshot.Metadata.APIServerURL = c.config.Host

	var (
		mu sync.Mutex
		wg sync.WaitGroup
		// concurrencyLimiter caps how many list calls run against the apiserver at once.
		// It's used as a counting semaphore: send into the channel before doing work,
		// receive when done, so at most `Parallelism` goroutines are inside fn() at any
		// moment. A buffered channel of struct{} is the idiomatic Go semaphore pattern.
		concurrencyLimiter = make(chan struct{}, c.opts.Parallelism)
		fatals             []error
		warnings           []string
		missing            []string
	)

	recordWarning := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, message)
	}

	recordMissing := func(resource string, err error) {
		mu.Lock()
		defer mu.Unlock()
		missing = append(missing, resource)
		warnings = append(warnings, fmt.Sprintf("%s: %v", resource, err))
	}

	runTask := func(resource string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrencyLimiter <- struct{}{}
			defer func() { <-concurrencyLimiter }()

			if err := fn(); err != nil {
				switch {
				case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
					recordMissing(resource, err)
				case meta.IsNoMatchError(err), apierrors.IsNotFound(err):
					// CRD isn't installed (Kyverno/Gatekeeper not deployed, or the API
					// server doesn't serve VAP). Not a failure, not a permissions issue —
					// just an absent resource. Record as a warning so operators see what
					// we tried, but don't add to PermissionsMissing (which implies "you
					// should grant access").
					recordWarning(fmt.Sprintf("%s: %v", resource, err))
				default:
					recordWarning(fmt.Sprintf("%s: %v", resource, err))
					mu.Lock()
					fatals = append(fatals, fmt.Errorf("%s: %w", resource, err))
					mu.Unlock()
				}
			}
		}()
	}

	if version, err := c.client.Discovery().ServerVersion(); err == nil {
		snapshot.Metadata.ClusterVersion = version.String()
	} else {
		recordWarning(fmt.Sprintf("server version: %v", err))
	}

	runTask("namespaces", func() error {
		list, err := c.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		namespaces := make([]corev1.Namespace, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Name) {
				namespaces = append(namespaces, sanitizeNamespace(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Namespaces = namespaces
		mu.Unlock()
		return nil
	})

	runTask("serviceaccounts", func() error {
		list, err := c.client.CoreV1().ServiceAccounts(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.ServiceAccount, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeServiceAccount(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.ServiceAccounts = items
		mu.Unlock()
		return nil
	})

	runTask("roles", func() error {
		list, err := c.client.RbacV1().Roles(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]rbacv1.Role, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeRole(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Roles = items
		mu.Unlock()
		return nil
	})

	runTask("clusterroles", func() error {
		list, err := c.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]rbacv1.ClusterRole, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeClusterRole(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.ClusterRoles = items
		mu.Unlock()
		return nil
	})

	runTask("rolebindings", func() error {
		list, err := c.client.RbacV1().RoleBindings(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]rbacv1.RoleBinding, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeRoleBinding(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.RoleBindings = items
		mu.Unlock()
		return nil
	})

	runTask("clusterrolebindings", func() error {
		list, err := c.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]rbacv1.ClusterRoleBinding, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeClusterRoleBinding(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.ClusterRoleBindings = items
		mu.Unlock()
		return nil
	})

	runTask("pods", func() error {
		list, err := c.client.CoreV1().Pods(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.Pod, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizePod(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Pods = items
		mu.Unlock()
		return nil
	})

	runTask("deployments", func() error {
		list, err := c.client.AppsV1().Deployments(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]appsv1.Deployment, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeDeployment(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Deployments = items
		mu.Unlock()
		return nil
	})

	runTask("daemonsets", func() error {
		list, err := c.client.AppsV1().DaemonSets(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]appsv1.DaemonSet, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeDaemonSet(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.DaemonSets = items
		mu.Unlock()
		return nil
	})

	runTask("statefulsets", func() error {
		list, err := c.client.AppsV1().StatefulSets(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]appsv1.StatefulSet, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeStatefulSet(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.StatefulSets = items
		mu.Unlock()
		return nil
	})

	runTask("jobs", func() error {
		list, err := c.client.BatchV1().Jobs(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]batchv1.Job, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeJob(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Jobs = items
		mu.Unlock()
		return nil
	})

	runTask("cronjobs", func() error {
		list, err := c.client.BatchV1().CronJobs(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]batchv1.CronJob, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeCronJob(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.CronJobs = items
		mu.Unlock()
		return nil
	})

	runTask("secrets", func() error {
		list, err := c.client.CoreV1().Secrets(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]models.SecretMetadata, 0, len(list.Items))
		for _, item := range list.Items {
			if !c.includeNamespace(item.Namespace) {
				continue
			}

			items = append(items, models.SecretMetadata{
				Name:        item.Name,
				Namespace:   item.Namespace,
				Type:        item.Type,
				Annotations: item.Annotations,
				Labels:      item.Labels,
			})
		}

		mu.Lock()
		snapshot.Resources.SecretsMetadata = items
		mu.Unlock()
		return nil
	})

	runTask("configmaps", func() error {
		list, err := c.client.CoreV1().ConfigMaps(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]models.ConfigMapSnapshot, 0, len(list.Items))
		for _, item := range list.Items {
			if !c.includeNamespace(item.Namespace) {
				continue
			}

			snapshotItem := models.ConfigMapSnapshot{
				Name:        item.Name,
				Namespace:   item.Namespace,
				Labels:      item.Labels,
				Annotations: item.Annotations,
			}
			if item.Namespace == "kube-system" && (item.Name == configMapAWSAuth || item.Name == configMapCoreDNS) {
				snapshotItem.Data = item.Data
			} else if len(item.Data) > 0 {
				snapshotItem.Data = redactConfigMapValues(item.Data)
			}

			items = append(items, snapshotItem)
		}

		mu.Lock()
		snapshot.Resources.ConfigMaps = items
		mu.Unlock()
		return nil
	})

	runTask("nodes", func() error {
		list, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.Node, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeNode(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.Nodes = items
		mu.Unlock()
		return nil
	})

	runTask("persistentvolumes", func() error {
		list, err := c.client.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.PersistentVolume, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizePersistentVolume(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.PersistentVolumes = items
		mu.Unlock()
		return nil
	})

	runTask("persistentvolumeclaims", func() error {
		list, err := c.client.CoreV1().PersistentVolumeClaims(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.PersistentVolumeClaim, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizePersistentVolumeClaim(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.PersistentVolumeClaims = items
		mu.Unlock()
		return nil
	})

	runTask("services", func() error {
		list, err := c.client.CoreV1().Services(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]corev1.Service, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeService(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.Services = items
		mu.Unlock()
		return nil
	})

	runTask("networkpolicies", func() error {
		list, err := c.client.NetworkingV1().NetworkPolicies(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]networkingv1.NetworkPolicy, 0, len(list.Items))
		for _, item := range list.Items {
			if c.includeNamespace(item.Namespace) {
				items = append(items, sanitizeNetworkPolicy(item, c.opts.IncludeManagedFields))
			}
		}

		mu.Lock()
		snapshot.Resources.NetworkPolicies = items
		mu.Unlock()
		return nil
	})

	runTask("certificatesigningrequests", func() error {
		// CSRs are cluster-scoped (no namespace filter). The collector keeps
		// SignerName + Usages + the approval Conditions; we deliberately drop the
		// raw .Spec.Request PEM because analyzers never inspect signing-request
		// payloads and we don't want them in offline snapshots.
		list, err := c.client.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]models.CSR, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeCSR(item))
		}

		mu.Lock()
		snapshot.Resources.CertificateSigningRequests = items
		mu.Unlock()
		return nil
	})

	runTask("validatingwebhookconfigurations", func() error {
		list, err := c.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.ValidatingWebhookConfiguration, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeValidatingWebhookConfiguration(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.ValidatingWebhookConfigs = items
		mu.Unlock()
		return nil
	})

	runTask("mutatingwebhookconfigurations", func() error {
		list, err := c.client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.MutatingWebhookConfiguration, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeMutatingWebhookConfiguration(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.MutatingWebhookConfigs = items
		mu.Unlock()
		return nil
	})

	// VAP graduated to GA in Kubernetes v1.30. On older clusters the typed list
	// returns NotFound; the runTask switch downgrades that to a warning.
	runTask("validatingadmissionpolicies", func() error {
		list, err := c.client.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.ValidatingAdmissionPolicy, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeValidatingAdmissionPolicy(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.ValidatingAdmissionPolicies = items
		mu.Unlock()
		return nil
	})

	runTask("validatingadmissionpolicybindings", func() error {
		list, err := c.client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeValidatingAdmissionPolicyBinding(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.ValidatingAdmissionPolicyBindings = items
		mu.Unlock()
		return nil
	})

	// MutatingAdmissionPolicy went stable (GA, admissionregistration.k8s.io/v1) in
	// Kubernetes v1.36. On clusters older than that, or with the feature gate off, the
	// typed list returns NotFound / NoMatch and the runTask switch downgrades it to a
	// warning, the same absent-resource path VAP takes. Unlike a webhook a mutating
	// policy carries its mutation logic in etcd and runs in-process, so `create` on it
	// (plus a binding) is an admission-time injection primitive the privesc graph draws.
	runTask("mutatingadmissionpolicies", func() error {
		list, err := c.client.AdmissionregistrationV1().MutatingAdmissionPolicies().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.MutatingAdmissionPolicy, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeMutatingAdmissionPolicy(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.MutatingAdmissionPolicies = items
		mu.Unlock()
		return nil
	})

	runTask("mutatingadmissionpolicybindings", func() error {
		list, err := c.client.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		items := make([]admissionregistrationv1.MutatingAdmissionPolicyBinding, 0, len(list.Items))
		for _, item := range list.Items {
			items = append(items, sanitizeMutatingAdmissionPolicyBinding(item, c.opts.IncludeManagedFields))
		}

		mu.Lock()
		snapshot.Resources.MutatingAdmissionPolicyBindings = items
		mu.Unlock()
		return nil
	})

	// Kyverno and Gatekeeper are CRDs — use the dynamic client (when available)
	// and pre-flight on Discovery().ServerGroups() so we skip the list entirely
	// when the API group isn't served. Avoids a per-engine NoMatchError round-trip
	// on clusters where the engine isn't installed.
	if c.dynamic != nil {
		apiGroups := map[string]bool{}
		groupsList, groupsErr := c.client.Discovery().ServerGroups()
		if groupsErr == nil {
			for _, g := range groupsList.Groups {
				apiGroups[g.Name] = true
			}
		}
		hasGroup := func(name string) bool {
			if groupsErr != nil {
				// Discovery failed — fall through to dynamic list, which will return
				// NoMatchError if the group is absent (handled by runTask switch).
				return true
			}
			return apiGroups[name]
		}

		if hasGroup("kyverno.io") {
			runTask("kyverno.clusterpolicies", func() error {
				gvr := schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies"}
				list, err := c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
				if err != nil {
					return err
				}
				mu.Lock()
				snapshot.Resources.KyvernoClusterPolicies = list.Items
				mu.Unlock()
				return nil
			})

			runTask("kyverno.policies", func() error {
				gvr := schema.GroupVersionResource{Group: "kyverno.io", Version: "v1", Resource: "policies"}
				list, err := c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
				if err != nil {
					return err
				}
				items := make([]unstructured.Unstructured, 0, len(list.Items))
				for _, item := range list.Items {
					if c.includeNamespace(item.GetNamespace()) {
						items = append(items, item)
					}
				}
				mu.Lock()
				snapshot.Resources.KyvernoPolicies = items
				mu.Unlock()
				return nil
			})
		}

		if hasGroup("templates.gatekeeper.sh") {
			runTask("gatekeeper.constrainttemplates", func() error {
				gvr := schema.GroupVersionResource{Group: "templates.gatekeeper.sh", Version: "v1", Resource: "constrainttemplates"}
				list, err := c.dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
				if err != nil {
					return err
				}
				mu.Lock()
				snapshot.Resources.GatekeeperConstraintTemplates = list.Items
				mu.Unlock()
				return nil
			})
		}
	}

	wg.Wait()

	snapshot.Metadata.CollectionWarnings = dedupeStrings(warnings)
	snapshot.Metadata.PermissionsMissing = dedupeStrings(missing)
	snapshot.Metadata.NamespacesScanned = c.scannedNamespaces(snapshot.Resources.Namespaces)
	snapshot.Metadata.CollectionDurationSecond = time.Since(start).Seconds()

	if snapshot.Metadata.CloudProvider == "" || snapshot.Metadata.CloudProvider == "none" {
		if detected := DetectCloudProvider(snapshot); detected != "" {
			snapshot.Metadata.CloudProvider = detected
		}
	}

	if len(snapshot.Resources.Namespaces) == 0 && len(fatals) > 0 {
		return snapshot, errors.Join(fatals...)
	}

	return snapshot, nil
}

// includeNamespace applies the Namespaces allow-list and ExcludeNamespaces deny-list for cluster-scoped lists.
func (c *Collector) includeNamespace(namespace string) bool {
	if namespace == "" {
		return true
	}

	if len(c.opts.Namespaces) > 0 && !slices.Contains(c.opts.Namespaces, namespace) {
		return false
	}

	return !slices.Contains(c.opts.ExcludeNamespaces, namespace)
}

// scannedNamespaces reports the list of namespaces that actually made it into the snapshot.
func (c *Collector) scannedNamespaces(namespaces []corev1.Namespace) []string {
	if len(namespaces) > 0 {
		result := make([]string, 0, len(namespaces))
		for _, ns := range namespaces {
			result = append(result, ns.Name)
		}
		return result
	}

	if len(c.opts.Namespaces) > 0 {
		return append([]string(nil), c.opts.Namespaces...)
	}

	return nil
}

// dedupeStrings returns values with blanks trimmed and duplicates removed, preserving order.
func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// redactConfigMapValues keeps ConfigMap key names but blanks out values so later heuristics can still scan keys without storing payloads.
func redactConfigMapValues(data map[string]string) map[string]string {
	if len(data) == 0 {
		return nil
	}

	redacted := make(map[string]string, len(data))
	for key := range data {
		// Keep only key names for heuristic checks while avoiding full config payloads.
		redacted[key] = ""
	}
	return redacted
}

// The sanitize* helpers below all share one body - drop ManagedFields when the operator
// didn't ask to keep them - but they exist per concrete type because Go generics cannot
// access the .ManagedFields struct field by name. Keep them in sync; if you change one,
// change all of them (or grep for `maybeManagedFields`).

func sanitizeNamespace(obj corev1.Namespace, includeManagedFields bool) corev1.Namespace {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeServiceAccount(obj corev1.ServiceAccount, includeManagedFields bool) corev1.ServiceAccount {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeRole(obj rbacv1.Role, includeManagedFields bool) rbacv1.Role {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeClusterRole(obj rbacv1.ClusterRole, includeManagedFields bool) rbacv1.ClusterRole {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeRoleBinding(obj rbacv1.RoleBinding, includeManagedFields bool) rbacv1.RoleBinding {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeClusterRoleBinding(obj rbacv1.ClusterRoleBinding, includeManagedFields bool) rbacv1.ClusterRoleBinding {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizePod(obj corev1.Pod, includeManagedFields bool) corev1.Pod {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeDeployment(obj appsv1.Deployment, includeManagedFields bool) appsv1.Deployment {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeDaemonSet(obj appsv1.DaemonSet, includeManagedFields bool) appsv1.DaemonSet {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeStatefulSet(obj appsv1.StatefulSet, includeManagedFields bool) appsv1.StatefulSet {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeJob(obj batchv1.Job, includeManagedFields bool) batchv1.Job {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeCronJob(obj batchv1.CronJob, includeManagedFields bool) batchv1.CronJob {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeNode(obj corev1.Node, includeManagedFields bool) corev1.Node {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeService(obj corev1.Service, includeManagedFields bool) corev1.Service {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeNetworkPolicy(obj networkingv1.NetworkPolicy, includeManagedFields bool) networkingv1.NetworkPolicy {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizePersistentVolume(obj corev1.PersistentVolume, includeManagedFields bool) corev1.PersistentVolume {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizePersistentVolumeClaim(obj corev1.PersistentVolumeClaim, includeManagedFields bool) corev1.PersistentVolumeClaim {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeValidatingWebhookConfiguration(obj admissionregistrationv1.ValidatingWebhookConfiguration, includeManagedFields bool) admissionregistrationv1.ValidatingWebhookConfiguration {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeMutatingWebhookConfiguration(obj admissionregistrationv1.MutatingWebhookConfiguration, includeManagedFields bool) admissionregistrationv1.MutatingWebhookConfiguration {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeValidatingAdmissionPolicy(obj admissionregistrationv1.ValidatingAdmissionPolicy, includeManagedFields bool) admissionregistrationv1.ValidatingAdmissionPolicy {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeValidatingAdmissionPolicyBinding(obj admissionregistrationv1.ValidatingAdmissionPolicyBinding, includeManagedFields bool) admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeMutatingAdmissionPolicy(obj admissionregistrationv1.MutatingAdmissionPolicy, includeManagedFields bool) admissionregistrationv1.MutatingAdmissionPolicy {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

func sanitizeMutatingAdmissionPolicyBinding(obj admissionregistrationv1.MutatingAdmissionPolicyBinding, includeManagedFields bool) admissionregistrationv1.MutatingAdmissionPolicyBinding {
	obj.ManagedFields = maybeManagedFields(nil, includeManagedFields, obj.ManagedFields)
	return obj
}

// sanitizeCSR projects a certificatesv1.CertificateSigningRequest into the minimal
// models.CSR shape the analyzers need: name, signer, requester identity (without the
// raw PEM Request body), key usages, and the approval Conditions. Approved is set true
// when any condition has Type=Approved and Status=True so callers don't have to scan
// Conditions themselves.
func sanitizeCSR(obj certificatesv1.CertificateSigningRequest) models.CSR {
	usages := make([]string, 0, len(obj.Spec.Usages))
	for _, u := range obj.Spec.Usages {
		usages = append(usages, string(u))
	}
	conditions := make([]models.CSRCondition, 0, len(obj.Status.Conditions))
	var approved bool
	for _, c := range obj.Status.Conditions {
		conditions = append(conditions, models.CSRCondition{
			Type:    string(c.Type),
			Status:  string(c.Status),
			Reason:  c.Reason,
			Message: c.Message,
		})
		if c.Type == certificatesv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			approved = true
		}
	}
	return models.CSR{
		Name:        obj.Name,
		SignerName:  obj.Spec.SignerName,
		Username:    obj.Spec.Username,
		Usages:      usages,
		Groups:      append([]string(nil), obj.Spec.Groups...),
		Conditions:  conditions,
		Approved:    approved,
		Annotations: obj.Annotations,
		Labels:      obj.Labels,
	}
}

// maybeManagedFields returns current when include is true and nil otherwise so callers can easily drop managedFields from snapshots.
func maybeManagedFields[T any](zero []T, include bool, current []T) []T {
	if include {
		return current
	}
	return zero
}
