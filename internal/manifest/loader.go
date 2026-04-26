// Package manifest loads Kubernetes YAML/JSON manifests from disk into a Snapshot without talking to a live cluster.
// This backs the `scan-resource` flow so users can assess a single manifest or a folder of rendered templates.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// objectMeta is a minimal header used to sniff Kind/APIVersion before full decoding.
type objectMeta struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// LoadSnapshot reads a YAML or JSON manifest file (possibly containing multiple documents) and returns a synthetic Snapshot.
// resourceTypeHint is used when a document lacks an explicit "kind" field (e.g. a headerless YAML fragment).
func LoadSnapshot(path string, resourceTypeHint string) (models.Snapshot, error) {
	bytesData, err := os.ReadFile(path)
	if err != nil {
		return models.Snapshot{}, fmt.Errorf("read manifest file: %w", err)
	}

	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "manifest-scan"

	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(bytesData), 4096)
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return models.Snapshot{}, fmt.Errorf("decode manifest: %w", err)
		}
		if len(raw) == 0 {
			continue
		}
		if err := appendObject(&snapshot, raw, resourceTypeHint); err != nil {
			return models.Snapshot{}, err
		}
	}

	return snapshot, nil
}

// appendObject dispatches a single decoded YAML/JSON object to the appropriate SnapshotResources slice, recursing into List items.
func appendObject(snapshot *models.Snapshot, raw map[string]any, resourceTypeHint string) error {
	kind := asString(raw["kind"])
	if kind == "" {
		kind = kindFromHint(resourceTypeHint)
	}

	if strings.EqualFold(kind, "List") {
		items, ok := raw["items"].([]any)
		if !ok {
			return nil
		}
		for _, item := range items {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if err := appendObject(snapshot, itemMap, resourceTypeHint); err != nil {
				return err
			}
		}
		return nil
	}

	payload, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal manifest object: %w", err)
	}

	switch kind {
	case "Namespace":
		var obj corev1.Namespace
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Namespaces = append(snapshot.Resources.Namespaces, obj)
	case "ServiceAccount":
		var obj corev1.ServiceAccount
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.ServiceAccounts = append(snapshot.Resources.ServiceAccounts, obj)
	case "Role":
		var obj rbacv1.Role
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Roles = append(snapshot.Resources.Roles, obj)
	case "ClusterRole":
		var obj rbacv1.ClusterRole
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.ClusterRoles = append(snapshot.Resources.ClusterRoles, obj)
	case "RoleBinding":
		var obj rbacv1.RoleBinding
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.RoleBindings = append(snapshot.Resources.RoleBindings, obj)
	case "ClusterRoleBinding":
		var obj rbacv1.ClusterRoleBinding
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, obj)
	case "Pod":
		var obj corev1.Pod
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Pods = append(snapshot.Resources.Pods, obj)
	case "Service":
		var obj corev1.Service
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Services = append(snapshot.Resources.Services, obj)
	case "Deployment":
		var obj appsv1.Deployment
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Deployments = append(snapshot.Resources.Deployments, obj)
	case "DaemonSet":
		var obj appsv1.DaemonSet
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.DaemonSets = append(snapshot.Resources.DaemonSets, obj)
	case "StatefulSet":
		var obj appsv1.StatefulSet
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.StatefulSets = append(snapshot.Resources.StatefulSets, obj)
	case "Job":
		var obj batchv1.Job
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.Jobs = append(snapshot.Resources.Jobs, obj)
	case "CronJob":
		var obj batchv1.CronJob
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.CronJobs = append(snapshot.Resources.CronJobs, obj)
	case "NetworkPolicy":
		var obj networkingv1.NetworkPolicy
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.NetworkPolicies = append(snapshot.Resources.NetworkPolicies, obj)
	case "ValidatingWebhookConfiguration":
		var obj admissionregistrationv1.ValidatingWebhookConfiguration
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.ValidatingWebhookConfigs = append(snapshot.Resources.ValidatingWebhookConfigs, obj)
	case "MutatingWebhookConfiguration":
		var obj admissionregistrationv1.MutatingWebhookConfiguration
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.MutatingWebhookConfigs = append(snapshot.Resources.MutatingWebhookConfigs, obj)
	case "Secret":
		var obj corev1.Secret
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.SecretsMetadata = append(snapshot.Resources.SecretsMetadata, models.SecretMetadata{
			Name:        obj.Name,
			Namespace:   obj.Namespace,
			Type:        obj.Type,
			Annotations: obj.Annotations,
			Labels:      obj.Labels,
		})
	case "ConfigMap":
		var obj corev1.ConfigMap
		if err := json.Unmarshal(payload, &obj); err != nil {
			return err
		}
		snapshot.Resources.ConfigMaps = append(snapshot.Resources.ConfigMaps, models.ConfigMapSnapshot{
			Name:        obj.Name,
			Namespace:   obj.Namespace,
			Labels:      obj.Labels,
			Annotations: obj.Annotations,
			Data:        obj.Data,
		})
	default:
		return fmt.Errorf("unsupported manifest kind %q", kind)
	}

	return nil
}

// asString returns value as a string when it is one, and empty otherwise.
func asString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

// kindFromHint maps a CLI --resource-type hint (case-insensitive) to the canonical Kubernetes Kind string.
func kindFromHint(hint string) string {
	switch strings.ToLower(strings.TrimSpace(hint)) {
	case "role":
		return "Role"
	case "clusterrole":
		return "ClusterRole"
	case "rolebinding":
		return "RoleBinding"
	case "clusterrolebinding":
		return "ClusterRoleBinding"
	case "pod":
		return "Pod"
	case "service":
		return "Service"
	case "deployment":
		return "Deployment"
	case "daemonset":
		return "DaemonSet"
	case "statefulset":
		return "StatefulSet"
	case "job":
		return "Job"
	case "cronjob":
		return "CronJob"
	case "serviceaccount":
		return "ServiceAccount"
	case "networkpolicy":
		return "NetworkPolicy"
	case "namespace":
		return "Namespace"
	case "validatingwebhookconfiguration":
		return "ValidatingWebhookConfiguration"
	case "mutatingwebhookconfiguration":
		return "MutatingWebhookConfiguration"
	default:
		return ""
	}
}
