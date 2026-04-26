// Package podsec analyzes pod specs (and their controlling workloads) for
// container-runtime security issues like privileged containers, host namespace
// sharing, sensitive hostPath mounts, and insecure image tags.
package podsec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
	"github.com/hardik/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer produces pod-security findings from a snapshot.
type Analyzer struct{}

// target is a normalized workload reference carrying its pod template for uniform inspection.
type target struct {
	Kind      string
	Name      string
	Namespace string
	PodSpec   corev1.PodSpec
}

// New returns a new pod-security analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "podsec"
}

// Analyze iterates each pod template in the snapshot and emits findings for
// dangerous PodSpec-level settings, hostPath mounts, and container SecurityContext gaps.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, target := range collectTargets(snapshot) {
		serviceAccount := target.PodSpec.ServiceAccountName
		if serviceAccount == "" {
			serviceAccount = "default"
		}

		if serviceAccount == "default" && !strings.HasPrefix(target.Namespace, "kube-") {
			findings = appendFinding(findings, seen, newFinding(target, "KUBE-SA-DEFAULT-001", models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(5.4),
				"Default service account in use",
				"This workload runs with the namespace default service account, which increases blast radius when that account accumulates permissions.",
				map[string]any{"service_account": serviceAccount},
				"Create a dedicated least-privilege service account for the workload and disable token mounting if the API is not required.",
				"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
				"defaultServiceAccount"))
		}

		if target.PodSpec.HostNetwork {
			findings = appendFinding(findings, seen, newFinding(target, "KUBE-ESCAPE-003", models.SeverityHigh, models.CategoryLateralMovement, scoring.Clamp(8.1),
				"Host network enabled",
				"This workload shares the node network namespace, increasing exposure to node-local services and cloud metadata endpoints.",
				map[string]any{"hostNetwork": true},
				"Avoid `hostNetwork` unless the workload genuinely needs node-level network access.",
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"hostNetwork"))
		}

		if target.PodSpec.HostPID {
			findings = appendFinding(findings, seen, newFinding(target, "KUBE-ESCAPE-002", models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.0),
				"Host PID enabled",
				"This workload can observe or interact with processes running on the node.",
				map[string]any{"hostPID": true},
				"Disable `hostPID` for application workloads.",
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"hostPID"))
		}

		if target.PodSpec.HostIPC {
			findings = appendFinding(findings, seen, newFinding(target, "KUBE-ESCAPE-004", models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(8.0),
				"Host IPC enabled",
				"This workload shares the node IPC namespace, weakening isolation from the host.",
				map[string]any{"hostIPC": true},
				"Disable `hostIPC` unless the workload is a trusted node-level component.",
				"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
				"hostIPC"))
		}

		for _, volume := range target.PodSpec.Volumes {
			if volume.HostPath == nil {
				continue
			}

			score := 7.6
			ruleID := "KUBE-HOSTPATH-001"
			title := "HostPath volume mount"
			description := "This workload mounts a host path from the node filesystem."

			switch volume.HostPath.Path {
			case "/":
				score = 10
				ruleID = "KUBE-ESCAPE-006"
				title = "Root filesystem hostPath mount"
				description = "This workload mounts the node root filesystem and can likely escape container isolation."
			case "/var/run/docker.sock":
				score = 10
				ruleID = "KUBE-ESCAPE-005"
				title = "Docker socket mount"
				description = "Mounting the Docker socket gives the container control over sibling containers and often the node."
			case "/var/run/containerd/containerd.sock":
				score = 9.8
				ruleID = "KUBE-CONTAINERD-SOCKET-001"
				title = "Containerd socket mount"
				description = "Mounting the container runtime socket can allow container breakout or host control."
			case "/var/log":
				score = 8.5
				ruleID = "KUBE-ESCAPE-008"
				title = "Host log directory mounted"
				description = "Writable or broadly exposed host logs can enable log-based host file access techniques."
			}

			findings = appendFinding(findings, seen, newFinding(target, ruleID, severityForScore(score), models.CategoryPrivilegeEscalation, scoring.Clamp(score),
				title,
				description,
				map[string]any{"volume": volume.Name, "path": volume.HostPath.Path},
				"Replace hostPath volumes with safer abstractions like projected volumes, ConfigMaps, Secrets, or CSI drivers.",
				"https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
				"hostPath"))
		}

		for _, container := range allContainers(target.PodSpec) {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				findings = appendFinding(findings, seen, newFinding(target, "KUBE-ESCAPE-001", models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.9),
					fmt.Sprintf("Privileged container: %s", container.Name),
					"This container runs in privileged mode and effectively has host-level capabilities.",
					map[string]any{"container": container.Name},
					"Drop privileged mode and grant only the explicit Linux capabilities the workload needs.",
					"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
					"privileged"))
			}

			if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				findings = appendFinding(findings, seen, newFinding(target, "KUBE-PODSEC-APE-001", models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(7.8),
					fmt.Sprintf("Privilege escalation allowed in container: %s", container.Name),
					"This container does not explicitly disable Linux privilege escalation.",
					map[string]any{"container": container.Name},
					"Set `allowPrivilegeEscalation: false` unless the container requires setuid/setgid behavior.",
					"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
					"allowPrivilegeEscalation"))
			}

			if runsAsRoot(target.PodSpec, container) {
				findings = appendFinding(findings, seen, newFinding(target, "KUBE-PODSEC-ROOT-001", models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(6.0),
					fmt.Sprintf("Container runs as root: %s", container.Name),
					"This container is configured to run as UID 0 or explicitly disables non-root enforcement.",
					map[string]any{"container": container.Name},
					"Run the container as a non-root user and set `runAsNonRoot: true`.",
					"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
					"runAsRoot"))
			}

			if usesLatestTag(container.Image) {
				findings = appendFinding(findings, seen, newFinding(target, "KUBE-IMAGE-LATEST-001", models.SeverityLow, models.CategoryDefenseEvasion, scoring.Clamp(2.5),
					fmt.Sprintf("Mutable image tag used: %s", container.Name),
					"This container image uses a mutable tag or no tag, which makes provenance and rollback harder.",
					map[string]any{"container": container.Name, "image": container.Image},
					"Pin the image to an immutable version tag or digest.",
					"https://kubernetes.io/docs/concepts/containers/images/",
					"imageTag"))
			}
		}
	}

	return findings, nil
}

// collectTargets flattens bare pods (skipping controller-managed ones to avoid duplicate findings) and every workload-kind pod template into target entries.
func collectTargets(snapshot models.Snapshot) []target {
	targets := make([]target, 0, len(snapshot.Resources.Pods)+len(snapshot.Resources.Deployments))

	for _, pod := range snapshot.Resources.Pods {
		if isControlledPod(pod.ObjectMeta) {
			continue
		}
		targets = append(targets, target{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
			PodSpec:   pod.Spec,
		})
	}

	for _, deployment := range snapshot.Resources.Deployments {
		targets = append(targets, workloadTarget("Deployment", deployment.Name, deployment.Namespace, deployment.Spec.Template.Spec))
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		targets = append(targets, workloadTarget("DaemonSet", daemonSet.Name, daemonSet.Namespace, daemonSet.Spec.Template.Spec))
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		targets = append(targets, workloadTarget("StatefulSet", statefulSet.Name, statefulSet.Namespace, statefulSet.Spec.Template.Spec))
	}
	for _, job := range snapshot.Resources.Jobs {
		targets = append(targets, workloadTarget("Job", job.Name, job.Namespace, job.Spec.Template.Spec))
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		targets = append(targets, workloadTarget("CronJob", cronJob.Name, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec))
	}

	return targets
}

// workloadTarget builds a target from a workload's embedded pod template.
func workloadTarget(kind, name, namespace string, spec corev1.PodSpec) target {
	return target{Kind: kind, Name: name, Namespace: namespace, PodSpec: spec}
}

// isControlledPod reports whether a pod is owned by a controller so that analysis can defer to the owning workload instead.
func isControlledPod(meta metav1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// allContainers returns init and runtime containers in a single slice for uniform iteration.
func allContainers(spec corev1.PodSpec) []corev1.Container {
	items := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	items = append(items, spec.InitContainers...)
	items = append(items, spec.Containers...)
	return items
}

// runsAsRoot reports whether the container is configured to run as UID 0 or explicitly disables runAsNonRoot.
func runsAsRoot(podSpec corev1.PodSpec, container corev1.Container) bool {
	if container.SecurityContext != nil {
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			return true
		}
		if container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot {
			return true
		}
	}

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.RunAsUser != nil && *podSpec.SecurityContext.RunAsUser == 0 {
			return true
		}
		if podSpec.SecurityContext.RunAsNonRoot != nil && !*podSpec.SecurityContext.RunAsNonRoot {
			return true
		}
	}

	return false
}

// usesLatestTag reports whether image uses a mutable tag such as :latest or no tag at all (digest references are considered immutable).
func usesLatestTag(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	if !strings.Contains(image, ":") {
		return true
	}
	return strings.HasSuffix(image, ":latest")
}

// newFinding materializes a pod-security Finding tied to the given target.
func newFinding(target target, ruleID string, severity models.Severity, category models.RiskCategory, score float64, title string, description string, evidence map[string]any, remediation string, reference string, check string) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	resource := &models.ResourceRef{
		Kind:      target.Kind,
		Name:      target.Name,
		Namespace: target.Namespace,
		APIGroup:  resourceAPIGroup(target.Kind),
	}
	return models.Finding{
		ID:          fmt.Sprintf("%s:%s:%s:%s", ruleID, target.Kind, target.Namespace, target.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       score,
		Category:    category,
		Title:       title,
		Description: description,
		Namespace:   target.Namespace,
		Resource:    resource,
		Evidence:    evidenceBytes,
		Remediation: remediation,
		References:  []string{reference},
		Tags:        []string{"module:pod_security", "check:" + check},
	}
}

// appendFinding deduplicates by Finding.ID before appending.
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// resourceAPIGroup returns the Kubernetes API group for a workload kind.
func resourceAPIGroup(kind string) string {
	switch kind {
	case "Deployment", "DaemonSet", "StatefulSet":
		return appsv1.GroupName
	case "Job", "CronJob":
		return batchv1.GroupName
	default:
		return ""
	}
}

// severityForScore maps a numeric base score to the corresponding severity bucket.
func severityForScore(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score >= 2.0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}
