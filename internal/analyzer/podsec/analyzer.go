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
			content := contentSADefault001(target.Kind, target.Namespace, target.Name, serviceAccount)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-SA-DEFAULT-001",
				models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(5.4),
				map[string]any{"service_account": serviceAccount}, "defaultServiceAccount", content).as())
		}

		if target.PodSpec.HostNetwork {
			content := contentEscape003(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-003",
				models.SeverityHigh, models.CategoryLateralMovement, scoring.Clamp(8.1),
				map[string]any{"hostNetwork": true}, "hostNetwork", content).as())
		}

		if target.PodSpec.HostPID {
			content := contentEscape002(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-002",
				models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.0),
				map[string]any{"hostPID": true}, "hostPID", content).as())
		}

		if target.PodSpec.HostIPC {
			content := contentEscape004(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-004",
				models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(8.0),
				map[string]any{"hostIPC": true}, "hostIPC", content).as())
		}

		for _, volume := range target.PodSpec.Volumes {
			if volume.HostPath == nil {
				continue
			}

			score := 7.6
			ruleID := "KUBE-HOSTPATH-001"
			var content ruleContent

			switch volume.HostPath.Path {
			case "/":
				score = 10
				ruleID = "KUBE-ESCAPE-006"
				content = contentEscape006(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/run/docker.sock":
				score = 10
				ruleID = "KUBE-ESCAPE-005"
				content = contentEscape005(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/run/containerd/containerd.sock":
				score = 9.8
				ruleID = "KUBE-CONTAINERD-SOCKET-001"
				content = contentContainerdSocket001(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/log":
				score = 8.5
				ruleID = "KUBE-ESCAPE-008"
				content = contentEscape008(target.Kind, target.Namespace, target.Name, volume.Name)
			default:
				content = contentHostPath001(target.Kind, target.Namespace, target.Name, volume.Name, volume.HostPath.Path)
			}

			findings = appendFinding(findings, seen, newFindingFromContent(target, ruleID,
				severityForScore(score), models.CategoryPrivilegeEscalation, scoring.Clamp(score),
				map[string]any{"volume": volume.Name, "path": volume.HostPath.Path}, "hostPath", content).withSuffix(":"+volume.Name))
		}

		for _, container := range allContainers(target.PodSpec) {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				content := contentEscape001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-001",
					models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.9),
					map[string]any{"container": container.Name}, "privileged", content).withSuffix(":"+container.Name))
			}

			if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				content := contentPodSecAPE001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-APE-001",
					models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(7.8),
					map[string]any{"container": container.Name}, "allowPrivilegeEscalation", content).withSuffix(":"+container.Name))
			}

			if runsAsRoot(target.PodSpec, container) {
				content := contentPodSecRoot001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-ROOT-001",
					models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(6.0),
					map[string]any{"container": container.Name}, "runAsRoot", content).withSuffix(":"+container.Name))
			}

			if usesLatestTag(container.Image) {
				content := contentImageLatest001(target.Kind, target.Namespace, target.Name, container.Name, container.Image)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-IMAGE-LATEST-001",
					models.SeverityLow, models.CategoryDefenseEvasion, scoring.Clamp(2.5),
					map[string]any{"container": container.Name, "image": container.Image}, "imageTag", content).withSuffix(":"+container.Name))
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

// findingWithID wraps a Finding so analyzer call-sites can apply a per-container ID suffix
// (different containers in the same workload should each produce a unique finding ID).
type findingWithID models.Finding

// withSuffix appends suffix to the Finding.ID and returns the result. Used so per-container
// findings (privileged, runAsRoot, etc.) inside the same workload don't collide on ID.
func (f findingWithID) withSuffix(suffix string) models.Finding {
	out := models.Finding(f)
	out.ID = out.ID + suffix
	return out
}

// as returns the underlying Finding without an ID suffix. Used at call sites that don't need
// per-container disambiguation.
func (f findingWithID) as() models.Finding {
	return models.Finding(f)
}

// newFindingFromContent materializes a pod-security Finding using the enriched ruleContent
// (Scope, Impact, AttackScenario, RemediationSteps, LearnMore, MitreTechniques) plus the
// runtime context. Returns findingWithID so per-container variants can use .withSuffix().
func newFindingFromContent(target target, ruleID string, severity models.Severity, category models.RiskCategory, score float64, evidence map[string]any, check string, content ruleContent) findingWithID {
	evidenceBytes, _ := json.Marshal(evidence)
	resource := &models.ResourceRef{
		Kind:      target.Kind,
		Name:      target.Name,
		Namespace: target.Namespace,
		APIGroup:  resourceAPIGroup(target.Kind),
	}
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return findingWithID(models.Finding{
		ID:               fmt.Sprintf("%s:%s:%s:%s", ruleID, target.Kind, target.Namespace, target.Name),
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Namespace:        target.Namespace,
		Resource:         resource,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:pod_security", "check:" + check},
	})
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
