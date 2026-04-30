package podsec

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerFindsHighRiskPodSecurityIssues(t *testing.T) {
	t.Parallel()

	privileged := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "risky",
						Namespace: "default",
					},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "default",
								HostNetwork:        true,
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx:latest",
										SecurityContext: &corev1.SecurityContext{
											Privileged: &privileged,
										},
									},
								},
								Volumes: []corev1.Volume{
									{
										Name: "rootfs",
										VolumeSource: corev1.VolumeSource{
											HostPath: &corev1.HostPathVolumeSource{Path: "/"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-SA-DEFAULT-001")
	assertRulePresent(t, findings, "KUBE-ESCAPE-003")
	assertRulePresent(t, findings, "KUBE-ESCAPE-001")
	assertRulePresent(t, findings, "KUBE-ESCAPE-006")
	assertRulePresent(t, findings, "KUBE-IMAGE-LATEST-001")
}

func TestAnalyzerIgnoresDigestPinnedNonRootWorkload(t *testing.T) {
	t.Parallel()

	falseValue := false
	runAsUser := int64(1000)
	runAsNonRoot := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "safe",
						Namespace: "default",
					},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "safe",
								Containers: []corev1.Container{
									{
										Name:  "app",
										Image: "nginx@sha256:deadbeef",
										SecurityContext: &corev1.SecurityContext{
											AllowPrivilegeEscalation: &falseValue,
											RunAsUser:                &runAsUser,
											RunAsNonRoot:             &runAsNonRoot,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}

	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}
