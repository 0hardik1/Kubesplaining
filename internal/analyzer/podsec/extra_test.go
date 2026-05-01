package podsec

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNameReturnsModuleIdentifier(t *testing.T) {
	t.Parallel()
	if New().Name() != "podsec" {
		t.Errorf("Name() = %q, want podsec", New().Name())
	}
}

func TestSeverityForScoreBuckets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		score float64
		want  models.Severity
	}{
		{10, models.SeverityCritical},
		{9.0, models.SeverityCritical},
		{8.5, models.SeverityHigh},
		{7.0, models.SeverityHigh},
		{6.0, models.SeverityMedium},
		{4.0, models.SeverityMedium},
		{3.5, models.SeverityLow},
		{2.0, models.SeverityLow},
		{1.0, models.SeverityInfo},
		{0, models.SeverityInfo},
	}
	for _, tc := range cases {
		if got := scoring.SeverityForScore(tc.score); got != tc.want {
			t.Errorf("scoring.SeverityForScore(%v) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

func TestResourceAPIGroupForKnownKinds(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Deployment":  appsv1.GroupName,
		"DaemonSet":   appsv1.GroupName,
		"StatefulSet": appsv1.GroupName,
		"Job":         batchv1.GroupName,
		"CronJob":     batchv1.GroupName,
		"Pod":         "",
		"Unknown":     "",
	}
	for kind, want := range cases {
		if got := resourceAPIGroup(kind); got != want {
			t.Errorf("resourceAPIGroup(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestUsesLatestTagVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		image string
		want  bool
	}{
		{"nginx", true},                  // no tag
		{"nginx:latest", true},           // explicit latest
		{"nginx:1.25", false},            // pinned tag
		{"nginx@sha256:deadbeef", false}, // digest
		{"registry.io/nginx:1", false},
		{"registry.io/nginx:latest", true},
	}
	for _, tc := range cases {
		if got := usesLatestTag(tc.image); got != tc.want {
			t.Errorf("usesLatestTag(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

func TestRunsAsRootDetectsPodAndContainerSettings(t *testing.T) {
	t.Parallel()

	zero := int64(0)
	nonzero := int64(1000)
	falseVal := false
	trueVal := true

	t.Run("container UID 0", func(t *testing.T) {
		got := runsAsRoot(corev1.PodSpec{}, corev1.Container{
			SecurityContext: &corev1.SecurityContext{RunAsUser: &zero},
		})
		if !got {
			t.Error("RunAsUser=0 should be detected as root")
		}
	})

	t.Run("container RunAsNonRoot=false", func(t *testing.T) {
		got := runsAsRoot(corev1.PodSpec{}, corev1.Container{
			SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &falseVal},
		})
		if !got {
			t.Error("container.RunAsNonRoot=false should be detected as root")
		}
	})

	t.Run("pod-level UID 0 propagates", func(t *testing.T) {
		got := runsAsRoot(corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: &zero},
		}, corev1.Container{})
		if !got {
			t.Error("pod-level RunAsUser=0 should be detected as root")
		}
	})

	t.Run("pod-level RunAsNonRoot=false", func(t *testing.T) {
		got := runsAsRoot(corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &falseVal},
		}, corev1.Container{})
		if !got {
			t.Error("pod-level RunAsNonRoot=false should be detected as root")
		}
	})

	t.Run("non-root explicit", func(t *testing.T) {
		got := runsAsRoot(corev1.PodSpec{}, corev1.Container{
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:    &nonzero,
				RunAsNonRoot: &trueVal,
			},
		})
		if got {
			t.Error("UID 1000 + RunAsNonRoot=true should not be flagged as root")
		}
	})
}

func TestIsControlledPodDetectsOwnerReferences(t *testing.T) {
	t.Parallel()

	yes := true
	no := false

	if !isControlledPod(metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs", Controller: &yes}},
	}) {
		t.Error("expected controller-owned pod to be detected")
	}

	if isControlledPod(metav1.ObjectMeta{}) {
		t.Error("bare pod should not be detected as controlled")
	}

	// Owner reference with Controller=false should not count.
	if isControlledPod(metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Controller: &no}},
	}) {
		t.Error("non-controller OwnerReference should not count")
	}
}

func TestAnalyzerSkipsControllerOwnedPodsToAvoidDoubleCounting(t *testing.T) {
	t.Parallel()

	yes := true
	privileged := true

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "owned", Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Controller: &yes}},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{Privileged: &privileged}},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "KUBE-ESCAPE-001" {
			t.Errorf("controller-owned pod should be skipped; got privileged finding %#v", f)
		}
	}
}

func TestAnalyzerEmitsHostPIDAndHostIPC(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "shared-ns", Namespace: "default"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								HostPID:            true,
								HostIPC:            true,
								ServiceAccountName: "custom",
								Containers: []corev1.Container{
									{Name: "c", Image: "nginx@sha256:abc",
										SecurityContext: &corev1.SecurityContext{
											AllowPrivilegeEscalation: ptrBool(false),
											RunAsNonRoot:             ptrBool(true),
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

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	mustHaveRule(t, got, "KUBE-ESCAPE-002") // hostPID
	mustHaveRule(t, got, "KUBE-ESCAPE-004") // hostIPC
}

func TestAnalyzerHostPathVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path   string
		ruleID string
	}{
		{"/var/run/docker.sock", "KUBE-ESCAPE-005"},
		{"/var/run/containerd/containerd.sock", "KUBE-CONTAINERD-SOCKET-001"},
		{"/var/log", "KUBE-ESCAPE-008"},
		{"/etc/kubernetes", "KUBE-HOSTPATH-001"}, // generic path
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					Pods: []corev1.Pod{
						{
							ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
							Spec: corev1.PodSpec{
								ServiceAccountName: "custom",
								Containers: []corev1.Container{
									{Name: "c", Image: "nginx@sha256:abc",
										SecurityContext: &corev1.SecurityContext{
											AllowPrivilegeEscalation: ptrBool(false),
											RunAsNonRoot:             ptrBool(true),
										}},
								},
								Volumes: []corev1.Volume{
									{Name: "v", VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{Path: tc.path},
									}},
								},
							},
						},
					},
				},
			}
			got, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			mustHaveRule(t, got, tc.ruleID)
		})
	}
}

func TestAnalyzerEmitsRunAsRootForRoot(t *testing.T) {
	t.Parallel()

	zero := int64(0)
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rooty", Namespace: "ns"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "custom",
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
									RunAsUser:                &zero,
								}},
						},
					},
				},
			},
		},
	}
	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	mustHaveRule(t, got, "KUBE-PODSEC-ROOT-001")
}

func TestAnalyzerSkipsDefaultSAFinding_ForKubeNamespace(t *testing.T) {
	t.Parallel()

	// Pods using "default" SA inside a kube- namespace should not produce KUBE-SA-DEFAULT-001
	// (system pods routinely use the default SA and the rule explicitly excludes them).
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "kube-pod", Namespace: "kube-system"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "c", Image: "nginx@sha256:abc",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: ptrBool(false),
									RunAsNonRoot:             ptrBool(true),
								}},
						},
					},
				},
			},
		},
	}
	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range got {
		if f.RuleID == "KUBE-SA-DEFAULT-001" {
			t.Error("expected KUBE-SA-DEFAULT-001 to be suppressed in kube-system namespace")
		}
	}
}

func TestAnalyzerCoversAllWorkloadKinds(t *testing.T) {
	t.Parallel()

	// One privileged container per workload kind. Each should produce its own KUBE-ESCAPE-001 finding.
	priv := true
	pod := corev1.PodSpec{
		ServiceAccountName: "custom",
		Containers: []corev1.Container{
			{Name: "c", Image: "nginx@sha256:abc",
				SecurityContext: &corev1.SecurityContext{Privileged: &priv}},
		},
	}
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Deployments: []appsv1.Deployment{
				{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "ns"},
					Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: pod}}},
			},
			DaemonSets: []appsv1.DaemonSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "ds", Namespace: "ns"},
					Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: pod}}},
			},
			StatefulSets: []appsv1.StatefulSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: "ns"},
					Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: pod}}},
			},
			Jobs: []batchv1.Job{
				{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "ns"},
					Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod}}},
			},
			CronJobs: []batchv1.CronJob{
				{ObjectMeta: metav1.ObjectMeta{Name: "cj", Namespace: "ns"},
					Spec: batchv1.CronJobSpec{
						JobTemplate: batchv1.JobTemplateSpec{
							Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: pod}},
						},
					}},
			},
		},
	}

	got, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	count := 0
	for _, f := range got {
		if f.RuleID == "KUBE-ESCAPE-001" {
			count++
		}
	}
	if count != 5 {
		t.Errorf("expected 5 KUBE-ESCAPE-001 findings (one per workload kind), got %d", count)
	}
}

func ptrBool(v bool) *bool { return &v }

func mustHaveRule(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s, findings=%v", ruleID, findings)
}
