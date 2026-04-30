package network

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerFindsCoverageAndWeakPolicies(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "unprotected"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "flat-network"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "unprotected"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "frontend"}},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "flat-network"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-broad", Namespace: "flat-network"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "api"},
						},
						Ingress: []networkingv1.NetworkPolicyIngressRule{
							{
								From: []networkingv1.NetworkPolicyPeer{
									{NamespaceSelector: &metav1.LabelSelector{}},
								},
							},
						},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{
								To: []networkingv1.NetworkPolicyPeer{
									{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}},
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

	assertRulePresent(t, findings, "KUBE-NETPOL-COVERAGE-001")
	assertRulePresent(t, findings, "KUBE-NETPOL-WEAKNESS-001")
	assertRulePresent(t, findings, "KUBE-NETPOL-WEAKNESS-002")
}

func TestAnalyzerFindsUncoveredWorkload(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "db-only", Namespace: "apps"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "db"},
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

	assertRulePresent(t, findings, "KUBE-NETPOL-COVERAGE-002")
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
