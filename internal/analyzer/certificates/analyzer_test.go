package certificates

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// approvedCondition is the shape the collector records for an approved CSR.
func approvedCondition() []models.CSRCondition {
	return []models.CSRCondition{{Type: "Approved", Status: "True", Reason: "KubectlApprove"}}
}

// TestCSRRules is the table for both object rules. The negative rows matter more
// than the positive ones: this module runs against every CSR in the cluster, and a
// kind / kubeadm cluster always has node-bootstrap CSRs sitting in the snapshot. If
// those fire, the rule is noise on literally every cluster.
func TestCSRRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		csr          models.CSR
		wantRules    []string
		wantSeverity map[string]models.Severity
		reason       string
	}{
		{
			name: "approved client cert requested by a ServiceAccount",
			csr: models.CSR{
				Name:       "sa-mint",
				SignerName: "kubernetes.io/kube-apiserver-client",
				Username:   "system:serviceaccount:apps:builder",
				Usages:     []string{"client auth"},
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules:    []string{"KUBE-CSR-001"},
			wantSeverity: map[string]models.Severity{"KUBE-CSR-001": models.SeverityHigh},
		},
		{
			name: "pending client cert requested by a ServiceAccount is lower severity",
			csr: models.CSR{
				Name:       "sa-pending",
				SignerName: "kubernetes.io/kube-apiserver-client",
				Username:   "system:serviceaccount:apps:builder",
			},
			wantRules:    []string{"KUBE-CSR-001"},
			wantSeverity: map[string]models.Severity{"KUBE-CSR-001": models.SeverityMedium},
			reason:       "nothing is issued yet, so the operator can still deny it",
		},
		{
			name: "denied request is skipped entirely",
			csr: models.CSR{
				Name:       "sa-denied",
				SignerName: "kubernetes.io/kube-apiserver-client",
				Username:   "system:serviceaccount:apps:builder",
				Conditions: []models.CSRCondition{{Type: "Denied", Status: "True"}},
			},
			wantRules: nil,
			reason:    "the apiserver refused to issue, so there is no credential",
		},
		{
			name: "node bootstrap CSR does not fire (the requester is not a ServiceAccount)",
			csr: models.CSR{
				Name:       "csr-abcde",
				SignerName: "kubernetes.io/kube-apiserver-client-kubelet",
				Username:   "system:bootstrap:x1y2z3",
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules: nil,
			reason:    "every kubeadm/kind cluster has these; firing here makes the module noise everywhere",
		},
		{
			name: "kubelet renewal CSR does not fire",
			csr: models.CSR{
				Name:       "csr-renew",
				SignerName: "kubernetes.io/kube-apiserver-client-kubelet",
				Username:   "system:node:worker-1",
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules: nil,
		},
		{
			name: "human-requested client cert does not fire",
			csr: models.CSR{
				Name:       "onboard-alice",
				SignerName: "kubernetes.io/kube-apiserver-client",
				Username:   "kubernetes-admin",
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules: nil,
			reason:    "cert-based user onboarding is routine ops; only a workload identity asking is anomalous",
		},
		{
			name: "serving cert requested by a ServiceAccount does not fire",
			csr: models.CSR{
				Name:       "serving",
				SignerName: "kubernetes.io/kubelet-serving",
				Username:   "system:serviceaccount:apps:builder",
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules: nil,
			reason:    "a serving cert is not a client credential against the apiserver",
		},
		{
			name: "legacy-unknown signer fires on its own rule regardless of requester",
			csr: models.CSR{
				Name:       "legacy",
				SignerName: "kubernetes.io/legacy-unknown",
				Username:   "kubernetes-admin",
			},
			wantRules:    []string{"KUBE-CSR-002"},
			wantSeverity: map[string]models.Severity{"KUBE-CSR-002": models.SeverityMedium},
			reason:       "CertificateSubjectRestriction only guards kube-apiserver-client, so this signer is the system:masters loophole",
		},
		{
			name: "approved legacy-unknown from a ServiceAccount fires both rules",
			csr: models.CSR{
				Name:       "legacy-sa",
				SignerName: "kubernetes.io/legacy-unknown",
				Username:   "system:serviceaccount:kube-system:sneaky",
				Conditions: approvedCondition(),
				Approved:   true,
			},
			wantRules: []string{"KUBE-CSR-001", "KUBE-CSR-002"},
			wantSeverity: map[string]models.Severity{
				"KUBE-CSR-001": models.SeverityHigh,
				"KUBE-CSR-002": models.SeverityHigh,
			},
			reason: "the rules answer different questions: who asked, and which signer was targeted",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					CertificateSigningRequests: []models.CSR{tc.csr},
				},
			}
			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			got := map[string]models.Finding{}
			for _, f := range findings {
				got[f.RuleID] = f
			}
			if len(got) != len(tc.wantRules) {
				t.Fatalf("got rules %v, want %v (%s)", keys(got), tc.wantRules, tc.reason)
			}
			for _, ruleID := range tc.wantRules {
				f, ok := got[ruleID]
				if !ok {
					t.Fatalf("expected %s to fire, got %v (%s)", ruleID, keys(got), tc.reason)
				}
				if want := tc.wantSeverity[ruleID]; f.Severity != want {
					t.Errorf("%s severity = %q, want %q", ruleID, f.Severity, want)
				}
				if f.Resource == nil || f.Resource.Kind != "CertificateSigningRequest" || f.Resource.Name != tc.csr.Name {
					t.Errorf("%s should point at the CSR object, got %+v", ruleID, f.Resource)
				}
			}
		})
	}
}

// TestSubjectIsTheRequestingServiceAccount pins the attribution: the finding carries
// the requesting SA as its Subject, so it lands next to that identity's other findings
// in the report rather than floating as an orphaned cluster-scoped object. (It is not
// a chain-amplification hook — the correlate pass bumps only the finding that is itself
// a chain edge.)
func TestSubjectIsTheRequestingServiceAccount(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			CertificateSigningRequests: []models.CSR{{
				Name:       "sa-mint",
				SignerName: "kubernetes.io/kube-apiserver-client",
				Username:   "system:serviceaccount:apps:builder",
				Conditions: approvedCondition(),
				Approved:   true,
			}},
		},
	}
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	subject := findings[0].Subject
	if subject == nil || subject.Kind != "ServiceAccount" || subject.Namespace != "apps" || subject.Name != "builder" {
		t.Fatalf("subject should be the requesting ServiceAccount, got %+v", subject)
	}
	// The copy must not claim we know which identity the CSR asked for: the raw PEM
	// is dropped by the collector, so the Subject DN is genuinely unknown here.
	if !strings.Contains(findings[0].Description, "does NOT claim") {
		t.Errorf("description must state the limit of what the snapshot can see: %q", findings[0].Description)
	}
}

// TestEmptySnapshot guards the common case: a cluster with no CSRs (or a snapshot
// taken from a cluster where listing them was forbidden) produces nothing.
func TestEmptySnapshot(t *testing.T) {
	t.Parallel()
	findings, err := New().Analyze(context.Background(), models.Snapshot{})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func keys(m map[string]models.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
