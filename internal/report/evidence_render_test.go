package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestRenderEvidenceRBACWildcard(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"api_groups":     []string{""},
		"resources":      []string{"secrets"},
		"verbs":          []string{"get", "list", "*"},
		"source_role":    "reader",
		"source_binding": "reader-binding",
		"namespace":      "prod",
		"scope":          "namespace",
	})
	out := string(renderEvidence(raw))
	for _, want := range []string{
		"Verbs", "Resources", "API groups",
		"reader", "reader-binding", "prod",
		"ev-chip wild", // wildcard verb chip
		"core/v1",      // empty api group rendered as core/v1
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RBAC wildcard render missing %q\n---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Holds credentials") {
		t.Errorf("expected secrets resource hint, got:\n%s", out)
	}
}

func TestRenderEvidencePodSecHostPath(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"volume": "docker-sock",
		"path":   "/var/run/docker.sock",
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "/var/run/docker.sock") {
		t.Errorf("expected docker.sock path in output:\n%s", out)
	}
	if !strings.Contains(out, "container engine takeover") {
		t.Errorf("expected docker socket hint, got:\n%s", out)
	}
}

func TestRenderEvidencePodSecHostNetwork(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"hostNetwork": true,
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "hostNetwork") {
		t.Errorf("expected hostNetwork key, got:\n%s", out)
	}
	if !strings.Contains(out, "ev-chip danger") {
		t.Errorf("expected danger-classed boolean chip, got:\n%s", out)
	}
	// HTML escaping turns the apostrophe in "node's" into &#39;, so look for a span
	// of the hint that contains no apostrophe.
	if !strings.Contains(out, "Shares the node") || !strings.Contains(out, "network namespace") {
		t.Errorf("expected hostNetwork hint, got:\n%s", out)
	}
}

func TestRenderEvidencePodSecMutableImage(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"container": "app",
		"image":     "nginx:latest",
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "nginx:latest") {
		t.Errorf("expected image string, got:\n%s", out)
	}
	if !strings.Contains(out, ":latest is mutable") {
		t.Errorf("expected mutable-tag hint, got:\n%s", out)
	}
}

func TestRenderEvidenceNetworkCIDRInternet(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"policy": "allow-broad",
		"cidr":   "0.0.0.0/0",
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("expected CIDR string, got:\n%s", out)
	}
	if !strings.Contains(out, "Entire IPv4 internet") {
		t.Errorf("expected internet CIDR hint, got:\n%s", out)
	}
}

func TestRenderEvidenceAdmissionFailureIgnore(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"failurePolicy": "Ignore",
		"namespaceSelector": map[string]any{
			"matchExpressions": []any{
				map[string]any{
					"key":      "kubernetes.io/metadata.name",
					"operator": "NotIn",
					"values":   []any{"kube-system"},
				},
			},
		},
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "Ignore") {
		t.Errorf("expected failurePolicy value, got:\n%s", out)
	}
	if !strings.Contains(out, "admission policy effectively off") {
		t.Errorf("expected fail-open hint, got:\n%s", out)
	}
	if !strings.Contains(out, "is NOT one of") {
		t.Errorf("expected NotIn translation, got:\n%s", out)
	}
	if !strings.Contains(out, "kube-system") {
		t.Errorf("expected exempted namespace, got:\n%s", out)
	}
}

func TestRenderEvidenceSecretsType(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"type": "kubernetes.io/service-account-token",
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "kubernetes.io/service-account-token") {
		t.Errorf("expected raw type, got:\n%s", out)
	}
	if !strings.Contains(out, "Long-lived ServiceAccount token") {
		t.Errorf("expected friendly secret-type label, got:\n%s", out)
	}
}

func TestRenderEvidenceServiceAccount(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"workloads": []any{
			map[string]any{"kind": "Deployment", "name": "api", "namespace": "prod"},
		},
		"rules": []any{
			map[string]any{
				"verbs":          []any{"get", "list"},
				"resources":      []any{"secrets"},
				"api_groups":     []any{""},
				"namespace":      "prod",
				"source_role":    "reader",
				"source_binding": "reader-binding",
			},
		},
		"dangerous_permissions": []any{"create pods (cluster)", "impersonate (cluster)"},
	})
	out := string(renderEvidence(raw))
	for _, want := range []string{
		"Deployment/api", "prod",
		"reader", "reader-binding",
		"create pods (cluster)", "impersonate (cluster)",
		"ev-chip danger",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ServiceAccount render missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderEvidenceUnknownKeyFallback(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"future_field": map[string]any{"a": 1, "b": "two"},
	})
	out := string(renderEvidence(raw))
	if !strings.Contains(out, "future_field") {
		t.Errorf("expected unknown key in output, got:\n%s", out)
	}
	if !strings.Contains(out, "ev-json") {
		t.Errorf("expected JSON fallback class, got:\n%s", out)
	}
}

func TestRenderEvidenceEmptyAndInvalid(t *testing.T) {
	if got := string(renderEvidence(nil)); got != "" {
		t.Errorf("nil Evidence should render empty, got %q", got)
	}
	if got := string(renderEvidence(json.RawMessage(`"just a string"`))); got != "" {
		t.Errorf("non-object Evidence should render empty, got %q", got)
	}
	if got := string(renderEvidence(json.RawMessage(`{}`))); got != "" {
		t.Errorf("empty object Evidence should render empty, got %q", got)
	}
}

func TestRenderEvidenceSuppressesPrivescSummary(t *testing.T) {
	// privesc evidence keys are intentionally suppressed from the structured view —
	// the EscalationPath renderer below covers the same ground more readably.
	raw, _ := json.Marshal(map[string]any{
		"target":        "cluster_admin_equivalent",
		"hop_count":     2,
		"techniques":    []any{"pod_exec", "impersonate"},
		"first_action":  "pod_exec",
		"chain_summary": []any{"1. pod_exec", "2. impersonate"},
	})
	out := string(renderEvidence(raw))
	if out != "" {
		t.Errorf("expected empty render for privesc-only summary keys, got:\n%s", out)
	}
}

func TestRenderEscalationPathTwoHop(t *testing.T) {
	hops := []models.EscalationHop{
		{
			Step:        1,
			Action:      "pod_create_token_theft",
			FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "privileged-reader", Namespace: "vulnerable"},
			ToSubject:   models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: "vulnerable"},
			Permission:  "create pods",
			Gains:       "can create pods that mount ServiceAccount vulnerable/default",
		},
		{
			Step:        2,
			Action:      "pod_host_escape",
			FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: "vulnerable"},
			ToSubject:   models.SubjectRef{}, // sink
			Permission:  "hostNetwork,privileged,hostPath:/",
			Gains:       "runs in pod vulnerable/risky-app with hostNetwork, privileged, hostPath:/",
		},
	}
	out := string(renderEscalationPath(hops))
	for _, want := range []string{
		"Step 1", "Step 2",
		"pod_create_token_theft", "pod_host_escape",
		"ServiceAccount/vulnerable/privileged-reader",
		"ServiceAccount/vulnerable/default",
		"create pods",
		"hostNetwork,privileged,hostPath:/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("EscalationPath render missing %q\n---\n%s", want, out)
		}
	}
	// Step 2's empty ToSubject should not produce a "From → /" arrow with empty trailing code.
	if strings.Contains(out, "→ <code></code>") {
		t.Errorf("empty ToSubject should not produce empty <code> tag:\n%s", out)
	}
}

func TestRenderEscalationPathEmpty(t *testing.T) {
	if got := string(renderEscalationPath(nil)); got != "" {
		t.Errorf("nil hops should render empty, got %q", got)
	}
}

func TestHostPathHintWalksParents(t *testing.T) {
	if got := hostPathHint("/var/run/docker.sock"); !strings.Contains(got, "container engine takeover") {
		t.Errorf("exact match failed: %q", got)
	}
	if got := hostPathHint("/etc/kubernetes/pki/ca.crt"); !strings.Contains(got, "PKI") {
		t.Errorf("parent walk to /etc/kubernetes/pki failed: %q", got)
	}
	if got := hostPathHint("/totally/unknown/path"); !strings.Contains(got, "Node root") {
		t.Errorf("unknown path should walk up to root: %q", got)
	}
	if got := hostPathHint(""); got != "" {
		t.Errorf("empty path should return empty hint: %q", got)
	}
}

func TestCIDRHintContainment(t *testing.T) {
	if got := cidrHint("0.0.0.0/0"); !strings.Contains(got, "Entire IPv4 internet") {
		t.Errorf("0.0.0.0/0 hint missing: %q", got)
	}
	if got := cidrHint("10.5.0.0/16"); !strings.Contains(got, "RFC1918") {
		t.Errorf("RFC1918 containment hint missing for 10.5.0.0/16: %q", got)
	}
	if got := cidrHint("169.254.169.254/32"); !strings.Contains(got, "metadata") {
		t.Errorf("metadata service hint missing: %q", got)
	}
	if got := cidrHint("8.8.8.8/32"); got != "" {
		t.Errorf("public IP outside well-known ranges should have no hint: %q", got)
	}
}

func TestMutableImageHint(t *testing.T) {
	cases := map[string]string{
		"nginx:latest": ":latest is mutable",
		"nginx":        "No tag",
		"nginx:1.25.3": "",
		"foo/bar:v1.0": "",
		"":             "",
	}
	for in, wantSub := range cases {
		got := mutableImageHint(in)
		if wantSub == "" {
			if got != "" {
				t.Errorf("mutableImageHint(%q) = %q, expected empty", in, got)
			}
			continue
		}
		if !strings.Contains(got, wantSub) {
			t.Errorf("mutableImageHint(%q) = %q, want substring %q", in, got, wantSub)
		}
	}
}
