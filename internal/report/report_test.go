package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardik/kubesplaining/internal/models"
)

func TestWriteProducesExpectedArtifacts(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "test-cluster"

	findings := []models.Finding{
		{
			ID:          "finding-1",
			RuleID:      "KUBE-TEST-001",
			Severity:    models.SeverityHigh,
			Score:       8.2,
			Category:    models.CategoryPrivilegeEscalation,
			Title:       "Test finding",
			Description: "A test finding",
			Namespace:   "default",
			Resource: &models.ResourceRef{
				Kind:      "Deployment",
				Name:      "app",
				Namespace: "default",
			},
			Remediation: "Fix it",
			References:  []string{"https://example.com"},
		},
	}

	written, err := Write(tmpDir, []string{"json", "csv", "sarif"}, snapshot, findings)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	expected := []string{
		filepath.Join(tmpDir, "scan-metadata.json"),
		filepath.Join(tmpDir, "triage.csv"),
		filepath.Join(tmpDir, "findings.json"),
		filepath.Join(tmpDir, "findings.sarif"),
	}

	for _, path := range expected {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}

	if len(written) != len(expected) {
		t.Fatalf("expected %d written artifacts, got %d", len(expected), len(written))
	}
}

func TestReadWriteMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	metadata := models.SnapshotMetadata{
		ClusterName:    "fixture",
		ClusterVersion: "v1.35.0",
	}

	path, err := WriteMetadata(tmpDir, metadata)
	if err != nil {
		t.Fatalf("WriteMetadata() error = %v", err)
	}

	loaded, err := ReadMetadata(path)
	if err != nil {
		t.Fatalf("ReadMetadata() error = %v", err)
	}

	if loaded.ClusterName != metadata.ClusterName || loaded.ClusterVersion != metadata.ClusterVersion {
		t.Fatalf("unexpected metadata round trip: %#v", loaded)
	}
}

func TestBuildHTMLDataGroupsFindings(t *testing.T) {
	t.Parallel()

	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:        "f1",
			RuleID:    "KUBE-RBAC-1",
			Severity:  models.SeverityCritical,
			Category:  models.CategoryPrivilegeEscalation,
			Title:     "Critical RBAC",
			Namespace: "default",
			Subject:   &models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: "default"},
			Resource:  &models.ResourceRef{Kind: "RBACRule", Name: "admin"},
			Tags:      []string{"module:rbac"},
		},
		{
			ID:        "f2",
			RuleID:    "KUBE-NETPOL-1",
			Severity:  models.SeverityHigh,
			Category:  models.CategoryLateralMovement,
			Title:     "Open network",
			Namespace: "prod",
			Resource:  &models.ResourceRef{Kind: "Namespace", Name: "prod", Namespace: "prod"},
			Tags:      []string{"module:network_policy"},
		},
	}

	data := BuildHTMLData(snapshot, findings)
	if data.Summary.Total != 2 {
		t.Fatalf("expected total summary of 2, got %#v", data.Summary)
	}
	if len(data.Modules) != 2 {
		t.Fatalf("expected 2 module sections, got %d", len(data.Modules))
	}
	if data.Modules[0].Label != "RBAC" {
		t.Fatalf("expected first module to be RBAC, got %s", data.Modules[0].Label)
	}
	if len(data.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(data.Categories))
	}
	if len(data.TopNamespaces) == 0 || data.TopNamespaces[0].Label != "default" {
		t.Fatalf("unexpected top namespaces: %#v", data.TopNamespaces)
	}
}

// TestHTMLReportInteractiveGraph verifies the rendered HTML carries the markup the JS layer
// requires (CSP allows scripts, JSON payload is embedded, nodes/edges have data IDs). It is a
// smoke test for the contract between Go and the embedded interactivity, not a behaviour test.
func TestHTMLReportInteractiveGraph(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:       "f-cap",
			RuleID:   "KUBE-PRIVESC-009",
			Severity: models.SeverityCritical,
			Score:    9.5,
			Category: models.CategoryPrivilegeEscalation,
			Title:    "RBAC bind/escalate permission",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"},
			Tags:     []string{"module:rbac"},
		},
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}

	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	mustContain := []string{
		`script-src 'unsafe-inline'`,
		`<script type="application/json" id="kp-graph-data">`,
		`data-node-id=`,
		`data-edge-id=`,
		`class="kp-filters"`,
		`class="kp-detail"`,
		`class="kp-tooltip"`,
		`KUBE-PRIVESC-009`,
	}
	for _, needle := range mustContain {
		if !strings.Contains(html, needle) {
			t.Errorf("rendered HTML missing %q", needle)
		}
	}
}
