package models_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// tierBAnchor is the prose immediately before the Tier B row's parenthesised list of
// object types in docs/privesc-research.md.
const tierBAnchor = "Needs a **new object type** added to the snapshot ("

// TestTierBListMatchesCollectedTypes guards a drift class that has already recurred.
//
// docs/privesc-research.md tiers every proposed rule by what it would cost to build.
// Tier B means "the collector does not have this object type yet", which is a claim
// about the tree, and the tree moves. Three types on that list (Services,
// ValidatingAdmissionPolicies, CertificateSigningRequests) were collected while the
// doc still rated rules over them as blocked on collector work, which mis-sequenced
// the roadmap: work already unblocked kept being filed behind a collector extension
// that had shipped.
//
// The check runs the sound direction only. It fails when the doc names a type the
// snapshot already carries, and says nothing about types the doc omits, because a
// type absent from both is simply a rule nobody has proposed.
func TestTierBListMatchesCollectedTypes(t *testing.T) {
	t.Parallel()

	doc := readRepoFile(t, filepath.Join("docs", "privesc-research.md"))

	start := strings.Index(doc, tierBAnchor)
	if start < 0 {
		t.Fatalf("could not locate the Tier B type list in docs/privesc-research.md.\n"+
			"It is found by the literal anchor %q. If the row was reworded, update the anchor;\n"+
			"do not delete this test, because the drift it catches has already happened three times.", tierBAnchor)
	}
	rest := doc[start+len(tierBAnchor):]
	end := strings.Index(rest, ")")
	if end < 0 {
		t.Fatal("the Tier B type list is not closed by a ')'")
	}

	listed := map[string]string{} // normalized -> as written
	for _, entry := range strings.Split(rest[:end], ",") {
		// "Endpoints/EndpointSlices" is one entry naming two types.
		for _, name := range strings.Split(entry, "/") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			listed[normalizeTypeName(name)] = name
		}
	}
	if len(listed) == 0 {
		t.Fatal("the Tier B type list parsed as empty; the check would pass vacuously")
	}

	resources := reflect.TypeOf(models.SnapshotResources{})
	for i := range resources.NumField() {
		field := resources.Field(i)
		if field.Type.Kind() != reflect.Slice {
			continue
		}
		collected := field.Type.Elem().Name()
		for _, alias := range append([]string{collected}, kindAliases[collected]...) {
			if written, ok := listed[normalizeTypeName(alias)]; ok {
				t.Errorf("docs/privesc-research.md rates %q as Tier B (needs a new object type added to "+
					"the snapshot), but models.SnapshotResources.%s already collects %s. Rules over it are "+
					"Tier A: drop it from the Tier B list and re-tier anything sequenced behind it.",
					written, field.Name, collected)
				break
			}
		}
	}
}

// kindAliases maps a snapshot field's Go element type onto the Kubernetes kind names
// the doc would use for it, for the few fields that hold a local wrapper rather than
// the upstream type. Without these the check would miss a Tier B entry written as
// "CertificateSigningRequests" against a field typed []models.CSR.
var kindAliases = map[string][]string{
	"CSR":               {"CertificateSigningRequest"},
	"SecretMetadata":    {"Secret"},
	"ConfigMapSnapshot": {"ConfigMap"},
}

// normalizeTypeName folds a Go type name and the doc's prose plural onto one key:
// lowercase, then strip a trailing plural suffix. "Ingresses" and "Ingress" both
// become "ingress"; "EndpointSlices" and "EndpointSlice" both become "endpointslice".
func normalizeTypeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasSuffix(name, "ies"):
		// Policies -> policy, so it lines up with ValidatingAdmissionPolicy.
		return strings.TrimSuffix(name, "ies") + "y"
	case strings.HasSuffix(name, "ses"), strings.HasSuffix(name, "xes"),
		strings.HasSuffix(name, "ches"), strings.HasSuffix(name, "shes"):
		// Ingresses -> ingress, PriorityClasses -> priorityclass.
		return strings.TrimSuffix(name, "es")
	case strings.HasSuffix(name, "s"):
		return strings.TrimSuffix(name, "s")
	}
	return name
}

// readRepoFile reads a path relative to the repository root, found by walking up
// from the test's working directory to the directory holding go.mod.
func readRepoFile(t *testing.T, relative string) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked past the filesystem root without finding go.mod")
		}
		dir = parent
	}

	content, err := os.ReadFile(filepath.Join(dir, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(content)
}
