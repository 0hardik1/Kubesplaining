package mitigation

import (
	"reflect"
	"testing"
)

func TestPolicyEnginesAny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		engines PolicyEngines
		want    bool
	}{
		{"empty", PolicyEngines{}, false},
		{"kyverno only", PolicyEngines{Kyverno: true}, true},
		{"gatekeeper only", PolicyEngines{Gatekeeper: true}, true},
		{"vap only", PolicyEngines{VAP: true}, true},
		{"all three", PolicyEngines{Kyverno: true, Gatekeeper: true, VAP: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.engines.Any(); got != tc.want {
				t.Errorf("Any() = %v want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyEnginesNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		engines PolicyEngines
		want    []string
	}{
		{"empty", PolicyEngines{}, []string{}},
		{"kyverno only", PolicyEngines{Kyverno: true}, []string{"kyverno"}},
		{"gatekeeper only", PolicyEngines{Gatekeeper: true}, []string{"gatekeeper"}},
		{"vap only", PolicyEngines{VAP: true}, []string{"vap"}},
		// Sort stability: regardless of struct field order, output is alphabetical so
		// downstream JSON / SARIF consumers see a deterministic list.
		{"kyverno+vap", PolicyEngines{Kyverno: true, VAP: true}, []string{"kyverno", "vap"}},
		{"all three", PolicyEngines{Kyverno: true, Gatekeeper: true, VAP: true}, []string{"gatekeeper", "kyverno", "vap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.engines.Names()
			// Treat nil and empty slice as equal — the empty-input case wants []string{}.
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Names() = %v want %v", got, tc.want)
			}
		})
	}
}
