package report

import "testing"

// TestNewPrivescActionsHaveTechniqueCopy guards the CLAUDE.md rule that every privesc
// action slug needs a Techniques entry. TechniqueKeyForFinding resolves a path finding
// via its first hop's Action, so a missing entry silently drops the explainer card from
// the report's Background block rather than failing loudly.
func TestNewPrivescActionsHaveTechniqueCopy(t *testing.T) {
	t.Parallel()

	for _, action := range []string{
		"colocated_sa_token_theft",
		"control_plane_pki_theft",
		"static_pod_admission_bypass",
		"operator_reconcile",
	} {
		explainer, ok := Techniques[action]
		if !ok {
			t.Errorf("no Techniques entry for action %q", action)
			continue
		}
		if explainer.Title == "" || explainer.Plain == "" {
			t.Errorf("Techniques[%q] must have a Title and Plain body", action)
		}
	}
}
