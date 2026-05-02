package models

// AdmissionSummary reports what the engine's admission-aware reweight stage did
// during a scan. It surfaces in the HTML report header, the JSON metadata block,
// and the SARIF run properties so consumers can audit how much risk was hidden
// or downweighted by namespace-level admission controls.
type AdmissionSummary struct {
	// Mode mirrors --admission-mode (off, attenuate, suppress).
	Mode string `json:"mode"`
	// Suppressed counts findings dropped because their namespace's PSA enforce
	// label would block the underlying workload. Always 0 unless Mode == suppress.
	Suppressed int `json:"suppressed"`
	// Attenuated counts findings whose Score was multiplied by the admission
	// mitigation factor because PSA would block the underlying workload. Always
	// 0 unless Mode == attenuate.
	Attenuated int `json:"attenuated"`
	// AuditOnly counts findings whose namespace has audit-mode PSA labels (not
	// enforce). These are tagged but never suppressed/attenuated, since audit
	// does not reject creates or updates.
	AuditOnly int `json:"audit_only,omitempty"`
	// WarnOnly counts findings whose namespace has warn-mode PSA labels.
	WarnOnly int `json:"warn_only,omitempty"`
	// SuppressedByNamespace breaks down Suppressed by namespace then RuleID for
	// per-namespace tooltips in the HTML report.
	SuppressedByNamespace map[string]map[string]int `json:"suppressed_by_namespace,omitempty"`
}
