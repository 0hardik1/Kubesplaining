// Package mitigation maps kubesplaining pod-security findings to the cluster admission
// controls that would block their workload at admission time. The engine consumes the
// results of WouldPSABlock + PSAStateForNamespace to suppress or attenuate findings whose
// underlying spec would never make it past Pod Security Admission.
package mitigation

const (
	// PSALevelPrivileged is the most permissive Pod Security Standard level — nothing is blocked.
	PSALevelPrivileged = "privileged"
	// PSALevelBaseline blocks known privilege-escalation surfaces (host namespaces, hostPath, privileged containers).
	PSALevelBaseline = "baseline"
	// PSALevelRestricted is a superset of baseline; also requires non-root, drops capabilities, blocks allowPrivilegeEscalation.
	PSALevelRestricted = "restricted"
)

const (
	// PSAModeEnforce rejects creates and updates that violate the level.
	PSAModeEnforce = "enforce"
	// PSAModeAudit logs violations but does not reject.
	PSAModeAudit = "audit"
	// PSAModeWarn surfaces a warning to the user-agent but does not reject.
	PSAModeWarn = "warn"
)

// LabelEnforce, LabelAudit, LabelWarn are the canonical PSA label keys on a namespace.
const (
	LabelEnforce = "pod-security.kubernetes.io/enforce"
	LabelAudit   = "pod-security.kubernetes.io/audit"
	LabelWarn    = "pod-security.kubernetes.io/warn"
)

// PSAState captures the three PSA labels resolved off a namespace. Empty strings mean the namespace is unlabeled in that mode.
type PSAState struct {
	Enforce string
	Audit   string
	Warn    string
}

// HasEnforce reports whether the namespace carries an enforce-mode label at baseline or stricter.
func (s PSAState) HasEnforce() bool {
	return s.Enforce == PSALevelBaseline || s.Enforce == PSALevelRestricted
}

// PSAStateForLabels extracts the three PSA labels from a namespace's labels map. Unrecognized
// or empty values pass through; callers should use the level constants above for comparisons.
func PSAStateForLabels(labels map[string]string) PSAState {
	if labels == nil {
		return PSAState{}
	}
	return PSAState{
		Enforce: labels[LabelEnforce],
		Audit:   labels[LabelAudit],
		Warn:    labels[LabelWarn],
	}
}

// WouldPSABlock reports whether a Pod Security Standard at the given level forbids the
// workload trait identified by check (the podsec-analyzer "check:<name>" tag value).
// Returns false for unknown checks, the privileged level, and empty levels — the engine
// treats these as "no admission attenuation applies, score stays as-is."
//
// Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
func WouldPSABlock(check, level string) bool {
	if check == "" || level == "" || level == PSALevelPrivileged {
		return false
	}
	switch check {
	case "privileged",
		"hostPath",
		"hostNetwork",
		"hostPID",
		"hostIPC":
		return level == PSALevelBaseline || level == PSALevelRestricted
	case "allowPrivilegeEscalation",
		"runAsRoot":
		return level == PSALevelRestricted
	default:
		return false
	}
}
