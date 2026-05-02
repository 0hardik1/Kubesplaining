package mitigation

import "testing"

func TestWouldPSABlock(t *testing.T) {
	cases := []struct {
		name  string
		check string
		level string
		want  bool
	}{
		// Restricted blocks everything in our host-security family.
		{"restricted_privileged", "privileged", PSALevelRestricted, true},
		{"restricted_hostPath", "hostPath", PSALevelRestricted, true},
		{"restricted_hostNetwork", "hostNetwork", PSALevelRestricted, true},
		{"restricted_hostPID", "hostPID", PSALevelRestricted, true},
		{"restricted_hostIPC", "hostIPC", PSALevelRestricted, true},
		{"restricted_allowPrivilegeEscalation", "allowPrivilegeEscalation", PSALevelRestricted, true},
		{"restricted_runAsRoot", "runAsRoot", PSALevelRestricted, true},

		// Baseline blocks the host-namespace + privileged + hostPath family but
		// not the runAsRoot / allowPrivilegeEscalation hardening checks.
		{"baseline_privileged", "privileged", PSALevelBaseline, true},
		{"baseline_hostPath", "hostPath", PSALevelBaseline, true},
		{"baseline_hostNetwork", "hostNetwork", PSALevelBaseline, true},
		{"baseline_hostPID", "hostPID", PSALevelBaseline, true},
		{"baseline_hostIPC", "hostIPC", PSALevelBaseline, true},
		{"baseline_allowPrivilegeEscalation", "allowPrivilegeEscalation", PSALevelBaseline, false},
		{"baseline_runAsRoot", "runAsRoot", PSALevelBaseline, false},

		// Privileged level blocks nothing.
		{"privileged_privileged", "privileged", PSALevelPrivileged, false},
		{"privileged_hostPath", "hostPath", PSALevelPrivileged, false},
		{"privileged_runAsRoot", "runAsRoot", PSALevelPrivileged, false},

		// Empty level / unknown level / unknown check fall through to false.
		{"empty_level", "privileged", "", false},
		{"unknown_level", "privileged", "fortified", false},
		{"unknown_check", "imageTag", PSALevelRestricted, false},
		{"empty_check", "", PSALevelRestricted, false},

		// Checks the analyzer emits but PSA does not concern itself with.
		{"defaultServiceAccount_restricted", "defaultServiceAccount", PSALevelRestricted, false},
		{"imageTag_restricted", "imageTag", PSALevelRestricted, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WouldPSABlock(tc.check, tc.level); got != tc.want {
				t.Fatalf("WouldPSABlock(%q, %q) = %v, want %v", tc.check, tc.level, got, tc.want)
			}
		})
	}
}

func TestPSAStateForLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   PSAState
	}{
		{
			name:   "nil labels",
			labels: nil,
			want:   PSAState{},
		},
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   PSAState{},
		},
		{
			name: "all three labels set",
			labels: map[string]string{
				LabelEnforce: PSALevelRestricted,
				LabelAudit:   PSALevelBaseline,
				LabelWarn:    PSALevelBaseline,
			},
			want: PSAState{Enforce: PSALevelRestricted, Audit: PSALevelBaseline, Warn: PSALevelBaseline},
		},
		{
			name: "audit-only",
			labels: map[string]string{
				LabelAudit: PSALevelRestricted,
			},
			want: PSAState{Audit: PSALevelRestricted},
		},
		{
			name: "unrelated labels ignored",
			labels: map[string]string{
				"app.kubernetes.io/name": "demo",
				LabelEnforce:             PSALevelBaseline,
			},
			want: PSAState{Enforce: PSALevelBaseline},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PSAStateForLabels(tc.labels)
			if got != tc.want {
				t.Fatalf("PSAStateForLabels(%v) = %+v, want %+v", tc.labels, got, tc.want)
			}
		})
	}
}

func TestHasEnforce(t *testing.T) {
	cases := []struct {
		name string
		s    PSAState
		want bool
	}{
		{"empty", PSAState{}, false},
		{"enforce_privileged", PSAState{Enforce: PSALevelPrivileged}, false},
		{"enforce_baseline", PSAState{Enforce: PSALevelBaseline}, true},
		{"enforce_restricted", PSAState{Enforce: PSALevelRestricted}, true},
		{"audit_only", PSAState{Audit: PSALevelRestricted}, false},
		{"warn_only", PSAState{Warn: PSALevelRestricted}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.HasEnforce(); got != tc.want {
				t.Fatalf("HasEnforce() = %v, want %v", got, tc.want)
			}
		})
	}
}
