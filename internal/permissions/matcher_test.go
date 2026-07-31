package permissions

import "testing"

func TestGrantsAPIGroupAwareness(t *testing.T) {
	tests := []struct {
		name      string
		apiGroups []string
		resources []string
		verbs     []string
		targets   []ResourceTarget
		want      []string
		expect    bool
	}{
		{
			name:      "core secrets matches core target",
			apiGroups: []string{""}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "custom-group secrets does not match core secrets",
			apiGroups: []string{"example.com"}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: false,
		},
		{
			name:      "wildcard apiGroup matches core target",
			apiGroups: []string{"*"}, resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "rbac group required for rolebindings",
			apiGroups: []string{""}, resources: []string{"rolebindings"}, verbs: []string{"create"},
			targets: []ResourceTarget{InGroup("rbac.authorization.k8s.io", "rolebindings")}, want: []string{"create"}, expect: false,
		},
		{
			name:      "rbac group matches rolebindings",
			apiGroups: []string{"rbac.authorization.k8s.io"}, resources: []string{"rolebindings"}, verbs: []string{"patch"},
			targets: []ResourceTarget{InGroup("rbac.authorization.k8s.io", "rolebindings")}, want: []string{"create", "update", "patch"}, expect: true,
		},
		{
			name:      "wildcard resource matches any target in the group",
			apiGroups: []string{""}, resources: []string{"*"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "verb must also match",
			apiGroups: []string{""}, resources: []string{"secrets"}, verbs: []string{"list"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Grants(tt.apiGroups, tt.resources, tt.verbs, nil, tt.targets, tt.want)
			if got != tt.expect {
				t.Errorf("Grants() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestGrantsResourceNamesSemantics(t *testing.T) {
	names := []string{"my-object"}
	tests := []struct {
		name      string
		resources []string
		verbs     []string
		targets   []ResourceTarget
		want      []string
		expect    bool
	}{
		{
			name:      "list on named collection is voided (cannot enumerate)",
			resources: []string{"secrets"}, verbs: []string{"list"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"list"}, expect: false,
		},
		{
			name:      "watch on named collection is voided",
			resources: []string{"secrets"}, verbs: []string{"watch"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"watch"}, expect: false,
		},
		{
			name:      "create on top-level resource is voided (no name at authz time)",
			resources: []string{"pods"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("pods")}, want: []string{"create"}, expect: false,
		},
		{
			name:      "deletecollection is voided",
			resources: []string{"secrets"}, verbs: []string{"deletecollection"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"deletecollection"}, expect: false,
		},
		{
			name:      "get on named object still matches (scoped read)",
			resources: []string{"secrets"}, verbs: []string{"get"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
		{
			name:      "update/patch on named object still matches",
			resources: []string{"secrets"}, verbs: []string{"patch"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"update", "patch"}, expect: true,
		},
		{
			name:      "impersonate scoped to named identity still matches (still dangerous)",
			resources: []string{"groups"}, verbs: []string{"impersonate"},
			targets: []ResourceTarget{Core("groups")}, want: []string{"impersonate"}, expect: true,
		},
		{
			name:      "create on a subresource is name-scopable (parent name in URL)",
			resources: []string{"serviceaccounts/token"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("serviceaccounts/token")}, want: []string{"create"}, expect: true,
		},
		{
			name:      "exec (create on pods/exec) is name-scopable",
			resources: []string{"pods/exec"}, verbs: []string{"create"},
			targets: []ResourceTarget{Core("pods/exec")}, want: []string{"create", "get"}, expect: true,
		},
		{
			name:      "wildcard verb does not resurrect a voided list",
			resources: []string{"secrets"}, verbs: []string{"*"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"list"}, expect: false,
		},
		{
			name:      "wildcard verb still authorizes a name-scopable get",
			resources: []string{"secrets"}, verbs: []string{"*"},
			targets: []ResourceTarget{Core("secrets")}, want: []string{"get"}, expect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Grants([]string{""}, tt.resources, tt.verbs, names, tt.targets, tt.want)
			if got != tt.expect {
				t.Errorf("Grants(resourceNames=%v) = %v, want %v", names, got, tt.expect)
			}
		})
	}
}

func TestEffectiveRuleGrantsAndNameScoped(t *testing.T) {
	unrestricted := EffectiveRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}
	if unrestricted.NameScoped() {
		t.Error("rule without resourceNames should not report NameScoped")
	}
	if !unrestricted.Grants([]ResourceTarget{Core("secrets")}, "list") {
		t.Error("unrestricted list secrets should grant")
	}

	scoped := EffectiveRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "get"}, ResourceNames: []string{"tls"}}
	if !scoped.NameScoped() {
		t.Error("rule with resourceNames should report NameScoped")
	}
	if scoped.Grants([]ResourceTarget{Core("secrets")}, "list") {
		t.Error("name-scoped list secrets must not grant enumeration")
	}
	if !scoped.Grants([]ResourceTarget{Core("secrets")}, "get") {
		t.Error("name-scoped get secrets should still grant a scoped read")
	}
}

// TestSignersCoveredNameGrammar pins the signer-name grammar, which is the one place
// resourceNames does NOT mean "these object instances". For the virtual `signers`
// resource the names are signerNames, with their own wildcard forms, so an
// unrestricted rule covers every signer while a rule pinned to somebody else's
// signer covers none of the ones that matter.
func TestSignersCoveredNameGrammar(t *testing.T) {
	tests := []struct {
		name          string
		apiGroups     []string
		resources     []string
		verbs         []string
		resourceNames []string
		wantedVerbs   []string
		want          []string
	}{
		{
			name:      "no resourceNames covers every client-auth signer",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "exact signer name",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"approve"},
			resourceNames: []string{SignerAPIServerClient}, wantedVerbs: []string{"approve"},
			want: []string{SignerAPIServerClient},
		},
		{
			name:      "domain wildcard covers the whole kubernetes.io family",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"kubernetes.io/*"}, wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "*/* covers everything",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"*/*"}, wantedVerbs: []string{"sign"}, want: ClientAuthSigners,
		},
		{
			name:      "third-party signer covers none of the apiserver-trusted ones",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"example.com/my-signer"}, wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "third-party domain wildcard covers none either",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"sign"},
			resourceNames: []string{"example.com/*"}, wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "wrong verb grants nothing",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"get", "list"},
			wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "wrong API group grants nothing (a CRD named signers is not this one)",
			apiGroups: []string{"example.com"}, resources: []string{"signers"}, verbs: []string{"sign"},
			wantedVerbs: []string{"sign"}, want: nil,
		},
		{
			name:      "verb wildcard authorizes sign",
			apiGroups: []string{"certificates.k8s.io"}, resources: []string{"signers"}, verbs: []string{"*"},
			resourceNames: []string{SignerAPIServerClientKubelet}, wantedVerbs: []string{"sign"},
			want: []string{SignerAPIServerClientKubelet},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SignersCovered(tt.apiGroups, tt.resources, tt.verbs, tt.resourceNames, ClientAuthSigners, tt.wantedVerbs)
			if len(got) != len(tt.want) {
				t.Fatalf("SignersCovered() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("SignersCovered() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
