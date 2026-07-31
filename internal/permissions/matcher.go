// Package permissions - matcher.go: the shared RBAC capability matcher used by the
// rbac, serviceaccount, and privesc analyzers. It answers one question - "does this
// effective rule authorize <verb> on <(apiGroup, resource)>?" - with the three
// pieces of RBAC precision the analyzers used to skip:
//
//  1. apiGroup awareness. A PolicyRule authorizes a request only when it covers the
//     request's API group AND resource AND verb. Matching on the bare resource name
//     (ignoring the group) mis-fires on custom resources that reuse a core name -
//     e.g. a CRD `secrets.example.com` in group `example.com` is not the core
//     `secrets`. Grants requires both the group and the resource to line up.
//
//  2. resourceNames awareness. A rule with a non-empty ResourceNames applies only to
//     those named object instances. RBAC cannot scope a request that has no object
//     name at authorization time - `list`, `watch`, `deletecollection`, and `create`
//     on a top-level resource - so a name-scoped rule does NOT authorize those verbs
//     (Kubernetes documents "you cannot restrict create or deletecollection requests
//     by their resource name"). Verbs that act on a named object (`get`, `update`,
//     `patch`, `delete`, `bind`, `escalate`, `impersonate`, and `create` on a
//     subresource whose parent name rides in the URL, like `pods/exec`) still match,
//     scoped to the named objects.
//
//  3. wildcard handling on every axis: "*" in the rule's groups, resources, or verbs
//     matches anything on that axis.
package permissions

import "strings"

// ResourceTarget is one (apiGroup, resource) pair a capability check looks for.
// Group "" is the core API group; Resource may name a subresource such as "pods/exec".
type ResourceTarget struct {
	Group    string
	Resource string
}

// Core builds a ResourceTarget in the core ("") API group.
func Core(resource string) ResourceTarget {
	return ResourceTarget{Group: "", Resource: resource}
}

// InGroup builds a ResourceTarget in the named API group.
func InGroup(group, resource string) ResourceTarget {
	return ResourceTarget{Group: group, Resource: resource}
}

// NameScoped reports whether this rule is restricted to specific named objects via
// resourceNames. Callers use it to annotate findings (evidence, tags, attenuated
// blast radius) when a matched grant only reaches a fixed set of named objects.
func (r EffectiveRule) NameScoped() bool {
	return len(r.ResourceNames) > 0
}

// Grants reports whether this effective rule authorizes any of the wanted verbs on
// any of the given targets. It is the method form of the package-level Grants, so
// analyzers holding a permissions.EffectiveRule can write rule.Grants(targets, verbs...).
func (r EffectiveRule) Grants(targets []ResourceTarget, verbs ...string) bool {
	return Grants(r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, targets, verbs)
}

// Grants reports whether an RBAC rule described by (apiGroups, resources, verbs,
// resourceNames) authorizes any of wantedVerbs on any of targets. See the package
// doc for the apiGroup / resourceNames / wildcard semantics it enforces.
func Grants(apiGroups, resources, verbs, resourceNames []string, targets []ResourceTarget, wantedVerbs []string) bool {
	nameScoped := len(resourceNames) > 0
	for _, target := range targets {
		if !covers(apiGroups, target.Group) || !covers(resources, target.Resource) {
			continue
		}
		for _, verb := range wantedVerbs {
			if nameScoped && collectionVerb(verb, target.Resource) {
				// A name-scoped rule cannot authorize a request that carries no object
				// name at authorization time, so this verb drops out of the match.
				continue
			}
			if covers(verbs, verb) {
				return true
			}
		}
	}
	return false
}

// covers reports whether an RBAC axis (a rule's groups, resources, or verbs) includes
// want, treating "*" as a match-all wildcard. Core-group membership works naturally:
// the core group is the empty string, so covers([""], "") is true.
func covers(values []string, want string) bool {
	for _, v := range values {
		if v == "*" || v == want {
			return true
		}
	}
	return false
}

// Signer names the kube-apiserver trusts for client authentication. A certificate
// issued by any of these is accepted as a credential by the apiserver's x509
// authenticator, so control over the approval or signing path for one of them
// converts directly into a cluster identity of the holder's choosing.
//
// kubelet-serving and any third-party signer are deliberately absent: their certs
// are server certs (or chain to a CA the apiserver does not trust as a client CA),
// so authority over them is a different, weaker problem.
const (
	SignerAPIServerClient        = "kubernetes.io/kube-apiserver-client"
	SignerAPIServerClientKubelet = "kubernetes.io/kube-apiserver-client-kubelet"
	SignerLegacyUnknown          = "kubernetes.io/legacy-unknown"
)

// ClientAuthSigners is the set above in a fixed order, so callers that report which
// signers a grant covers produce deterministic output.
var ClientAuthSigners = []string{SignerAPIServerClient, SignerAPIServerClientKubelet, SignerLegacyUnknown}

// signerTargets is the (group, resource) pair the `sign` / `approve` verbs are
// checked against. The `signers` resource is virtual: it exists only as an
// authorization handle, which is why it never appears in a collector listing.
var signerTargets = []ResourceTarget{InGroup("certificates.k8s.io", "signers")}

// SignersCovered returns which of the wanted signer names an RBAC rule authorizes any
// of wantedVerbs on, via the `signers` resource in certificates.k8s.io. Empty means
// the rule grants nothing relevant.
//
// The `signers` resource inverts the usual meaning of resourceNames: the names are
// signer *names* (`kubernetes.io/kube-apiserver-client`), not object instances, and
// Kubernetes gives them their own wildcard grammar - an exact name, a domain-scoped
// `example.com/*`, or `*/*` for every signer. An empty resourceNames covers every
// signer. Grants is therefore called with a nil resourceNames (its object-name
// semantics do not apply here) and the name check happens in coversSignerName.
func SignersCovered(apiGroups, resources, verbs, resourceNames, signers, wantedVerbs []string) []string {
	if !Grants(apiGroups, resources, verbs, nil, signerTargets, wantedVerbs) {
		return nil
	}
	covered := make([]string, 0, len(signers))
	for _, signer := range signers {
		if coversSignerName(resourceNames, signer) {
			covered = append(covered, signer)
		}
	}
	if len(covered) == 0 {
		return nil
	}
	return covered
}

// SignersCovered is the method form for callers holding an EffectiveRule.
func (r EffectiveRule) SignersCovered(signers []string, verbs ...string) []string {
	return SignersCovered(r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, signers, verbs)
}

// coversSignerName reports whether a rule's resourceNames covers signer, honoring the
// signer-name grammar: no names at all (every signer), "*" / "*/*" (every signer), an
// exact match, or a domain wildcard such as "kubernetes.io/*".
func coversSignerName(resourceNames []string, signer string) bool {
	if len(resourceNames) == 0 {
		return true
	}
	for _, name := range resourceNames {
		if name == "*" || name == "*/*" || name == signer {
			return true
		}
		if strings.HasSuffix(name, "/*") && strings.HasPrefix(signer, strings.TrimSuffix(name, "*")) {
			return true
		}
	}
	return false
}

// collectionVerb reports whether verb operates on a collection (or creates a new
// object) with no object name available at authorization time, so a resourceNames
// restriction cannot authorize it. `create` is collection-like only for top-level
// resources: on a subresource (resource contains "/") the parent object's name rides
// in the request URL, so resourceNames scopes it and it is NOT collection-like.
func collectionVerb(verb, resource string) bool {
	switch verb {
	case "list", "watch", "deletecollection":
		return true
	case "create":
		return !strings.Contains(resource, "/")
	default:
		return false
	}
}
