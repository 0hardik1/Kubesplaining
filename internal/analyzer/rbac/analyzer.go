// Package rbac analyzes Role/ClusterRole bindings and flags subjects whose
// effective permissions enable privilege escalation or data exfiltration.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/remediation"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	rbacv1 "k8s.io/api/rbac/v1"
)

// API groups for the resources the privilege-escalation checks inspect. Matching on
// the group (not the bare resource name) is what keeps a custom resource that reuses
// a core name - e.g. a CRD `secrets.example.com` - from tripping the core-`secrets`
// checks.
const (
	groupRBAC  = "rbac.authorization.k8s.io"
	groupCerts = "certificates.k8s.io"
	groupApps  = "apps"
	groupBatch = "batch"
)

// Target sets for the dangerous-permission checks below, each pinned to its API
// group. Shared by the per-rule switch and the multi-rule correlations (CSR mint,
// secret-token mint, node migration).
var (
	targetSecrets     = []permissions.ResourceTarget{permissions.Core("secrets")}
	targetPods        = []permissions.ResourceTarget{permissions.Core("pods")}
	targetPodExec     = []permissions.ResourceTarget{permissions.Core("pods/exec"), permissions.Core("pods/attach")}
	targetEphemeral   = []permissions.ResourceTarget{permissions.Core("pods/ephemeralcontainers")}
	targetPortForward = []permissions.ResourceTarget{permissions.Core("pods/portforward")}
	targetSAToken     = []permissions.ResourceTarget{permissions.Core("serviceaccounts/token")}
	targetNodesProxy  = []permissions.ResourceTarget{permissions.Core("nodes/proxy")}
	targetNodesStatus = []permissions.ResourceTarget{permissions.Core("nodes/status")}
	targetNodes       = []permissions.ResourceTarget{permissions.Core("nodes")}
	targetImpersonate = []permissions.ResourceTarget{permissions.Core("users"), permissions.Core("groups"), permissions.Core("serviceaccounts")}
	targetWorkloads   = []permissions.ResourceTarget{permissions.InGroup(groupApps, "deployments"), permissions.InGroup(groupApps, "daemonsets"), permissions.InGroup(groupApps, "statefulsets"), permissions.InGroup(groupBatch, "jobs"), permissions.InGroup(groupBatch, "cronjobs")}
	targetRoles       = []permissions.ResourceTarget{permissions.InGroup(groupRBAC, "roles"), permissions.InGroup(groupRBAC, "clusterroles")}
	targetBindings    = []permissions.ResourceTarget{permissions.InGroup(groupRBAC, "rolebindings"), permissions.InGroup(groupRBAC, "clusterrolebindings")}
	targetCSR         = []permissions.ResourceTarget{permissions.InGroup(groupCerts, "certificatesigningrequests")}
	targetCSRApproval = []permissions.ResourceTarget{permissions.InGroup(groupCerts, "certificatesigningrequests/approval")}
	targetCSRStatus   = []permissions.ResourceTarget{permissions.InGroup(groupCerts, "certificatesigningrequests/status")}
)

// grants reports whether this rule authorizes any of verbs on any of targets,
// honoring the target API group and this rule's resourceNames (see permissions.Grants).
func (r effectiveRule) grants(targets []permissions.ResourceTarget, verbs ...string) bool {
	return permissions.Grants(r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, targets, verbs)
}

// Analyzer produces RBAC-focused findings from a snapshot.
type Analyzer struct{}

// effectiveRule is a flattened policy rule tagged with where it came from so findings can point back at it.
//
// SourceRole / SourceBinding hold the raw object names (used in Evidence JSON, where
// machine-readable identifiers are correct). The Kind/Namespace fields let prose
// renderers qualify those names with their resource Kind — e.g. "ClusterRoleBinding
// `crb-nodes-proxy`" instead of an opaque "`crb-nodes-proxy`" — which is what the
// Findings tab needs to be readable for someone who hasn't memorized the cluster.
type effectiveRule struct {
	Namespace              string
	APIGroups              []string
	Resources              []string
	Verbs                  []string
	ResourceNames          []string
	SourceRole             string
	SourceRoleKind         string
	SourceRoleNamespace    string
	SourceBinding          string
	SourceBindingKind      string
	SourceBindingNamespace string
}

// formattedBinding returns the binding rendered as "ClusterRoleBinding `name`" or
// "RoleBinding `ns/name`" for inclusion in finding prose. See formatBindingRef.
func (r effectiveRule) formattedBinding() string {
	return formatBindingRef(r.SourceBindingKind, r.SourceBindingNamespace, r.SourceBinding)
}

// formattedRole mirrors formattedBinding for the Role/ClusterRole side.
func (r effectiveRule) formattedRole() string {
	return formatRoleRef(r.SourceRoleKind, r.SourceRoleNamespace, r.SourceRole)
}

// effectivePermissions collects every effectiveRule that resolves to a given subject.
type effectivePermissions struct {
	Subject models.SubjectRef
	Rules   []effectiveRule
}

// New returns a new RBAC analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "rbac"
}

// Analyze walks role and cluster role bindings, resolves each subject's effective permissions,
// and emits findings for wildcard access, secret reads, impersonation, bind/escalate, and similar risks.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	roleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.Roles))
	for _, role := range snapshot.Resources.Roles {
		roleRules[fmt.Sprintf("%s/%s", role.Namespace, role.Name)] = role.Rules
	}

	clusterRoleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.ClusterRoles))
	for _, clusterRole := range snapshot.Resources.ClusterRoles {
		clusterRoleRules[clusterRole.Name] = clusterRole.Rules
	}

	subjects := map[string]*effectivePermissions{}

	for _, binding := range snapshot.Resources.RoleBindings {
		rules := referencedRules(binding.RoleRef, binding.Namespace, roleRules, clusterRoleRules)
		// A RoleBinding's RoleRef.Kind is "Role" (same namespace) or "ClusterRole" (cluster-scoped).
		// Roles are always co-located with their RoleBinding, so the role's namespace mirrors
		// binding.Namespace; ClusterRoles have no namespace.
		roleNamespace := ""
		if binding.RoleRef.Kind == "Role" {
			roleNamespace = binding.Namespace
		}
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, binding.Namespace)
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					Namespace:              binding.Namespace,
					APIGroups:              append([]string(nil), rule.APIGroups...),
					Resources:              append([]string(nil), rule.Resources...),
					Verbs:                  append([]string(nil), rule.Verbs...),
					ResourceNames:          append([]string(nil), rule.ResourceNames...),
					SourceRole:             binding.RoleRef.Name,
					SourceRoleKind:         binding.RoleRef.Kind,
					SourceRoleNamespace:    roleNamespace,
					SourceBinding:          binding.Name,
					SourceBindingKind:      "RoleBinding",
					SourceBindingNamespace: binding.Namespace,
				})
			}
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		rules := referencedRules(binding.RoleRef, "", roleRules, clusterRoleRules)
		// ClusterRoleBindings can only reference ClusterRoles; both are cluster-scoped.
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					APIGroups:         append([]string(nil), rule.APIGroups...),
					Resources:         append([]string(nil), rule.Resources...),
					Verbs:             append([]string(nil), rule.Verbs...),
					ResourceNames:     append([]string(nil), rule.ResourceNames...),
					SourceRole:        binding.RoleRef.Name,
					SourceRoleKind:    binding.RoleRef.Kind,
					SourceBinding:     binding.Name,
					SourceBindingKind: "ClusterRoleBinding",
				})
			}
		}
	}

	usedServiceAccounts := usedServiceAccounts(snapshot)
	privilegedNamespaces := namespacesAllowingPrivileged(snapshot)
	seen := map[string]struct{}{}
	findings := make([]models.Finding, 0)

	for _, perms := range subjects {
		for _, rule := range perms.Rules {
			// Score multipliers (applied to each rule's base score below):
			//   blastRadius     - cluster-scoped grants reach every namespace, so we bump them 20%
			//                     over namespace-scoped grants of the same permission.
			//   exploitability  - a ServiceAccount that is actually mounted by a pod can be reached
			//                     by an attacker who lands in that pod; an unused SA is a paper risk
			//                     until something starts mounting it, so the mounted ones get +20%.
			blastRadius := 1.0
			if rule.Namespace == "" {
				blastRadius = 1.2
			}
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}
			// A resourceNames-scoped grant reaches only a fixed set of named objects -
			// a much smaller blast radius than the whole resource type - so attenuate
			// it. The grant is still real (the checks below only match name-scopable
			// verbs on a name-scoped rule), just narrower, so it ranks below an
			// unrestricted grant of the same permission instead of disappearing.
			if len(rule.ResourceNames) > 0 {
				blastRadius *= 0.6
			}
			// scaledScore captures the per-rule multipliers above so each case below
			// only has to declare its base score - the formula is named once instead of
			// duplicated nine times.
			scaledScore := func(base float64) float64 {
				return scoring.Clamp(base * exploitability * blastRadius)
			}

			bindingRef := rule.formattedBinding()
			roleRef := rule.formattedRole()

			// Each case detects one privilege-escalation primitive and emits the matching
			// finding. switch (not if/else chain) so a rule that matches several cases
			// only fires the first - we prefer the most specific framing and let dedupe
			// merge cross-module overlaps later.
			//
			// `attachDangerousRemediation` (defined below) populates the structured
			// RemediationHint for the dangerous-verb findings. Wave 1 slot #17 added the
			// per-rule remediation generator; the analyzer is the one place that has the
			// snapshot in scope when these findings are constructed.
			switch {
			case hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) && hasWildcard(rule.APIGroups):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-017", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.8),
					contentPrivesc017(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetSecrets, "list", "watch"):
				// list/watch return every Secret's contents in one call (the
				// enumerate-everything case). get-only is the narrower -006 below.
				// A resourceNames-scoped rule never reaches this case: list/watch
				// cannot enumerate a name-restricted collection.
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-005", models.SeverityHigh, models.CategoryDataExfiltration,
					scaledScore(8.2),
					contentPrivesc005(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetSecrets, "get"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-006", models.SeverityHigh, models.CategoryDataExfiltration,
					scaledScore(7.6),
					contentPrivesc006(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetPods, "create"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-001", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.4),
					contentPrivesc001(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetPodExec, "create", "get"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-004", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.0),
					contentPrivesc004(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetEphemeral, "update", "patch"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-013", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.0),
					contentPrivesc013(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetPortForward, "create"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-015", models.SeverityMedium, models.CategoryLateralMovement,
					scaledScore(6.0),
					contentPrivesc015(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetWorkloads, "create", "update", "patch"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-003", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.1),
					contentPrivesc003(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetImpersonate, "impersonate"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-008", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.4),
					contentPrivesc008(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetRoles, "bind", "escalate"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-009", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.2),
					contentPrivesc009(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetBindings, "create", "update", "patch"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-010", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.0),
					contentPrivesc010(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetNodesProxy, "get"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-012", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.3),
					contentPrivesc012(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			case rule.grants(targetSAToken, "create"):
				findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-014", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.0),
					contentPrivesc014(rule.Namespace, perms.Subject, bindingRef, roleRef)), snapshot))
			}

			// KUBE-PRIVESC-002 — pod create + permissive Pod Security Admission.
			// Emitted IN ADDITION to the switch's -001 (token theft): when the
			// target namespace does not enforce a PSA level that blocks privileged
			// pods, the same pod-create grant also yields a host escape. Full
			// wildcards are already -017, so skip them here to avoid noise.
			isPodCreate := rule.grants(targetPods, "create")
			isFullWildcard := hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) && hasWildcard(rule.APIGroups)
			if isPodCreate && !isFullWildcard {
				if target, ok := podCreatePrivilegedTarget(rule.Namespace, privilegedNamespaces); ok {
					findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, rule,
						"KUBE-PRIVESC-002", models.SeverityHigh, models.CategoryPrivilegeEscalation,
						scaledScore(8.6),
						contentPrivesc002(rule.Namespace, perms.Subject, bindingRef, roleRef, target)), snapshot))
				}
			}
		}

		// KUBE-PRIVESC-011 / -024 — the two certificates-API mint primitives. Both
		// correlate separate rules on the same subject, so they run as a per-subject
		// pass after the per-rule switch above: the halves can arrive from different
		// bindings, and only the union over the subject's whole effective-rule set
		// can see that. Every half is cluster-scoped — CSRs and `signers` are
		// cluster-scoped resources, so a namespaced grant of any of them is dead RBAC.
		//
		//   -011 (approval path): `create certificatesigningrequests` +
		//        `update/patch certificatesigningrequests/approval`, optionally plus
		//        `approve` on the signer, which the CertificateApproval admission
		//        plugin has required since 1.19. Holding the signer half too makes
		//        the path fully enforced-authorized rather than plugin-dependent.
		//   -024 (signing path): `sign` on the signer + `update/patch
		//        certificatesigningrequests/status`. This skips approval entirely:
		//        the holder IS the signer and writes the issued cert itself.
		var createRule, approveRule, signerApproveRule, signRule, statusRule *effectiveRule
		var approveSigners, signSigners []string
		for i := range perms.Rules {
			r := &perms.Rules[i]
			if r.Namespace != "" {
				continue // CSRs and signers are cluster-scoped; namespaced grants are dead RBAC
			}
			if matchesCSRCreate(*r) && createRule == nil {
				createRule = r
			}
			if matchesCSRApprove(*r) && approveRule == nil {
				approveRule = r
			}
			if signerApproveRule == nil {
				if covered := r.signersApproved(); len(covered) > 0 {
					signerApproveRule, approveSigners = r, covered
				}
			}
			if signRule == nil {
				if covered := r.signersSigned(); len(covered) > 0 {
					signRule, signSigners = r, covered
				}
			}
			if matchesCSRStatusWrite(*r) && statusRule == nil {
				statusRule = r
			}
		}

		// Named for the certificates rules specifically: the -007 / -016 correlations
		// below compute their own multipliers, and a shared `blastRadius` here would
		// only be shadowed there.
		const csrBlastRadius = 1.2 // CSRs and signers are cluster-scoped, always blast-radius=1.2
		csrExploitability := 1.0
		if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
			csrExploitability = 1.2
		}
		csrScore := func(base float64) float64 {
			return scoring.Clamp(base * csrExploitability * csrBlastRadius)
		}

		if createRule != nil && approveRule != nil {
			grants := csrMintGrants{
				CreateBinding:  createRule.formattedBinding(),
				CreateRole:     createRule.formattedRole(),
				ApproveBinding: approveRule.formattedBinding(),
				ApproveRole:    approveRule.formattedRole(),
				SignerApprove:  approveSigners,
			}
			// Severity splits on the signer half. Without it, the CertificateApproval
			// admission plugin rejects the approval on a default 1.19+ cluster, so the
			// grant is a latent misconfiguration; with it, every gate the apiserver
			// enforces is already satisfied and nothing stands between the subject and
			// a client cert for the identity of its choice.
			severity, base := models.SeverityHigh, 7.0
			if len(approveSigners) > 0 {
				severity, base = models.SeverityCritical, 8.5
				grants.SignerBinding = signerApproveRule.formattedBinding()
				grants.SignerRole = signerApproveRule.formattedRole()
			}
			findings = appendFinding(findings, seen, findingFromContent(perms.Subject, *createRule,
				"KUBE-PRIVESC-011", severity, models.CategoryPrivilegeEscalation,
				csrScore(base), // base × 1.2 blast (clamped if the SA is mounted)
				contentPrivesc011(perms.Subject, grants)))
		}

		// KUBE-PRIVESC-024 — signer control. `sign` on an apiserver-trusted client
		// signer plus the `certificatesigningrequests/status` write is the exact pair
		// the apiserver enforces for *being* the signer: the CertificateSigning
		// admission plugin checks `sign` when a status write populates
		// `status.certificate`. The holder issues certs without any approval step.
		if signRule != nil && statusRule != nil {
			// Only the kube-apiserver-client signer accepts an arbitrary Subject DN, so
			// only it converts into an identity of the holder's choosing (up to
			// cluster-admin). The kubelet signers issue node identities, which is a
			// serious but bounded gain, and legacy-unknown is unsigned by modern
			// controller-managers.
			severity := models.SeverityHigh
			if slices.Contains(signSigners, permissions.SignerAPIServerClient) {
				severity = models.SeverityCritical
			}
			findings = appendFinding(findings, seen, findingFromContent(perms.Subject, *signRule,
				"KUBE-PRIVESC-024", severity, models.CategoryPrivilegeEscalation,
				csrScore(8.0),
				contentPrivesc024(perms.Subject, csrSignGrants{
					Signers:       signSigners,
					SignBinding:   signRule.formattedBinding(),
					SignRole:      signRule.formattedRole(),
					StatusBinding: statusRule.formattedBinding(),
					StatusRole:    statusRule.formattedRole(),
				})))
		}

		// KUBE-PRIVESC-007 — secret-creation token theft. `create` + `get` on
		// secrets in composing scopes lets the subject mint a legacy
		// ServiceAccount-token Secret and read the controller-populated token,
		// bypassing the serviceaccounts/token gate. Correlated per subject.
		var secretCreateRule, secretGetRule *effectiveRule
		for i := range perms.Rules {
			r := &perms.Rules[i]
			if matchesSecretCreate(*r) && secretCreateRule == nil {
				secretCreateRule = r
			}
			if matchesSecretGet(*r) && secretGetRule == nil {
				secretGetRule = r
			}
		}
		if secretCreateRule != nil && secretGetRule != nil && scopesCompose(secretCreateRule.Namespace, secretGetRule.Namespace) {
			blastRadius := 1.0
			if secretCreateRule.Namespace == "" || secretGetRule.Namespace == "" {
				blastRadius = 1.2
			}
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}
			findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, *secretCreateRule,
				"KUBE-PRIVESC-007", models.SeverityHigh, models.CategoryPrivilegeEscalation,
				scoring.Clamp(8.0*exploitability*blastRadius),
				contentPrivesc007(secretCreateRule.Namespace, perms.Subject, secretCreateRule.formattedBinding(), secretCreateRule.formattedRole(), secretGetRule.formattedBinding(), secretGetRule.formattedRole())), snapshot))
		}

		// KUBE-PRIVESC-016 — node-status / delete-pod migration. `delete pods`
		// plus cluster-scoped node manipulation (cordon via nodes/status, or
		// delete nodes) can relocate sensitive pods onto an attacker node.
		var deletePodsRule, nodeManipRule *effectiveRule
		nodeAction := ""
		for i := range perms.Rules {
			r := &perms.Rules[i]
			if matchesPodDelete(*r) && deletePodsRule == nil {
				deletePodsRule = r
			}
			if nodeManipRule == nil && r.Namespace == "" {
				if matchesNodeStatusWrite(*r) {
					nodeManipRule = r
					nodeAction = "update nodes/status"
				} else if matchesNodeDelete(*r) {
					nodeManipRule = r
					nodeAction = "delete nodes"
				}
			}
		}
		if deletePodsRule != nil && nodeManipRule != nil {
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}
			findings = appendFinding(findings, seen, attachDangerousRemediation(findingFromContent(perms.Subject, *nodeManipRule,
				"KUBE-PRIVESC-016", models.SeverityHigh, models.CategoryPrivilegeEscalation,
				scoring.Clamp(7.5*exploitability*1.2), // node manipulation is cluster-scoped
				contentPrivesc016(perms.Subject, deletePodsRule.formattedBinding(), deletePodsRule.formattedRole(), nodeManipRule.formattedBinding(), nodeManipRule.formattedRole(), nodeAction)), snapshot))
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" {
			for _, subject := range binding.Subjects {
				ref := subjectRef(subject, "")
				if strings.HasPrefix(ref.Name, "system:") {
					continue
				}
				overbroadFinding := findingFromContent(
					ref,
					effectiveRule{
						SourceBinding:     binding.Name,
						SourceBindingKind: "ClusterRoleBinding",
						SourceRole:        binding.RoleRef.Name,
						SourceRoleKind:    binding.RoleRef.Kind,
					},
					"KUBE-RBAC-OVERBROAD-001", models.SeverityCritical, models.CategoryPrivilegeEscalation, 10,
					contentRBACOverbroad001(ref, binding.Name))
				overbroadFinding.RemediationHint = remediation.ForRBACOverbroad(overbroadFinding, snapshot)
				findings = appendFinding(findings, seen, overbroadFinding)
			}
		}
	}

	// Third pass — stale / dangling bindings.
	//
	// A (Cluster)RoleBinding whose roleRef points at a Role/ClusterRole that no
	// longer exists in the snapshot grants no permissions today, but reactivates
	// with whatever permissions the role contains the moment anyone re-creates
	// the role with the same name — without the binding being re-reviewed. That's
	// the KUBE-RBAC-STALE-001 case.
	//
	// Likewise, a binding whose subjects include a ServiceAccount that does not
	// exist in the snapshot becomes a live grant the moment a SA with that
	// namespace+name is (re-)created (an attacker with `create serviceaccounts`,
	// or a routine redeploy). That's KUBE-RBAC-STALE-002. User and Group subjects
	// cannot be validated this way: Kubernetes maintains no inventory of
	// Users/Groups (they are authenticated externally and asserted per request),
	// so the snapshot cannot tell us whether they "exist".
	serviceAccountSet := make(map[string]struct{}, len(snapshot.Resources.ServiceAccounts))
	for _, sa := range snapshot.Resources.ServiceAccounts {
		serviceAccountSet[fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)] = struct{}{}
	}
	for _, binding := range snapshot.Resources.RoleBindings {
		findings = analyzeStaleBinding(findings, seen, binding.Name, "RoleBinding", binding.Namespace, binding.RoleRef, binding.Subjects, roleRules, clusterRoleRules, serviceAccountSet)
	}
	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		findings = analyzeStaleBinding(findings, seen, binding.Name, "ClusterRoleBinding", "", binding.RoleRef, binding.Subjects, roleRules, clusterRoleRules, serviceAccountSet)
	}

	return findings, nil
}

// analyzeStaleBinding emits KUBE-RBAC-STALE-001 / -002 findings for a single
// (Cluster)RoleBinding. See the third-pass comment in Analyze for the rule
// semantics. When the roleRef is missing we emit -001 for every subject and
// skip the -002 check for that subject — a missing role already captures the
// drift, so adding -002 for any missing SA subjects on the same binding would
// just inflate the finding count.
func analyzeStaleBinding(
	findings []models.Finding,
	seen map[string]struct{},
	bindingName, bindingKind, bindingNamespace string,
	roleRef rbacv1.RoleRef,
	subjects []rbacv1.Subject,
	roleRules, clusterRoleRules map[string][]rbacv1.PolicyRule,
	serviceAccountSet map[string]struct{},
) []models.Finding {
	refs := make([]models.SubjectRef, 0, len(subjects))
	for _, s := range subjects {
		refs = append(refs, subjectRef(s, bindingNamespace))
	}
	bindingRefStr := formatBindingRef(bindingKind, bindingNamespace, bindingName)
	roleNamespace := roleRefNamespaceFor(roleRef, bindingNamespace)
	roleRefStr := formatRoleRef(roleRef.Kind, roleNamespace, roleRef.Name)
	roleExists := isBuiltinClusterRole(roleRef) || lookupRoleExists(roleRef, bindingNamespace, roleRules, clusterRoleRules)

	for i, subject := range subjects {
		ref := refs[i]
		if !roleExists {
			others := append([]models.SubjectRef{}, refs[:i]...)
			others = append(others, refs[i+1:]...)
			ctx := staleContext{
				BindingRef:       bindingRefStr,
				BindingNamespace: bindingNamespace,
				RoleRef:          roleRefStr,
				RoleName:         roleRef.Name,
				RoleKind:         roleRef.Kind,
				Subject:          ref,
				OtherSubjects:    others,
			}
			evidence, _ := json.Marshal(map[string]any{
				"source_binding":      bindingName,
				"source_binding_kind": bindingKind,
				"binding_namespace":   bindingNamespace,
				"missing_role":        roleRef.Name,
				"missing_role_kind":   roleRef.Kind,
				"other_subjects":      others,
			})
			findings = appendFinding(findings, seen, staleFinding(
				"KUBE-RBAC-STALE-001",
				models.SeverityMedium,
				5.0,
				ref,
				&models.ResourceRef{Kind: roleRef.Kind, Name: roleRef.Name, Namespace: roleNamespace, APIGroup: "rbac.authorization.k8s.io"},
				bindingNamespace, bindingName, bindingKind,
				evidence,
				contentRBACStale001(ctx),
				"stale:roleref",
			))
			continue
		}
		// -002 only applies to ServiceAccount subjects. User/Group existence
		// cannot be verified from the snapshot — see third-pass docstring above.
		if subject.Kind != "ServiceAccount" {
			continue
		}
		if _, ok := serviceAccountSet[fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)]; ok {
			continue
		}
		ctx := staleContext{
			BindingRef:       bindingRefStr,
			BindingNamespace: bindingNamespace,
			RoleRef:          roleRefStr,
			RoleName:         roleRef.Name,
			RoleKind:         roleRef.Kind,
			Subject:          ref,
		}
		evidence, _ := json.Marshal(map[string]any{
			"source_binding":      bindingName,
			"source_binding_kind": bindingKind,
			"binding_namespace":   bindingNamespace,
			"source_role":         roleRef.Name,
			"source_role_kind":    roleRef.Kind,
		})
		findings = appendFinding(findings, seen, staleFinding(
			"KUBE-RBAC-STALE-002",
			models.SeverityLow,
			3.5,
			ref,
			&models.ResourceRef{Kind: roleRef.Kind, Name: roleRef.Name, Namespace: roleNamespace, APIGroup: "rbac.authorization.k8s.io"},
			bindingNamespace, bindingName, bindingKind,
			evidence,
			contentRBACStale002(ctx),
			"stale:subject",
		))
	}
	return findings
}

// isBuiltinClusterRole reports whether roleRef names one of the four user-facing
// ClusterRoles every Kubernetes distribution ships: `cluster-admin`, `admin`,
// `edit`, `view`. A snapshot that omits these (scan-resource of a single
// manifest, or a collection that hit RBAC-list permission errors) is still
// describing a real cluster where these roles exist — so we must not flag
// bindings to them as stale just because they're missing from the snapshot.
//
// We deliberately do NOT add `system:*` here: the standard exclusions preset
// drops findings whose subjects are `system:*` Users/Groups/SAs, so orphan
// findings involving a `system:*` subject disappear at the exclusions stage
// anyway. Conversely, a non-`system:*` subject bound to a missing `system:*`
// role is still a legitimate cleanup signal worth keeping.
func isBuiltinClusterRole(roleRef rbacv1.RoleRef) bool {
	if roleRef.Kind != "ClusterRole" {
		return false
	}
	switch roleRef.Name {
	case "cluster-admin", "admin", "edit", "view":
		return true
	}
	return false
}

// lookupRoleExists reports whether roleRef resolves to a known Role/ClusterRole
// in the supplied lookup maps. Unknown roleRef.Kind values are treated as
// existing (conservative — we don't flag what we can't categorize).
func lookupRoleExists(roleRef rbacv1.RoleRef, bindingNamespace string, roleRules, clusterRoleRules map[string][]rbacv1.PolicyRule) bool {
	switch roleRef.Kind {
	case "Role":
		_, ok := roleRules[fmt.Sprintf("%s/%s", bindingNamespace, roleRef.Name)]
		return ok
	case "ClusterRole":
		_, ok := clusterRoleRules[roleRef.Name]
		return ok
	}
	return true
}

// roleRefNamespaceFor returns the namespace component of a RoleRef for prose
// rendering. RoleBinding → Role inherits the binding's namespace; everything
// else (RoleBinding → ClusterRole, ClusterRoleBinding → ClusterRole) is
// cluster-scoped.
func roleRefNamespaceFor(roleRef rbacv1.RoleRef, bindingNamespace string) string {
	if roleRef.Kind == "Role" {
		return bindingNamespace
	}
	return ""
}

// staleFinding assembles a KUBE-RBAC-STALE-* Finding. It mirrors
// findingFromContent but specialises Evidence and Resource to the stale-binding
// shape (Resource = the role itself, not "RBACRule"; no per-rule verb/resource
// fields). The Finding.ID encodes the binding, so two stale findings on the
// same subject from two different bindings dedupe independently.
func staleFinding(
	ruleID string,
	severity models.Severity,
	score float64,
	subject models.SubjectRef,
	resource *models.ResourceRef,
	bindingNamespace, bindingName, bindingKind string,
	evidence json.RawMessage,
	content ruleContent,
	extraTag string,
) models.Finding {
	id := fmt.Sprintf("%s:%s:%s/%s/%s", ruleID, subject.Key(), bindingKind, bindingNamespace, bindingName)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	tags := []string{"module:rbac"}
	if extraTag != "" {
		tags = append(tags, extraTag)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         models.CategoryPrivilegeEscalation,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Resource:         resource,
		Namespace:        bindingNamespace,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidence,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             tags,
	}
}

// appendFinding adds finding to the slice unless its ID has already been seen (deduplication keyed by Finding.ID).
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// attachDangerousRemediation populates the structured RemediationHint for the
// dangerous-verb (KUBE-PRIVESC-001 … -017) findings. Wired at each switch
// branch above as a one-line wrapper around findingFromContent so the per-rule
// remediation generator runs with the finding's evidence already populated.
//
// The remediation package guards on the rule ID and returns nil for anything
// it doesn't know about, so the wrapper is safe to apply uniformly.
func attachDangerousRemediation(f models.Finding, snap models.Snapshot) models.Finding {
	f.RemediationHint = remediation.ForRBACDangerous(f.RuleID, f, snap)
	return f
}

// findingFromContent materializes a models.Finding using the enriched ruleContent (Scope, Impact,
// AttackScenario, RemediationSteps, LearnMore, MitreTechniques) plus the runtime context (subject,
// originating rule, severity/score/category bucket). Evidence keeps the same shape as before so
// existing consumers continue to work.
func findingFromContent(subject models.SubjectRef, rule effectiveRule, ruleID string, severity models.Severity, category models.RiskCategory, score float64, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(map[string]any{
		"source_role":         rule.SourceRole,
		"source_role_kind":    rule.SourceRoleKind,
		"source_binding":      rule.SourceBinding,
		"source_binding_kind": rule.SourceBindingKind,
		"api_groups":          rule.APIGroups,
		"resources":           rule.Resources,
		"resource_names":      rule.ResourceNames,
		"verbs":               rule.Verbs,
		"namespace":           rule.Namespace,
		"scope":               string(content.Scope.Level),
	})

	tags := []string{"module:rbac"}
	if len(rule.ResourceNames) > 0 {
		// Surface that this grant reaches only specific named objects, so report
		// consumers can see the scope that attenuated the score.
		tags = append(tags, "scope:resource-names")
	}

	resource := &models.ResourceRef{
		Kind:      "RBACRule",
		Name:      rule.SourceRole,
		Namespace: rule.Namespace,
		APIGroup:  "rbac.authorization.k8s.io",
	}

	id := fmt.Sprintf("%s:%s:%s:%s", ruleID, subject.Key(), rule.Namespace, strings.Join(rule.Resources, ","))
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Resource:         resource,
		Namespace:        rule.Namespace,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             tags,
	}
}

// referencedRules returns the PolicyRules that roleRef points at, handling both Role and ClusterRole references.
func referencedRules(
	roleRef rbacv1.RoleRef,
	namespace string,
	roleRules map[string][]rbacv1.PolicyRule,
	clusterRoleRules map[string][]rbacv1.PolicyRule,
) []rbacv1.PolicyRule {
	if roleRef.Kind == "Role" {
		return roleRules[fmt.Sprintf("%s/%s", namespace, roleRef.Name)]
	}
	return clusterRoleRules[roleRef.Name]
}

// getSubject fetches or creates the effectivePermissions entry for ref.
func getSubject(subjects map[string]*effectivePermissions, ref models.SubjectRef) *effectivePermissions {
	key := ref.Key()
	if subjects[key] == nil {
		subjects[key] = &effectivePermissions{Subject: ref}
	}
	return subjects[key]
}

// subjectRef normalizes a binding subject into models.SubjectRef, defaulting ServiceAccount namespace when unset.
func subjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
	ref := models.SubjectRef{
		Kind: subject.Kind,
		Name: subject.Name,
	}
	if subject.Kind == "ServiceAccount" {
		ref.Namespace = subject.Namespace
		if ref.Namespace == "" {
			ref.Namespace = fallbackNamespace
		}
	}
	return ref
}

// hasWildcard reports whether values contains the "*" match-all token. Retained for
// the triple-wildcard cluster-admin check (KUBE-PRIVESC-017); the resource/verb
// primitive matching now goes through effectiveRule.grants / permissions.Grants.
func hasWildcard(values []string) bool {
	return slices.Contains(values, "*")
}

// matchesCSRCreate reports whether rule grants `create` on the cluster-scoped
// `certificatesigningrequests` resource. Cluster scope is the caller's
// responsibility (rule.Namespace == "").
func matchesCSRCreate(rule effectiveRule) bool {
	return rule.grants(targetCSR, "create")
}

// matchesCSRApprove reports whether rule grants `update` or `patch` on the
// `certificatesigningrequests/approval` subresource. The /approval subresource
// is the RBAC gate on CSR approval — the parent CSR object's `update` verb
// does not allow approval — so this check is narrow on resource and broad on
// the two verbs `kubectl certificate approve` could use.
//
// It is one of two gates, not the only one: since 1.19 the CertificateApproval
// admission plugin additionally requires the approving identity to hold `approve`
// on the CSR's signer (see signersApproved). Detection keeps firing on this half
// alone because the plugin is disableable and the /approval verb is the grant an
// operator actually audits, but the finding says which of the two the subject holds.
func matchesCSRApprove(rule effectiveRule) bool {
	return rule.grants(targetCSRApproval, "update", "patch")
}

// matchesCSRStatusWrite reports whether rule grants `update` or `patch` on the
// `certificatesigningrequests/status` subresource — the write that carries the
// issued certificate. It is the second half of the signing pair (see
// signersSigned): the CertificateSigning admission plugin authorizes the `sign`
// verb on the signer when this write populates `status.certificate`.
func matchesCSRStatusWrite(rule effectiveRule) bool {
	return rule.grants(targetCSRStatus, "update", "patch")
}

// signersApproved / signersSigned report which apiserver-trusted client signers
// this rule grants `approve` / `sign` on, via the virtual `signers` resource.
// Empty means none. See permissions.SignersCovered for the signer-name grammar
// (exact name, `kubernetes.io/*` domain wildcard, `*/*`, or no names at all).
func (r effectiveRule) signersApproved() []string {
	return permissions.SignersCovered(r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, permissions.ClientAuthSigners, []string{"approve"})
}

func (r effectiveRule) signersSigned() []string {
	return permissions.SignersCovered(r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, permissions.ClientAuthSigners, []string{"sign"})
}

// matchesSecretCreate / matchesSecretGet are the two halves of the
// KUBE-PRIVESC-007 secret-creation token-theft primitive.
func matchesSecretCreate(rule effectiveRule) bool {
	return rule.grants(targetSecrets, "create")
}

func matchesSecretGet(rule effectiveRule) bool {
	return rule.grants(targetSecrets, "get")
}

// matchesPodDelete, matchesNodeStatusWrite, and matchesNodeDelete are the
// halves of the KUBE-PRIVESC-016 node-migration primitive. The node halves are
// cluster-scoped resources, so the caller also requires rule.Namespace == "".
func matchesPodDelete(rule effectiveRule) bool {
	return rule.grants(targetPods, "delete")
}

func matchesNodeStatusWrite(rule effectiveRule) bool {
	return rule.grants(targetNodesStatus, "update", "patch")
}

func matchesNodeDelete(rule effectiveRule) bool {
	return rule.grants(targetNodes, "delete")
}

// scopesCompose reports whether a create-secrets grant in createNs and a
// get-secrets grant in getNs overlap so the KUBE-PRIVESC-007 primitive is
// realisable: either grant being cluster-scoped ("") covers all namespaces, and
// two namespaced grants compose only when they name the same namespace.
func scopesCompose(createNs, getNs string) bool {
	return createNs == "" || getNs == "" || createNs == getNs
}

// psaEnforceLabel is the namespace label Pod Security Admission reads to choose
// the standard it enforces. Absent, or "privileged", means privileged pods are
// admissible.
const psaEnforceLabel = "pod-security.kubernetes.io/enforce"

// namespacesAllowingPrivileged returns the set of non-system namespaces whose
// Pod Security Admission posture does NOT block privileged pods (no enforce
// label, or enforce=privileged). baseline/restricted block privileged and are
// excluded. The three built-in system namespaces are excluded because they
// legitimately run privileged control-plane pods, which would make the
// cluster-scoped KUBE-PRIVESC-002 signal fire unconditionally.
func namespacesAllowingPrivileged(snapshot models.Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, ns := range snapshot.Resources.Namespaces {
		switch ns.Name {
		case "kube-system", "kube-public", "kube-node-lease":
			continue
		}
		switch ns.Labels[psaEnforceLabel] {
		case "", "privileged":
			out[ns.Name] = true
		}
	}
	return out
}

// podCreatePrivilegedTarget reports whether a pod-create grant in ruleNamespace
// can land a privileged pod, and a human description of where. A cluster-scoped
// grant ("") can target any privileged-allowing namespace; a namespaced grant
// only its own.
func podCreatePrivilegedTarget(ruleNamespace string, privilegedNamespaces map[string]bool) (string, bool) {
	if ruleNamespace == "" {
		if len(privilegedNamespaces) > 0 {
			return "any namespace without a restrictive Pod Security Admission `enforce` label", true
		}
		return "", false
	}
	if privilegedNamespaces[ruleNamespace] {
		return fmt.Sprintf("namespace `%s`", ruleNamespace), true
	}
	return "", false
}

// usedServiceAccounts returns the set of ServiceAccounts actually mounted by pods, used to bump exploitability scoring.
func usedServiceAccounts(snapshot models.Snapshot) map[string]bool {
	result := make(map[string]bool)
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		result[models.SubjectRef{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: pod.Namespace,
		}.Key()] = true
	}
	return result
}
