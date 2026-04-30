// Content for privilege-escalation path findings. Each builder takes runtime context
// (source subject, hop chain, target sink) and returns ruleContent with explicit scope,
// step-by-step attacker walkthrough that mirrors the chain, ordered remediation that
// names the *weakest* hop to remove, and authoritative references.
//
// Sources: HackTricks Cloud — Abusing Roles/ClusterRoles in K8s, Aqua Security
// "Kubernetes Privilege Escalation: Excessive Permissions in Popular Helm Charts" (2024),
// MITRE ATT&CK Containers, Microsoft Threat Matrix for Kubernetes, Bishop Fox Power Outages
// research, Christophe Tafani-Dereeper EKS-IMDS-pivot, NSA/CISA Hardening Guide v1.2.
package privesc

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

type ruleContent struct {
	Title            string
	Scope            models.Scope
	Description      string
	Impact           string
	AttackScenario   []string
	Remediation      string
	RemediationSteps []string
	LearnMore        []models.Reference
	MitreTechniques  []models.MitreTechnique
}

var (
	mitreT1078_004 = models.MitreTechnique{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"}
	mitreT1098     = models.MitreTechnique{ID: "T1098", Name: "Account Manipulation", URL: "https://attack.mitre.org/techniques/T1098/"}
	mitreT1611     = models.MitreTechnique{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"}
	mitreT1552_007 = models.MitreTechnique{ID: "T1552.007", Name: "Container API", URL: "https://attack.mitre.org/techniques/T1552/007/"}
	mitreT1068     = models.MitreTechnique{ID: "T1068", Name: "Exploitation for Privilege Escalation", URL: "https://attack.mitre.org/techniques/T1068/"}
	mitreT1556     = models.MitreTechnique{ID: "T1556", Name: "Modify Authentication Process", URL: "https://attack.mitre.org/techniques/T1556/"}
)

var (
	refHackTricksRBAC = models.Reference{Title: "HackTricks Cloud — Abusing RBAC in Kubernetes", URL: "https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html"}
	refRBACGoodPrac   = models.Reference{Title: "Kubernetes — RBAC good practices", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"}
	refMSThreatMatrix = models.Reference{Title: "Microsoft — Threat Matrix for Kubernetes", URL: "https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/"}
	refNSAHardening   = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
)

// scopeForPath returns scope based on the target sink. Cluster-admin and system:masters are
// always cluster scope; node-escape is cluster scope (host root → all nodes); kube-system
// secrets is namespace scope. The Detail names the source subject so the reader sees who
// can reach the sink.
func scopeForPath(source models.SubjectRef, target models.EscalationTarget) models.Scope {
	switch target {
	case models.TargetClusterAdmin, models.TargetSystemMasters, models.TargetNodeEscape:
		return models.Scope{
			Level:  models.ScopeCluster,
			Detail: fmt.Sprintf("Source `%s` → `%s` — terminal sink is cluster-scoped (full API control or host root)", source.Key(), targetLabel(target)),
		}
	case models.TargetKubeSystemSecrets:
		return models.Scope{
			Level:  models.ScopeNamespace,
			Detail: fmt.Sprintf("Source `%s` → kube-system Secrets — control-plane namespace; reads here typically yield credentials usable cluster-wide", source.Key()),
		}
	default:
		return models.Scope{
			Level:  models.ScopeCluster,
			Detail: fmt.Sprintf("Source `%s` → `%s`", source.Key(), targetLabel(target)),
		}
	}
}

// hopNarrative renders one hop into a natural-prose sentence describing what the
// attacker does at that step. The output goes into Finding.AttackScenario, which
// the report template wraps in an <ol> — so we deliberately omit any "Step N:"
// prefix (the list renders the number) and write each hop as a self-contained
// sentence using the technique's human-readable title rather than its slug.
//
// The technique titles here intentionally mirror internal/report/glossary.go's
// Techniques map. We don't import that map directly because the privesc analyzer
// must not depend on the report package; if a slug is added there it should be
// reflected here too. Fallback prose is generic but still readable.
func hopNarrative(hop models.EscalationHop) string {
	from := backtickSubject(hop.FromSubject)
	to := backtickSubject(hop.ToSubject)
	hasTo := to != ""
	perm := ""
	if hop.Permission != "" {
		perm = fmt.Sprintf("`%s`", hop.Permission)
	}
	gains := strings.TrimSpace(hop.Gains)

	switch hop.Action {
	case "bound_to_cluster_admin":
		return fmt.Sprintf("%s is bound directly to the `cluster-admin` ClusterRole — no chain step is needed beyond compromising the subject itself.", from)

	case "wildcard_permission":
		return fmt.Sprintf("The identity %s already holds wildcard verbs on wildcard resources (%s), which is functionally identical to `cluster-admin`. The attacker can take any action on any resource in the cluster without further escalation.", from, perm)

	case "modify_role_binding":
		return fmt.Sprintf("Acting as %s, the attacker abuses RoleBinding write access (%s) to add themselves (or any subject they control) to a high-privilege ClusterRoleBinding — typically `cluster-admin`. They don't need the target role's permissions today, only the ability to change bindings.", from, perm)

	case "bind_or_escalate":
		if hasTo {
			return fmt.Sprintf("Acting as %s, the attacker uses the RBAC `bind/escalate` bypass (%s) to grant themselves a role they do not currently hold and bind to %s. `bind/escalate` is the carve-out that lets the holder escape RBAC's normal \"you can only grant what you have\" guardrail.", from, perm, to)
		}
		return fmt.Sprintf("Acting as %s, the attacker uses the RBAC `bind/escalate` bypass (%s) to grant themselves any role they choose — typically `cluster-admin`. `bind/escalate` is the carve-out that lets the holder escape RBAC's normal \"you can only grant what you have\" guardrail.", from, perm)

	case "impersonate":
		if hasTo {
			return fmt.Sprintf("Acting as %s, the attacker uses RBAC impersonation (the `impersonate` verb on %s) to send API requests as %s — the kube-apiserver honours the `Impersonate-User/Impersonate-Group` headers and authorizes the request against the impersonated identity's permissions instead of the attacker's.", from, perm, to)
		}
		return fmt.Sprintf("Acting as %s, the attacker uses RBAC impersonation (the `impersonate` verb on %s) to send API requests as any identity in the cluster — including `system:masters`, which the apiserver hard-codes as cluster-admin. Granting `impersonate` on `groups: [\"*\"]` is functionally a cluster-admin grant.", from, perm)

	case "impersonate_system_masters":
		return fmt.Sprintf("Acting as %s, the attacker impersonates the `system:masters` group (%s). The kube-apiserver hard-codes that group as authorized for every operation regardless of RBAC — a single such grant collapses the entire authorization layer.", from, perm)

	case "read_secrets":
		return fmt.Sprintf("Acting as %s, the attacker reads ServiceAccount tokens out of the cluster's Secrets store (%s) and uses one of those tokens — typically a control-plane controller's — to escalate. Read-access on Secrets is the most consequential single verb in Kubernetes RBAC because every other identity's credential lives in a Secret object somewhere.", from, perm)

	case "nodes_proxy":
		return fmt.Sprintf("Acting as %s, the attacker uses `nodes/proxy` (%s) to forward requests directly to the kubelet on each node. Combined with the kubelet's `/exec` endpoint this becomes a primitive for running commands inside any pod the kubelet can see.", from, perm)

	case "pod_create_token_theft":
		if hasTo {
			return fmt.Sprintf("Acting as %s, the attacker creates a pod that mounts the %s ServiceAccount and then reads `/var/run/secrets/kubernetes.io/serviceaccount/token` from inside the container. The pod becomes a token-theft primitive: any ServiceAccount the attacker can mount, they can lift.", from, to)
		}
		return fmt.Sprintf("Acting as %s, the attacker creates a pod that mounts a privileged ServiceAccount and reads `/var/run/secrets/kubernetes.io/serviceaccount/token` from inside the container — the pod is a token-theft primitive.", from)

	case "pod_exec":
		if hasTo {
			return fmt.Sprintf("Acting as %s, the attacker uses `pods/exec` (%s) to open a shell inside %s and inherit whatever ServiceAccount or host privileges that container holds.", from, perm, to)
		}
		return fmt.Sprintf("Acting as %s, the attacker uses `pods/exec` (%s) to open a shell inside a privileged pod and inherit whatever ServiceAccount or host privileges that container holds.", from, perm)

	case "token_request":
		if hasTo {
			return fmt.Sprintf("Acting as %s, the attacker calls the `serviceaccounts/token` subresource (%s) to mint a fresh, valid token for %s — no pod creation required, and a thinner audit trail than the pod-mount route.", from, perm, to)
		}
		return fmt.Sprintf("Acting as %s, the attacker calls the `serviceaccounts/token` subresource (%s) to mint a fresh token for a privileged ServiceAccount — no pod creation required, and a thinner audit trail than the pod-mount route.", from, perm)

	case "mint_arbitrary_token":
		return fmt.Sprintf("Acting as %s, the attacker calls `serviceaccounts/token` at cluster scope (%s) to mint a token for any ServiceAccount in any namespace. With no `resourceNames` constraint, the verb amounts to a credential-issuing oracle.", from, perm)

	case "pod_host_escape":
		return fmt.Sprintf("Acting as %s, the attacker schedules a pod with host-level access (`privileged: true`, `hostPath: /`, `hostPID`, or `hostNetwork`) and escapes onto the underlying node. From there they read every co-located pod's filesystem, every projected ServiceAccount token on that node, and the kubelet's client cert.", from)
	}

	// Fallback: unknown technique slug. Produce readable prose using the raw fields
	// rather than a colon-and-semicolon dump, so a future analyzer rule that emits
	// a new slug still reads sensibly until a case is added above.
	var b strings.Builder
	fmt.Fprintf(&b, "Acting as %s", from)
	if hasTo {
		fmt.Fprintf(&b, ", the attacker uses the `%s` technique to reach %s", hop.Action, to)
	} else if hop.Action != "" {
		fmt.Fprintf(&b, ", the attacker uses the `%s` technique", hop.Action)
	}
	if perm != "" {
		fmt.Fprintf(&b, " via %s", perm)
	}
	if gains != "" {
		fmt.Fprintf(&b, " — %s", gains)
	}
	b.WriteString(".")
	return b.String()
}

// backtickSubject returns a Markdown backtick-wrapped Key() for a subject, or
// "" when the SubjectRef is empty (e.g. the tail of an escalation path whose
// terminal hop ends at a synthetic sink — cluster_admin, node_escape — instead
// of another subject). Callers that reference the target should branch on the
// empty case to produce sink-aware prose, since an empty backtick pair reads
// as a rendering bug to the reader.
func backtickSubject(s models.SubjectRef) string {
	key := s.Key()
	if key == "" || key == "/" {
		return ""
	}
	return fmt.Sprintf("`%s`", key)
}

// hopsRemediation surfaces the hop most suitable for breaking the chain: prefer mid-chain
// `pod_create_token_theft`, `impersonate`, `bind`, `escalate` techniques, then fall back to
// the first hop. Returns a human-readable description for the remediation step.
func hopsRemediation(hops []models.EscalationHop) string {
	if len(hops) == 0 {
		return "constrain the source subject's permissions"
	}
	priority := []string{"impersonate", "bind", "escalate", "pod_create_token_theft", "secrets_read_token", "wildcard_verbs", "exec_pod"}
	for _, want := range priority {
		for _, hop := range hops {
			if strings.Contains(hop.Action, want) {
				return fmt.Sprintf("remove the `%s` capability that enables hop %d (`%s` → `%s`)", hop.Permission, hop.Step, hop.FromSubject.Key(), hop.ToSubject.Key())
			}
		}
	}
	hop := hops[0]
	return fmt.Sprintf("remove the permission `%s` that enables the first hop (`%s` → `%s`)", hop.Permission, hop.FromSubject.Key(), hop.ToSubject.Key())
}

func contentClusterAdminPath(source models.SubjectRef, hops []models.EscalationHop) ruleContent {
	hopCount := len(hops)
	steps := make([]string, 0, hopCount+2)
	steps = append(steps, fmt.Sprintf("Attacker compromises any pod or credential associated with `%s` (RCE in any application using its identity, leaked token, or compromised image).", source.Key()))
	for _, hop := range hops {
		steps = append(steps, hopNarrative(hop))
	}
	steps = append(steps, "Final step: attacker now wields a credential authorized for `verbs:[*]` on `resources:[*]` — they read every Secret cluster-wide, exec into any pod, and persist via DaemonSets, mutating webhooks, or backdoor RBAC bindings.")
	return ruleContent{
		Title: fmt.Sprintf("`%s` can reach **cluster-admin equivalent** in %d hop(s)", source.Key(), hopCount),
		Scope: scopeForPath(source, models.TargetClusterAdmin),
		Description: fmt.Sprintf("Subject `%s` has a multi-hop privilege-escalation path that ends at a cluster-admin-equivalent identity (`verbs:[*]` on `resources:[*]`). The graph search found a chain of %d hop(s) where each hop is an RBAC primitive: secret-read into token theft, role binding, role escalation, impersonation, or pod-create-with-mounted-SA. Once a chain exists, the question is not \"could this be exploited\" but \"how quickly\" — every hop is a built-in API operation, no exploit dev needed.\n\n"+
			"The chain (each step uses an explicit RBAC verb the engine validated against the snapshot):\n%s\n\n"+
			"This finding is correlated against pod-mounted ServiceAccounts and the engine's `correlate` pass — a chain whose source is mounted by a workload is qualitatively worse than one whose source is a manually-issued user, because every workload compromise becomes an immediate path to cluster-admin.",
			source.Key(), hopCount, formatHopList(hops)),
		Impact:         fmt.Sprintf("Compromise of `%s` (or anything mounted by it) yields full cluster control: read every Secret, mutate any workload, exfiltrate any data, plant persistent backdoors. There is no defense-in-depth past this point.", source.Key()),
		AttackScenario: steps,
		Remediation:    fmt.Sprintf("Break the chain at the weakest hop: %s.", hopsRemediation(hops)),
		RemediationSteps: []string{
			"Confirm the chain is real with `kubectl auth can-i` for each verb the engine cited (run as the source SA / each intermediate hop).",
			fmt.Sprintf("Identify the lowest-cost hop to break (typically %s) — removing one mid-chain hop kills the entire path.", hopsRemediation(hops)),
			"Apply the change in a non-prod cluster first; re-run the scanner to confirm the path no longer resolves.",
			"For each remaining `wildcard verbs / wildcard resources` binding in the chain, run `audit2rbac` to derive the minimum verbs the workload actually uses, then replace.",
			"Wire enforcement: a Kyverno or OPA Gatekeeper policy that fails any new RoleBinding/ClusterRoleBinding with `verbs:[*]` on `resources:[*]` to non-system subjects, plus a CI check that re-runs `kubesplaining` against the rendered manifests of every PR.",
		},
		LearnMore: []models.Reference{
			refHackTricksRBAC,
			refRBACGoodPrac,
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1098, mitreT1068, mitreT1556},
	}
}

func contentNodeEscapePath(source models.SubjectRef, hops []models.EscalationHop) ruleContent {
	hopCount := len(hops)
	steps := make([]string, 0, hopCount+2)
	steps = append(steps, fmt.Sprintf("Attacker compromises any workload or credential bound to `%s`.", source.Key()))
	for _, hop := range hops {
		steps = append(steps, hopNarrative(hop))
	}
	steps = append(steps, "Final step: a privileged pod with `hostPath: /` (or `hostPID + privileged: true`) is created. The attacker `chroot /host bash` and now runs as root on the worker node — reading every other pod's filesystem, every projected ServiceAccount token on that node, and the kubelet client cert.")
	return ruleContent{
		Title: fmt.Sprintf("`%s` can reach **node escape** (host root) in %d hop(s)", source.Key(), hopCount),
		Scope: scopeForPath(source, models.TargetNodeEscape),
		Description: fmt.Sprintf("Subject `%s` has a privesc path that terminates in the ability to schedule a pod with host-level access (`hostPath: /`, `privileged: true`, `hostPID`, or hostNetwork) — which is structurally equivalent to root on the worker node. Once an attacker has node root, all defense-in-depth at the Kubernetes layer is bypassed: pod isolation depends on the kernel and runtime, not on RBAC, and node root reads every other pod's filesystem (including projected ServiceAccount tokens) and every kubelet credential.\n\n"+
			"The chain (%d hop(s); each step uses an explicit RBAC verb or pod primitive the engine validated):\n%s\n\n"+
			"Node escape is qualitatively different from cluster-admin: cluster-admin gives API control; node escape gives *operational* control over a host. With node root the attacker can plant a persistent rootkit, install a kernel module, capture every container's network traffic via tcpdump on the host's `cni0/flannel.1/cali*` interface, and exfiltrate every projected ServiceAccount token by reading `/var/lib/kubelet/pods/*/volumes/.../token`. From there, those tokens cascade into more cluster-admin paths.",
			source.Key(), hopCount, formatHopList(hops)),
		Impact:         fmt.Sprintf("Compromise of `%s` yields host root on a worker node — every co-located pod's filesystem and every projected SA token are immediately readable, and the kubelet client cert can be used to access node-level APIs.", source.Key()),
		AttackScenario: steps,
		Remediation:    fmt.Sprintf("Break the chain by either (a) removing the pod-creation primitive that enables node escape, or (b) constraining what privileged settings the chain's pods can request. Lowest-cost cut: %s.", hopsRemediation(hops)),
		RemediationSteps: []string{
			"Identify which hop ends in `pod_create_*` or grants Pod Security violations (`privileged`, `hostPath`, `hostPID`, `hostNetwork`).",
			"Apply Pod Security Admission `restricted` profile to namespaces reachable from this chain — `kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted`. This blocks privileged pods at admission.",
			"Audit any namespace that is `privileged`-labeled — DaemonSets and operators that genuinely need host access should run in a dedicated namespace not reachable via tenant chains.",
			fmt.Sprintf("Remove the cited capability: %s.", hopsRemediation(hops)),
			"Wire admission policy (Kyverno `restrict-host-path-mount`, `disallow-privileged-containers`) so future pods cannot regress.",
		},
		LearnMore: []models.Reference{
			refHackTricksRBAC,
			{Title: "Kubernetes — Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_007, mitreT1068, mitreT1078_004},
	}
}

func contentKubeSystemSecretsPath(source models.SubjectRef, hops []models.EscalationHop) ruleContent {
	hopCount := len(hops)
	steps := make([]string, 0, hopCount+2)
	steps = append(steps, fmt.Sprintf("Attacker compromises any workload mounting `%s`.", source.Key()))
	for _, hop := range hops {
		steps = append(steps, hopNarrative(hop))
	}
	steps = append(steps, "Final step: the attacker has `get secrets -n kube-system`. They list every Secret, decode each `data` value, and pull cloud IAM credentials, registry pull secrets, addon API keys, and SA tokens for cluster-admin-adjacent operators. Each of those is a separate privesc path, often shorter than the one that got them here.")
	return ruleContent{
		Title: fmt.Sprintf("`%s` can read **kube-system Secrets** in %d hop(s)", source.Key(), hopCount),
		Scope: scopeForPath(source, models.TargetKubeSystemSecrets),
		Description: fmt.Sprintf("Subject `%s` has a privesc path that terminates in `get/list/watch secrets` in `kube-system`. This is not full cluster-admin, but it is the most consequential namespace to read — `kube-system` Secrets typically contain the credentials that *unlock* cluster-admin: cloud IAM keys (cloud-controller-manager, EBS/PD/Disk CSI), registry pull secrets (system images), addon API keys, and tokens for SAs that are themselves bound to `cluster-admin` (operator installers, helm-controllers).\n\n"+
			"The chain (%d hop(s); each step uses an explicit RBAC verb the engine validated):\n%s\n\n"+
			"In production clusters this path is the single most common one in `kubesplaining`'s output — `secrets:get` is over-granted by Helm chart defaults, by stale `view`-style roles, and by ConfigMap-reader roles that wildcard `resources` to include Secrets. The path is short (often 1-2 hops) and exploitation is trivial: the attacker decodes base64 and is in.",
			source.Key(), hopCount, formatHopList(hops)),
		Impact:         "Reading kube-system Secrets typically yields cloud-account compromise, registry write (supply-chain implant), and tokens for cluster-admin-adjacent SAs — a one-way ratchet to full cluster control through subsequent privesc paths.",
		AttackScenario: steps,
		Remediation:    fmt.Sprintf("Eliminate the path by tightening `secrets:get` in `kube-system` to a narrow allowlist of system controllers, then break the chain at: %s.", hopsRemediation(hops)),
		RemediationSteps: []string{
			"List who can `get secrets -n kube-system`: `kubectl auth can-i get secrets -n kube-system --as=system:serviceaccount:<ns>:<sa>` for every workload SA, and `kubectl get rolebindings,clusterrolebindings -A -o yaml | grep -B5 secrets` to find broad grants.",
			"Move kube-system Secrets that don't need to be live to External Secrets Operator (Vault/SecretsManager) so the in-cluster Secret becomes a generated artifact instead of source-of-truth.",
			fmt.Sprintf("Break the chain at: %s.", hopsRemediation(hops)),
			"For controllers that legitimately need a kube-system Secret read, scope the binding to that exact named Secret using `resourceNames`, not `resources: [secrets]`.",
			"Wire admission policy: a Kyverno rule that fails any new RoleBinding/ClusterRoleBinding granting `secrets` verbs without `resourceNames` to non-system subjects.",
		},
		LearnMore: []models.Reference{
			refHackTricksRBAC,
			refRBACGoodPrac,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_007, mitreT1078_004, mitreT1098},
	}
}

func contentSystemMastersPath(source models.SubjectRef, hops []models.EscalationHop) ruleContent {
	hopCount := len(hops)
	steps := make([]string, 0, hopCount+2)
	steps = append(steps, fmt.Sprintf("Attacker compromises any workload bound to `%s`.", source.Key()))
	for _, hop := range hops {
		steps = append(steps, hopNarrative(hop))
	}
	steps = append(steps, "Final step: attacker can impersonate group `system:masters`. The kube-apiserver short-circuits authorization for `system:masters` via the static token / certificate path — bypassing every RBAC check. They are now indistinguishable from a kubeadm control-plane operator.")
	return ruleContent{
		Title: fmt.Sprintf("`%s` can impersonate **`system:masters`** in %d hop(s) — bypasses all RBAC", source.Key(), hopCount),
		Scope: scopeForPath(source, models.TargetSystemMasters),
		Description: fmt.Sprintf("Subject `%s` can chain into the ability to impersonate the `system:masters` group. `system:masters` is special: the kube-apiserver hard-codes it as authorized for *every* operation regardless of RBAC. There is no Role or ClusterRole that grants `system:masters` reach — it is a pre-RBAC carve-out for kubeadm control-plane operators (cert-based auth with `O=system:masters` skips authorization entirely).\n\n"+
			"The chain (%d hop(s); each step is an RBAC verb the engine validated):\n%s\n\n"+
			"Impersonation of `system:masters` is the rarest but most severe finding type. Most clusters do not give workload SAs `impersonate users/groups` because `system:masters` is the pathological consequence — a single `impersonate` grant on a workload SA is the entire chain. CIS Kubernetes 5.1.4 and the RBAC good-practices guide explicitly call out impersonation grants for review.",
			source.Key(), hopCount, formatHopList(hops)),
		Impact:         "Impersonating `system:masters` bypasses every RBAC check the cluster ever had. Every API call succeeds. Audit logs are written but the actor field shows the impersonated principal; attribution requires reading the `impersonate` audit annotation.",
		AttackScenario: steps,
		Remediation:    fmt.Sprintf("Remove every `impersonate` grant on a path to `system:masters`. Concretely: %s.", hopsRemediation(hops)),
		RemediationSteps: []string{
			"List subjects with impersonate: `kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]? | .kind == \"User\" or .kind == \"Group\" or .kind == \"ServiceAccount\") | .metadata.name + \" → \" + (.roleRef.name)'` then check each role's rules for `impersonate`.",
			"Almost no production workload genuinely needs `impersonate users/groups`. Kubectl plugins/dashboards that *do* need it should use `kubectl --as=...` from a human admin's session, not a workload SA.",
			fmt.Sprintf("Break the chain: %s.", hopsRemediation(hops)),
			"For kubectl-as-a-service workloads, scope the impersonation with `resourceNames: [<allowed-user>]` to a fixed allowlist of principals — *never* `users: [*]` or `groups: [*]`.",
			"Wire admission policy: a Kyverno rule that fails any RoleBinding granting `impersonate` to a non-system subject without an explicit `resourceNames` carve-out.",
		},
		LearnMore: []models.Reference{
			refHackTricksRBAC,
			refRBACGoodPrac,
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1098, mitreT1556, mitreT1068},
	}
}

func contentGenericPath(source models.SubjectRef, target models.EscalationTarget, hops []models.EscalationHop) ruleContent {
	hopCount := len(hops)
	steps := make([]string, 0, hopCount+2)
	steps = append(steps, fmt.Sprintf("Attacker compromises any workload bound to `%s`.", source.Key()))
	for _, hop := range hops {
		steps = append(steps, hopNarrative(hop))
	}
	steps = append(steps, fmt.Sprintf("Final step: attacker reaches `%s`.", target))
	return ruleContent{
		Title: fmt.Sprintf("`%s` can reach `%s` in %d hop(s)", source.Key(), target, hopCount),
		Scope: scopeForPath(source, target),
		Description: fmt.Sprintf("Subject `%s` has a multi-hop chain to `%s`. Each hop in the chain is an RBAC primitive the engine validated against the snapshot.\n\nThe chain:\n%s",
			source.Key(), target, formatHopList(hops)),
		Impact:         fmt.Sprintf("Compromise of `%s` chains to `%s` — investigate the specific privileges this sink represents in your cluster.", source.Key(), target),
		AttackScenario: steps,
		Remediation:    fmt.Sprintf("Break the chain at the weakest hop: %s.", hopsRemediation(hops)),
		RemediationSteps: []string{
			"Confirm each hop with `kubectl auth can-i`.",
			fmt.Sprintf("Apply the cut: %s.", hopsRemediation(hops)),
			"Re-run the scanner to confirm the path no longer resolves.",
		},
		LearnMore: []models.Reference{
			refHackTricksRBAC,
			refRBACGoodPrac,
			refMSThreatMatrix,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1098, mitreT1068},
	}
}

// formatHopList renders the chain as a numbered Markdown list embeddable in Description.
func formatHopList(hops []models.EscalationHop) string {
	if len(hops) == 0 {
		return "  (no hops — direct membership)"
	}
	lines := make([]string, 0, len(hops))
	for _, hop := range hops {
		lines = append(lines, fmt.Sprintf("  %d. `%s` → `%s` via `%s` (%s) — %s", hop.Step, hop.FromSubject.Key(), hop.ToSubject.Key(), hop.Action, hop.Permission, hop.Gains))
	}
	return strings.Join(lines, "\n")
}
