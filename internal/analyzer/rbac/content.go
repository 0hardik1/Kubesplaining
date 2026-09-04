// Content for RBAC findings. Each rule has a builder that takes runtime context
// (namespace, subject, source role/binding) and returns an enriched ruleContent
// with scope-aware language, an attacker walkthrough, ordered remediation steps,
// and structured references / MITRE technique citations.
//
// Sources for the content below: Kubernetes RBAC Good Practices, NSA/CISA Kubernetes
// Hardening Guide v1.2, MITRE ATT&CK Containers matrix, Microsoft Threat Matrix for
// Kubernetes, kubernetes/kubernetes#119640 (nodes/proxy escalation), Datadog Security
// Labs (TokenRequest persistence), Aqua Security and SCHUTZWERK RBAC writeups.
package rbac

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// ruleContent bundles every enriched field a rule emits beyond Title/Description.
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

// scopeForRule renders the Scope a finding inherits from its source rule. Cluster-wide
// when the originating binding is a ClusterRoleBinding (rule.Namespace == "") and namespace-scoped
// otherwise. The Detail string is what the report shows in the scope chip and CSV.
func scopeForRule(ruleNamespace string) models.Scope {
	if ruleNamespace == "" {
		return models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: applies to every current and future namespace",
		}
	}
	return models.Scope{
		Level:  models.ScopeNamespace,
		Detail: fmt.Sprintf("Namespace `%s` only", ruleNamespace),
	}
}

// scopePhrase is the short prefix used in titles, e.g. "Cluster-wide" or "Namespace `prod`".
func scopePhrase(s models.Scope) string {
	if s.Level == models.ScopeCluster {
		return "Cluster-wide"
	}
	if s.Detail != "" {
		return s.Detail
	}
	return "Namespace-scoped"
}

// subjectKey is a short helper so analyzer call-sites stay readable.
func subjectKey(subject models.SubjectRef) string {
	return subject.Key()
}

// formatBindingRef renders a RoleBinding/ClusterRoleBinding reference for inclusion
// in finding prose. ClusterRoleBindings are cluster-scoped and rendered as
// "ClusterRoleBinding `name`"; RoleBindings include their namespace so a reader
// can locate them with `kubectl -n <ns> get rolebinding <name>`.
func formatBindingRef(kind, namespace, name string) string {
	if kind == "" {
		return fmt.Sprintf("`%s`", name)
	}
	if namespace != "" {
		return fmt.Sprintf("%s `%s/%s`", kind, namespace, name)
	}
	return fmt.Sprintf("%s `%s`", kind, name)
}

// formatRoleRef renders a Role/ClusterRole reference identically to formatBindingRef.
// Roles are namespace-scoped (rendered as "Role `ns/name`"); ClusterRoles are
// cluster-scoped (rendered as "ClusterRole `name`").
func formatRoleRef(kind, namespace, name string) string {
	return formatBindingRef(kind, namespace, name)
}

// kubectlAuthCanI returns the verification command tailored to scope.
func kubectlAuthCanI(verb, resource string, ruleNamespace string, subject models.SubjectRef) string {
	scope := "-A"
	if ruleNamespace != "" {
		scope = fmt.Sprintf("-n %s", ruleNamespace)
	}
	return fmt.Sprintf("kubectl auth can-i %s %s --as=%s %s", verb, resource, subject.Name, scope)
}

// References used across most rules — collected once so each rule's LearnMore stays focused.
var (
	refRBACGoodPractices = models.Reference{
		Title: "Kubernetes — RBAC Good Practices",
		URL:   "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
	}
	refRBACDocs = models.Reference{
		Title: "Kubernetes — Using RBAC Authorization",
		URL:   "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	}
	refNSAHardening = models.Reference{
		Title: "NSA/CISA Kubernetes Hardening Guide v1.2 (PDF)",
		URL:   "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF",
	}
	refMSThreatMatrix = models.Reference{
		Title: "Microsoft Threat Matrix for Kubernetes",
		URL:   "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/",
	}
)

// MITRE ATT&CK helpers (Containers matrix). These objects are reused across rules.
var (
	mitreT1078 = models.MitreTechnique{
		ID:   "T1078",
		Name: "Valid Accounts",
		URL:  "https://attack.mitre.org/techniques/T1078/",
	}
	mitreT1078_004 = models.MitreTechnique{
		ID:   "T1078.004",
		Name: "Valid Accounts: Cloud Accounts",
		URL:  "https://attack.mitre.org/techniques/T1078/004/",
	}
	mitreT1098 = models.MitreTechnique{
		ID:   "T1098",
		Name: "Account Manipulation",
		URL:  "https://attack.mitre.org/techniques/T1098/",
	}
	mitreT1098_001 = models.MitreTechnique{
		ID:   "T1098.001",
		Name: "Account Manipulation: Additional Cloud Credentials",
		URL:  "https://attack.mitre.org/techniques/T1098/001/",
	}
	mitreT1134 = models.MitreTechnique{
		ID:   "T1134",
		Name: "Access Token Manipulation",
		URL:  "https://attack.mitre.org/techniques/T1134/",
	}
	mitreT1528 = models.MitreTechnique{
		ID:   "T1528",
		Name: "Steal Application Access Token",
		URL:  "https://attack.mitre.org/techniques/T1528/",
	}
	mitreT1548 = models.MitreTechnique{
		ID:   "T1548",
		Name: "Abuse Elevation Control Mechanism",
		URL:  "https://attack.mitre.org/techniques/T1548/",
	}
	mitreT1550 = models.MitreTechnique{
		ID:   "T1550",
		Name: "Use Alternate Authentication Material",
		URL:  "https://attack.mitre.org/techniques/T1550/",
	}
	mitreT1552_007 = models.MitreTechnique{
		ID:   "T1552.007",
		Name: "Unsecured Credentials: Container API",
		URL:  "https://attack.mitre.org/techniques/T1552/007/",
	}
	mitreT1609 = models.MitreTechnique{
		ID:   "T1609",
		Name: "Container Administration Command",
		URL:  "https://attack.mitre.org/techniques/T1609/",
	}
	mitreT1610 = models.MitreTechnique{
		ID:   "T1610",
		Name: "Deploy Container",
		URL:  "https://attack.mitre.org/techniques/T1610/",
	}
	mitreT1611 = models.MitreTechnique{
		ID:   "T1611",
		Name: "Escape to Host",
		URL:  "https://attack.mitre.org/techniques/T1611/",
	}
	mitreT1613 = models.MitreTechnique{
		ID:   "T1613",
		Name: "Container and Resource Discovery",
		URL:  "https://attack.mitre.org/techniques/T1613/",
	}
	mitreT1090 = models.MitreTechnique{
		ID:   "T1090",
		Name: "Proxy",
		URL:  "https://attack.mitre.org/techniques/T1090/",
	}
)

// contentPrivesc017 — Wildcard verbs/resources/apiGroups (KUBE-PRIVESC-017).
func contentPrivesc017(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s wildcard RBAC permissions on `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("RBAC rule from %s → %s grants `*` verbs on `*` resources in `*` apiGroups to %s. %s.\n\n"+
			"Wildcards are dangerous beyond their current expansion: any resource type added later (CRDs, new core subresources, future verbs) is automatically granted to this subject without anyone reviewing the change. The Kubernetes project explicitly flags this in `RBAC Good Practices` as an anti-pattern.\n\n"+
			"In a typical attack, an adversary who reaches a workload bound to this rule has full control: they read every Secret, create privileged pods on any node, bind themselves to additional ClusterRoles, and persist by minting long-lived tokens via the TokenRequest API. There is no further escalation needed. The box is already at the top.",
			sourceBinding, sourceRole, subjectKey(subject), scope.Detail),
		Impact: fmt.Sprintf("Full control over %s: read/write every Secret, RBAC, Pod, Node; equivalent to `cluster-admin` when cluster-scoped.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a workload that resolves to %s (vulnerable container image, supply-chain backdoor, or stolen kubeconfig).", subjectKey(subject)),
			fmt.Sprintf("They run `%s` and confirm wildcard permissions.", kubectlAuthCanI("'*'", "'*'", ruleNamespace, subject)),
			"They list every Secret in scope (`kubectl get secrets -A -o yaml`) to harvest cloud-provider credentials, registry pull secrets, and other ServiceAccount tokens.",
			"They create a privileged DaemonSet that mounts the host filesystem and reads `/etc/kubernetes/pki/*` to steal the cluster CA.",
			"They establish persistence by minting a long-lived token for `clusterrole-aggregation-controller` via the TokenRequest API, then optionally remove their original binding to evade detection.",
		},
		Remediation: "Replace the wildcard rule with an explicit allowlist of (apiGroups, resources, verbs) limited to what the workload actually calls.",
		RemediationSteps: []string{
			fmt.Sprintf("Inventory what %s actually needs. Run `%s` and correlate with audit logs filtered on `user.username`.", subjectKey(subject), kubectlAuthCanI("--list", "", ruleNamespace, subject)),
			"Author a least-privilege Role/ClusterRole listing only those (apiGroups, resources, verbs); drop every wildcard. Prefer namespace-scoped Role+RoleBinding over ClusterRole+ClusterRoleBinding wherever possible.",
			fmt.Sprintf("Apply the new binding, delete the wildcard binding %s, and verify with `%s` returning `no`.", sourceBinding, kubectlAuthCanI("'*'", "'*'", ruleNamespace, subject)),
			"Add a ValidatingAdmissionPolicy (or Kyverno/OPA Gatekeeper rule) that rejects any future Role/ClusterRole containing `*` in verbs, resources, or apiGroups.",
		},
		LearnMore: []models.Reference{
			refRBACGoodPractices,
			refRBACDocs,
			refNSAHardening,
			{Title: "Microsoft Threat Matrix for Kubernetes — Privilege Escalation", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/tactics/PrivilegeEscalation/"},
			{Title: "Unit 42 — Mitigating RBAC-Based Privilege Escalation", URL: "https://unit42.paloaltonetworks.com/kubernetes-privilege-escalation/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078, mitreT1078_004, mitreT1610, mitreT1613, mitreT1098},
	}
}

// contentPrivesc005 — Secret listing (KUBE-PRIVESC-005). `list`/`watch` on
// secrets enumerates AND reads every Secret in scope in one call; the narrower
// `get`-only case is KUBE-PRIVESC-006.
func contentPrivesc005(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s list/watch access to Secrets enumerates every Secret on `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `list` or `watch` core `secrets` via %s → %s. %s.\n\n"+
			"The Kubernetes documentation is explicit that `list` and `watch` return Secret contents in the response body (they are not metadata-only verbs). Unlike `get` (KUBE-PRIVESC-006), which requires knowing each Secret's name, a single `list` enumerates and dumps every Secret in scope at once: the holder does not need to know what exists first.\n\n"+
			"Kubernetes Secrets typically hold ServiceAccount tokens, kubeconfigs, image-pull credentials, TLS private keys, database passwords, and integration secrets for cloud APIs. Once Secret contents are exposed, the holder can authenticate as the corresponding ServiceAccount/user, which usually amplifies the original blast radius far beyond 'read access'. Cluster-wide listing includes `kube-system` ServiceAccount tokens, which are routinely cluster-admin-equivalent.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("%s enumeration and read of every Secret (ServiceAccount tokens, TLS keys, registry credentials, integration secrets), enabling identity replay and cross-namespace lateral movement.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker reaches %s (compromised pod, leaked kubeconfig, or stolen token).", subjectKey(subject)),
			"They run `kubectl get secrets -o yaml` in scope and base64-decode every `data` field, harvesting all Secrets in one request.",
			"They identify Secrets of type `kubernetes.io/service-account-token` (legacy) or call the TokenRequest API with harvested credentials.",
			"They replay the highest-privileged token against the API server (`kubectl --token=<jwt> get clusterrolebindings`).",
			"They pivot to cloud APIs using extracted IRSA / Workload Identity / cloud-provider credentials, or persist by writing a backdoor into a privileged Deployment.",
		},
		Remediation: "Remove `list`/`watch` on `secrets` from this subject; if a specific Secret is genuinely needed, scope a `get` by `resourceNames` to that one name.",
		RemediationSteps: []string{
			"Confirm the workload genuinely needs API-time Secret access. Most apps consume Secrets via volume/env injection at pod start and don't need RBAC read.",
			"If runtime access is required, drop `list` and `watch` entirely and scope a `get` rule by `resourceNames` to the exact Secret(s) the workload reads. Never leave it as 'all secrets'.",
			"Move the binding from cluster-wide to namespace-scoped (RoleBinding instead of ClusterRoleBinding) so the blast radius is bounded.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("list", "secrets", ruleNamespace, subject)),
			"For sensitive Secrets (TLS keys, cloud credentials), consider an external secret store (Vault, AWS/GCP Secrets Manager via CSI driver) and enable encryption-at-rest with a KMS-backed `EncryptionConfiguration`.",
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Good practices for Kubernetes Secrets", URL: "https://kubernetes.io/docs/concepts/security/secrets-good-practices/"},
			{Title: "Kubernetes — RBAC Good Practices: Secrets read", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#secrets"},
			{Title: "Kubernetes — Encryption at Rest (KMS provider)", URL: "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"},
			{Title: "Datadog Security Labs — Persistence via TokenRequest API", URL: "https://securitylabs.datadoghq.com/articles/kubernetes-tokenrequest-api/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_007, mitreT1528, mitreT1078_004},
	}
}

// contentPrivesc001 — Pod creation (KUBE-PRIVESC-001).
func contentPrivesc001(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s pod creation enables token theft and node takeover (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` pods via %s → %s. %s.\n\n"+
			"Under Kubernetes' RBAC model, pod creation is one of the most powerful permissions because the API server does not police the privileges of the pod being created, only the create verb itself. A pod is a request to run code as a ServiceAccount; by choosing `spec.serviceAccountName` the attacker borrows the identity (and RBAC permissions) of any ServiceAccount in the target namespace, with the token mounted automatically at `/var/run/secrets/kubernetes.io/serviceaccount/token`.\n\n"+
			"Beyond identity hopping, a created pod can request `hostPath`, `hostNetwork`, `hostPID`, `privileged: true`, or `SYS_ADMIN`. None of those are blocked by RBAC; only Pod Security Admission or a policy engine (Kyverno, Gatekeeper, ValidatingAdmissionPolicy) can stop them. A typical attack mounts / from the host and reads `/etc/kubernetes/pki/admin.conf` directly.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Run arbitrary code as any ServiceAccount in %s (including privileged ones); optionally request privileged/host-mount pods to escape to the underlying node.", phrase),
		AttackScenario: []string{
			"Attacker enumerates target namespaces with `kubectl get sa -A` to find privileged ServiceAccounts (e.g. `kube-system/clusterrole-aggregation-controller`).",
			"They craft a pod manifest with `spec.serviceAccountName: <privileged-sa>` and any container image they control.",
			"They `kubectl apply -f` the pod; the kubelet mounts the privileged ServiceAccount's JWT into the container at the well-known path.",
			"They `exec` into the pod (or have the container phone home), read the token, and replay it against the API server.",
			"Optionally, they instead create a pod with `hostPID: true` + `privileged: true` + `hostPath` of `/` and break out to the node.",
		},
		Remediation: "Remove direct pod-create rights from non-platform identities; have CI/CD or controllers create workload objects (Deployments) so the controller-manager creates the pod under its own ServiceAccount.",
		RemediationSteps: []string{
			"Replace direct `create` on `pods` with `create/update` on `deployments` (or the appropriate workload controller).",
			"Enforce `restricted` Pod Security Standard via `pod-security.kubernetes.io/enforce=restricted` namespace label so privileged/hostPath pods are rejected at admission.",
			"Add a Kyverno/Gatekeeper policy that requires `automountServiceAccountToken: false` on user-created pods, or pins them to a non-privileged ServiceAccount.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "pods", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: Workload creation", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation"},
			{Title: "Kubernetes — Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
			{Title: "Kubernetes — Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
			{Title: "Bishop Fox — Bad Pods: Pod Privilege Escalation", URL: "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1552_007, mitreT1611, mitreT1078_004},
	}
}

// contentPrivesc003 — Workload-controller mutation (KUBE-PRIVESC-003).
func contentPrivesc003(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s workload-controller mutation can spawn privileged pods on `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create/update/patch` workload controllers (`deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`) via %s → %s. %s.\n\n"+
			"Anyone who can write a workload template inherits the same implicit permissions as `pods/create`: choice of ServiceAccount, choice of Pod Security context, and choice of host-level features. The specific danger of controller mutation (vs. pod create) is durability and stealth: a `kubectl edit deployment` adding a `privileged: true` sidecar produces pods continuously, so restart-looping the pod returns a fresh shell every time.\n\n"+
			"DaemonSet write is the most dangerous variant because a DaemonSet runs one pod on every node, including new nodes added later. CronJobs offer time-based persistence that survives pod evictions, node reboots, and short-lived RBAC remediations. A realistic incident: an attacker with `patch daemonsets` in `kube-system` mutates `kube-proxy` to add a malicious sidecar inheriting the existing pod's host-mounts and ServiceAccount.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Spawn (or mutate existing) pods running as any ServiceAccount in %s. DaemonSet write specifically yields one attacker pod per node, including future nodes.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates writable controllers with `%s`.", kubectlAuthCanI("patch", "daemonsets", ruleNamespace, subject)),
			"They identify a high-value DaemonSet (e.g. `kube-system/kube-proxy`, `kube-system/cilium`, or any node-agent that already runs privileged).",
			"They `kubectl patch` to add a sidecar container under their control, inheriting the existing pod's host-mounts, capabilities, and ServiceAccount.",
			"The DaemonSet controller rolls the change to every node; the attacker now has a privileged shell on every node and a node-level token on each.",
			"They use the token to enumerate cluster Secrets and pivot to control-plane components. Persistence survives subject-token rotation because the malicious sidecar continues running.",
		},
		Remediation: "Restrict workload-controller mutation to platform/CI identities; route application changes through GitOps with PR review.",
		RemediationSteps: []string{
			"Audit who has `create/update/patch` on `deployments,daemonsets,statefulsets,jobs,cronjobs`. Most application identities should not have this.",
			"Move deployment changes behind GitOps (Argo CD/Flux) so humans push to Git and the controller applies the change under its own ServiceAccount.",
			"Add a Kyverno/Gatekeeper policy that rejects pod templates with `privileged`, `hostPID`, `hostNetwork`, `hostPath` mounts, or `automountServiceAccountToken: true` outside an explicit allowlist.",
			fmt.Sprintf("For DaemonSets specifically, restrict creation to named platform ServiceAccounts. Verify with `%s` returning `no`.", kubectlAuthCanI("create", "daemonsets", "kube-system", subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: Workload creation", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation"},
			{Title: "Kubernetes — DaemonSet (runs on every node)", URL: "https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/"},
			{Title: "Kyverno — Disallow privileged containers policy", URL: "https://kyverno.io/policies/pod-security/baseline/disallow-privileged-containers/disallow-privileged-containers/"},
			{Title: "Microsoft Threat Matrix for Kubernetes — Privilege Escalation", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/tactics/PrivilegeEscalation/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1098, mitreT1078_004},
	}
}

// contentPrivesc008 — Impersonate (KUBE-PRIVESC-008).
func contentPrivesc008(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `impersonate` permission on `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s has the `impersonate` verb on `users/groups/serviceaccounts` via %s → %s. %s.\n\n"+
			"Kubernetes' impersonation lets a request set `Impersonate-User/Impersonate-Group` headers (or `kubectl --as`) so the API server processes the request as a different identity. The Kubernetes project flags this in `RBAC Good Practices` as one of three verbs (alongside `bind` and `escalate`) that override normal RBAC limits.\n\n"+
			"Most damaging is the ability to impersonate the `system:masters` group, which is hardcoded inside kube-apiserver to bypass RBAC entirely. There is no Role or RoleBinding that grants `system:masters` membership; the apiserver simply trusts the assertion. `kubectl --as=admin --as-group=system:masters get secrets -A` runs as cluster-admin, full stop. Impersonation is also stealthier than a binding change because audit logs show `user.username` as the original subject.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Act as any user/group/ServiceAccount in %s; impersonating `system:masters` bypasses all RBAC checks irrevocably.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("impersonate", "users", ruleNamespace, subject)),
			"They run `kubectl --as=admin --as-group=system:masters get clusterrolebindings` to confirm `system:masters` impersonation succeeds.",
			"They impersonate the highest-privileged ServiceAccount they can find (e.g. `system:serviceaccount:kube-system:clusterrole-aggregation-controller`) and exfiltrate Secrets cluster-wide.",
			"They establish persistence by creating a benign-looking ClusterRoleBinding via the impersonated identity (audit logs blame the impersonated SA, not the attacker).",
			"They optionally add their own user to a privileged group via OIDC group claims, providing identity-layer persistence that survives RBAC remediation.",
		},
		Remediation: "Remove `impersonate` entirely; if a SaaS console truly needs it, gate on `resourceNames` and never grant it on `groups`.",
		RemediationSteps: []string{
			"Remove `impersonate` on `users`, `groups`, and `serviceaccounts`. The vast majority of workloads have no need for impersonation.",
			"If impersonation is genuinely required, scope to `users` only (not `groups`, and never allow `system:masters`), use `resourceNames` to allow only specific identities, and never grant cluster-wide.",
			"Enable Impersonate-* audit policy at `Metadata` level minimum so every impersonated request is logged with the original caller. SIEM-alert on impersonation of any `system:` user or group.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("impersonate", "'*'", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — User Impersonation", URL: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation"},
			{Title: "Kubernetes — RBAC Good Practices: Privilege escalation risks", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks"},
			{Title: "Kubernetes — Auditing", URL: "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078, mitreT1078_004, mitreT1550, mitreT1134},
	}
}

// contentPrivesc009 — Bind/escalate (KUBE-PRIVESC-009).
func contentPrivesc009(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `bind/escalate` on roles bypasses RBAC (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s has the `bind` or `escalate` verb on `roles/clusterroles` via %s → %s. %s.\n\n"+
			"Kubernetes' RBAC normally enforces a privilege-escalation guard: you cannot create a Role/RoleBinding granting permissions you do not already hold. The `escalate` and `bind` verbs are explicit, documented exceptions to that guard.\n\n"+
			"`escalate` lets the subject author or modify a Role/ClusterRole with verbs and resources they don't currently possess. In practice, they rewrite an existing Role they're already bound to and instantly inherit whatever they wrote into it.\n\n"+
			"`bind` lets the subject create a RoleBinding/ClusterRoleBinding referencing a (Cluster)Role they don't already hold. With `bind` on `clusterroles`, an attacker creates a ClusterRoleBinding from themselves to `cluster-admin` and is done in one step.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Defeat the API-level escalation guard in %s; subject can grant itself any (Cluster)Role's permissions, including `cluster-admin`.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("bind", "clusterroles", ruleNamespace, subject)),
			"They write a one-line ClusterRoleBinding from their identity (or a SA they control) to the `cluster-admin` ClusterRole and `kubectl apply` it.",
			"They re-use the same token (ClusterRoleBindings take effect immediately on next request) and have full cluster control.",
			"Alternatively, with `escalate` on `clusterroles`, they `kubectl edit clusterrole/<role-they-already-have>` and add `*` verbs/resources/apiGroups, retaining the same binding.",
			"They optionally name the new ClusterRoleBinding innocuously (e.g. `cluster-monitor-binding`) so the change is less visible to operators reviewing `kubectl get clusterrolebindings`.",
		},
		Remediation: "Remove `bind` and `escalate` from non-admin identities; gate any legitimate need behind admission policy that rejects bindings to `cluster-admin` or system roles.",
		RemediationSteps: []string{
			"Audit every Role/ClusterRole that includes `bind` or `escalate` with `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.verbs[]? | IN(\"bind\",\"escalate\"))'`.",
			"Remove the verbs from this Role/ClusterRole. If operators legitimately need them (Argo CD, Crossplane, OperatorHub), scope `bind` with `resourceNames` to a list of low-privilege ClusterRoles.",
			"Add a ValidatingAdmissionPolicy (or Kyverno) that rejects creation of any ClusterRoleBinding referencing `cluster-admin/admin/system:masters` outside a tiny admin allowlist.",
			fmt.Sprintf("Verify with `%s` and `%s` both returning `no`.", kubectlAuthCanI("bind", "clusterroles", ruleNamespace, subject), kubectlAuthCanI("escalate", "roles", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Authorization: Restrictions on role-binding creation/update", URL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update"},
			{Title: "Aqua Security — Kubernetes RBAC: How to Avoid Privilege Escalation", URL: "https://www.aquasec.com/blog/kubernetes-rbac-privilige-escalation/"},
			{Title: "SCHUTZWERK — Kubernetes RBAC: Paths for Privilege Escalation", URL: "https://www.schutzwerk.com/en/blog/kubernetes-privilege-escalation-01/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1078_004, mitreT1548},
	}
}

// contentPrivesc010 — RoleBinding write (KUBE-PRIVESC-010).
func contentPrivesc010(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s write access to (Cluster)RoleBindings opens a self-grant path (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create/update/patch` `rolebindings/clusterrolebindings` via %s → %s. %s.\n\n"+
			"RoleBinding write is the most direct self-grant path in Kubernetes. Even with the API-level escalation guard active (binding only to roles whose permissions you already have), this permission is dangerous: if the subject already holds any powerful permission (often inherited from a default ClusterRole like `view/edit`), they can re-bind it to backup identities for persistence.\n\n"+
			"A RoleBinding can also reference a *ClusterRole*, granting that ClusterRole's permissions inside the binding's namespace, so `create rolebindings` in `kube-system` is effectively cluster-admin-on-kube-system. Combined with `bind` on `clusterroles` (KUBE-PRIVESC-009), this bypasses the escalation guard entirely and yields cluster-admin in one step. Microsoft's Threat Matrix for Kubernetes documents this as the `Cluster-admin binding` technique.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: "Self-grant any role the subject already holds (or any ClusterRole, when paired with `bind` or when binding into namespaces); cluster-wide writes are one step from cluster-admin.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates what they can already bind with `%s` and `%s`.", kubectlAuthCanI("create", "clusterrolebindings", ruleNamespace, subject), kubectlAuthCanI("--list", "", ruleNamespace, subject)),
			"If they hold a useful role, they create a ClusterRoleBinding granting that role to a backup identity for persistence.",
			"With `bind` on `cluster-admin` (often via wildcards), they create a ClusterRoleBinding from themselves to `cluster-admin`.",
			"Even without `bind`, in `kube-system` they create a RoleBinding referencing `system:controller:clusterrole-aggregation-controller` (which has `escalate` baked in) and pivot from there.",
			"They name the binding innocuously (e.g. `monitoring-readonly`) so audit logs look benign.",
		},
		Remediation: "Restrict `create/update/patch` on `rolebindings/clusterrolebindings` to a small admin boundary; require all RBAC changes to flow through GitOps with PR review.",
		RemediationSteps: []string{
			"Audit who has write access to RBAC bindings. Most workloads should have zero RBAC write rights.",
			"Remove the verbs entirely from this Role/ClusterRole, or scope them with `resourceNames` to a fixed list of binding names that the workload owns.",
			"Move RBAC management to GitOps (Argo CD/Flux) so binding changes require a PR. The GitOps controller should be the only identity with cluster-wide RBAC write access.",
			"Add a ValidatingAdmissionPolicy that rejects ClusterRoleBindings to high-risk ClusterRoles (`cluster-admin`, `admin`, anything matching `*system:*`) outside an approved admin allowlist.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "clusterrolebindings", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Authorization: Restrictions on role-binding creation/update", URL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update"},
			{Title: "Microsoft Threat Matrix for Kubernetes — Cluster-admin binding", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster-admin%20binding/"},
			{Title: "Elastic — Kubernetes Cluster-Admin Role Binding Created (detection)", URL: "https://www.elastic.co/guide/en/security/8.19/kubernetes-cluster-admin-role-binding-created.html"},
			{Title: "Google Cloud — Best practices for GKE RBAC", URL: "https://cloud.google.com/kubernetes-engine/docs/best-practices/rbac"},
			refRBACGoodPractices,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1078_004, mitreT1548},
	}
}

// contentPrivesc012 — nodes/proxy (KUBE-PRIVESC-012).
func contentPrivesc012(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	// nodes is cluster-scoped; report scope as cluster regardless of ruleNamespace value.
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide kubelet API on every node (nodes is cluster-scoped)",
	}
	return ruleContent{
		Title: fmt.Sprintf("`get nodes/proxy` enables kubelet exec via API server (`%s`)", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `get` `nodes/proxy` via %s → %s. Despite the read-only-sounding `get` verb, this permission lets the holder execute arbitrary commands inside any pod on any node by tunneling through the API server to the kubelet's internal HTTP API: `/exec`, `/run`, `/attach`, `/portforward`.\n\n"+
			"The technical root cause: pod exec uses an HTTP-to-WebSocket upgrade. The API server authorizes the upgrade based on the initial GET against the proxy subresource, not against `pods/exec`. So a subject with `get nodes/proxy` can issue `kubectl get --raw '/api/v1/nodes/<node>/proxy/exec/...'` and end up with an interactive shell in any container, even with no `pods/exec` permission anywhere.\n\n"+
			"Worse, the resulting commands execute over a direct API-server-to-kubelet WebSocket and are NOT recorded in apiserver audit logs at the `objectRef/verb` granularity. The audit log shows only the proxy GET. Detection requires node-level eBPF/process monitoring (Falco, Tetragon, KubeArmor), not API-server logs alone. Kubernetes issue #119640 and Stream Security have published proof-of-concept exploits.",
			subjectKey(subject), sourceBinding, sourceRole),
		Impact: "Cluster-wide remote code execution: exec into any container on any node via the kubelet API, with execution invisible to standard apiserver audit logs.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("get", "nodes/proxy", "", subject)),
			"They list nodes (`kubectl get nodes`) and pick a high-value one, typically a control-plane node or any node hosting `kube-apiserver/etcd`/operator pods.",
			"They issue an exec request via the proxy endpoint, e.g. `kubectl get --raw '/api/v1/nodes/<node>/proxy/run/kube-system/<pod>/<container>?cmd=id'`, or open a WebSocket to `/exec`.",
			"They land in the target container with that container's privileges (host-mounts, capabilities, ServiceAccount token).",
			"From a control-plane container they read `/etc/kubernetes/pki/admin.conf` for cluster-admin credentials. The entire chain leaves no `pods/exec` audit entries.",
		},
		Remediation: "Remove `nodes/proxy` from this subject; reserve it for the API server itself and a tiny set of trusted operators that document this need.",
		RemediationSteps: []string{
			"Remove the rule entirely. Application workloads never need `nodes/proxy`; Kubernetes documents this as a 'severe escalation hazard' in RBAC Good Practices.",
			"If a monitoring/observability stack genuinely requires it, migrate to the `nodes/metrics` and `nodes/stats` subresources, which expose telemetry without the exec endpoints.",
			"Deploy node-level runtime monitoring (Falco, Tetragon, KubeArmor) to detect kubelet `/exec`, `/run`, `/attach` usage at the kernel level.",
			fmt.Sprintf("Verify with `%s` returning `no`. Test the high-impact case with `kubectl get --raw '/api/v1/nodes/<node>/proxy/run/...'` returning 403.", kubectlAuthCanI("get", "nodes/proxy", "", subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: nodes/proxy escalation hazard", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#escalation"},
			{Title: "kubernetes/kubernetes #119640 — Privilege escalation via nodes/proxy", URL: "https://github.com/kubernetes/kubernetes/issues/119640"},
			{Title: "Aqua Security — Privilege Escalation from Node/Proxy Rights", URL: "https://www.aquasec.com/blog/privilege-escalation-kubernetes-rbac/"},
			{Title: "Stream Security — Invisible Kubernetes RCE: Why Nodes/Proxy GET is More Dangerous Than You Think", URL: "https://www.stream.security/post/invisible-kubernetes-rec-why-nodes-proxy-get-is-more-dangerous-than-you-think"},
			{Title: "Graham Helton — Kubernetes RCE Via Nodes/Proxy GET", URL: "https://grahamhelton.com/blog/nodes-proxy-rce"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1609, mitreT1611, mitreT1078_004, mitreT1610},
	}
}

// csrMintGrants describes the RBAC halves behind a KUBE-PRIVESC-011 finding: the two
// `certificatesigningrequests` grants that are always required, plus the signer half
// the CertificateApproval admission plugin has additionally required since 1.19.
// SignerApprove is empty in the common case, which is what tells the copy (and the
// severity) that the approval would currently be rejected by that plugin.
type csrMintGrants struct {
	CreateBinding  string
	CreateRole     string
	ApproveBinding string
	ApproveRole    string
	SignerApprove  []string
	SignerBinding  string
	SignerRole     string
}

// contentPrivesc011 — CSR mint via create + self-approve (KUBE-PRIVESC-011).
//
// Detection requires correlating two separate cluster-scoped rules on the same
// subject: `create certificatesigningrequests` AND `update/patch
// certificatesigningrequests/approval`. Held together, the subject can submit a
// CSR claiming any identity it likes and self-approve it; the CA-signed client
// cert then authenticates as that identity.
//
// The identity to claim is the part most write-ups get wrong today. `O=system:masters`
// is the famous version and it is the one modern clusters block: the
// CertificateSubjectRestriction admission plugin (on by default since 1.19) rejects
// any CSR for the `kubernetes.io/kube-apiserver-client` signer that names
// `system:masters` as an Organization. Nothing restricts the Common Name, though, and
// the apiserver's x509 authenticator maps CN straight onto the username it authorizes.
// Kubernetes itself never issues a certificate to a ServiceAccount, but it also never
// checks who an identity "should" be, so a cert with
// `CN=system:serviceaccount:kube-system:<sa>` authenticates as that ServiceAccount and
// inherits its bindings. That variant is unrestricted, and it is why the copy below
// leads with it rather than with system:masters.
//
// Sources: Kubernetes RBAC Good Practices ("Privilege Escalation Risks"
// section: "anyone able to create/issue CertificateSigningRequests"), Rory
// McCune (Aqua Security) CSR writeup, kube-apiserver client cert flow docs,
// the CertificateSubjectRestriction / CertificateApproval admission plugin reference.
func contentPrivesc011(subject models.SubjectRef, grants csrMintGrants) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: CertificateSigningRequests are a cluster-scoped resource and approval applies cluster-wide",
	}

	// The signer half decides whether this is a live path or a latent one, so it
	// changes the title, the last paragraph, and the confirmation step rather than
	// being tacked on as a footnote.
	signerNote := "The subject does NOT currently hold `approve` on any signer, which is the second gate: since 1.19 the CertificateApproval admission plugin rejects an approval unless the approver holds the `approve` verb on the CSR's `signers` resource. On a cluster running the default plugin set the approval step therefore fails today, and this grant is a latent escalation: it becomes live the moment anyone adds the signer verb, or the plugin is disabled (`--disable-admission-plugins=CertificateApproval`), or the subject finds a signer it is allowed to approve for."
	signerTitle := "(latent: no `approve` on any signer yet)"
	if len(grants.SignerApprove) > 0 {
		signerNote = fmt.Sprintf("The subject ALSO holds `approve` on %s (via %s → %s), which is the second gate the CertificateApproval admission plugin enforces since 1.19. Both gates the apiserver checks are therefore already satisfied: nothing stands between this subject and a signed client certificate for an identity of its choosing.", strings.Join(quoteEach(grants.SignerApprove), ", "), grants.SignerBinding, grants.SignerRole)
		signerTitle = "(fully enforced-authorized: also holds `approve` on the signer)"
	}

	return ruleContent{
		Title: fmt.Sprintf("CSR create + approve mints a client cert for any identity on `%s` %s", subjectKey(subject), signerTitle),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can both `create` `certificatesigningrequests` (via %s → %s) and `update/patch` the `certificatesigningrequests/approval` subresource (via %s → %s). Held together, those two verbs turn the certificates API into an identity vending machine.\n\n"+
			"The mechanism: a CertificateSigningRequest carries an x509 CSR whose Subject DN is chosen by whoever submits it. The kube-apiserver's client-cert authenticator treats the Common Name as the `User` and each Organization as a `Group`, and it applies that mapping to any certificate signed by a CA in `--client-ca-file` — it never asks whether the identity in the cert is one Kubernetes would have issued. Kubernetes never issues a certificate to a ServiceAccount, but a cert with `CN=system:serviceaccount:kube-system:<sa>` authenticates as exactly that ServiceAccount and inherits every binding it has.\n\n"+
			"Note which claim actually works. `O=system:masters` (the group the apiserver hard-codes as cluster-admin) is the textbook version and it is the one modern clusters block: the CertificateSubjectRestriction admission plugin, on by default since 1.19, rejects any `kubernetes.io/kube-apiserver-client` CSR naming `system:masters` as an Organization. Nothing restricts the CN, so the working route is to claim a privileged existing identity — a kube-system ServiceAccount such as `clusterrole-aggregation-controller` (which holds `escalate` on ClusterRoles), a control-plane user like `system:kube-controller-manager`, or `O=system:nodes` for a node identity. An operator who tests only the system:masters form will wrongly conclude this finding is not exploitable.\n\n"+
			"%s\n\n"+
			"The Kubernetes project flags the underlying grant in `RBAC Good Practices`: 'Anyone with full control over the CertificateSigningRequest API, including the ability to approve CSRs, is effectively a Kubernetes cluster admin'. The issued cert survives RBAC binding revocation, has whatever validity period the signer applies (often a year), leaves no Secret behind to rotate, and Kubernetes has no revocation list — only a CA rotation invalidates it.",
			subjectKey(subject), grants.CreateBinding, grants.CreateRole, grants.ApproveBinding, grants.ApproveRole, signerNote),
		Impact: "Identity forgery via the certificates API: the subject can mint a CA-signed x509 client cert for any user, group, or ServiceAccount name it chooses (including privileged kube-system ServiceAccounts and control-plane users), then authenticate as that identity. The cert persists after the RBAC grant is revoked and cannot be revoked.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the two halves with `%s` and `%s`, and checks the signer gate with `kubectl auth can-i --list --as=%s | grep signers`.", kubectlAuthCanI("create", "certificatesigningrequests", "", subject), kubectlAuthCanI("update", "certificatesigningrequests/approval", "", subject), impersonationName(subject)),
			"They pick an identity worth stealing — `kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects[]?'` — typically a kube-system ServiceAccount or a control-plane user.",
			"They generate a key + CSR claiming it in the Common Name: `openssl req -new -newkey rsa:2048 -nodes -keyout steal.key -subj '/CN=system:serviceaccount:kube-system:clusterrole-aggregation-controller' -out steal.csr`. (They avoid `O=system:masters`: CertificateSubjectRestriction rejects that Organization for this signer.)",
			"They submit it against the `kubernetes.io/kube-apiserver-client` signer with `usages: [client auth]`: `kubectl apply -f csr.yaml`.",
			"They self-approve: `kubectl certificate approve <csr-name>`. The kube-controller-manager's signer issues the cert with the cluster CA.",
			"They extract it — `kubectl get csr <csr-name> -o jsonpath='{.status.certificate}' | base64 -d > steal.crt` — and use it: `kubectl --client-certificate=steal.crt --client-key=steal.key get secrets -A`, now authenticated as the impersonated ServiceAccount with all of its permissions.",
		},
		Remediation: "Split the halves across different subjects: never grant `create csr` and `update csr/approval` to the same identity. Approval belongs to the kube-controller-manager's auto-approver (for known signers) or a strict admin allowlist, and the `approve` verb on `signers` should be scoped to the one signerName that identity legitimately handles.",
		RemediationSteps: []string{
			"Audit who holds both verbs: `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.resources[]? | test(\"certificatesigningrequests\")) | {kind, name: .metadata.name, rules}'`.",
			fmt.Sprintf("Remove one half from %s. Application workloads almost never need either verb; CI/CD systems that issue dev certs typically need `create` but never `approval`.", subjectKey(subject)),
			"Keep the CertificateApproval and CertificateSubjectRestriction admission plugins enabled (they are default-on; confirm no `--disable-admission-plugins` entry on the apiserver removes them), and scope any legitimate `approve` grant with `resourceNames: [\"<the one signerName>\"]` on the `signers` resource.",
			"For legitimate auto-approval (kubelet bootstrap), use the built-in `system:kube-controller-manager` flow or a CSR controller with a tightly-scoped `signerName` (e.g. `kubernetes.io/kubelet-serving` only).",
			"Add a ValidatingAdmissionPolicy (or Kyverno) over CertificateSigningRequest creation that rejects Subject DNs claiming an identity the requester is not: `system:masters` in an Organization, any `system:serviceaccount:` or `system:node:` Common Name, and any CN naming a user bound to a privileged ClusterRole.",
			fmt.Sprintf("Verify the remediation with `%s` returning `no` for at least one of the two halves.", kubectlAuthCanI("update", "certificatesigningrequests/approval", "", subject)),
			"Check whether a cert was already issued: `kubectl get csr -o custom-columns=NAME:.metadata.name,SIGNER:.spec.signerName,REQUESTOR:.spec.username,APPROVED:.status.conditions[*].type`. Note the CSR cleaner deletes issued CSRs about an hour after issuance, so an empty list does not prove nothing was minted.",
			"Rotate the cluster CA if you suspect a cert was issued — Kubernetes has no CRL or OCSP, so an issued cert stays valid for its full lifetime and CA rotation is the only revocation.",
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: CertificateSigningRequest escalation", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#certificatesigningrequest"},
			{Title: "Kubernetes — Certificate Signing Requests (signers, approval, authorization)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/"},
			{Title: "Kubernetes — Authenticating: X509 client certificates (CN → user, O → group)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certificates"},
			{Title: "Kubernetes — Admission Controllers: CertificateApproval, CertificateSigning, CertificateSubjectRestriction", URL: "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#certificatesubjectrestriction"},
			{Title: "Rory McCune (Aqua) — Kubernetes CSR API for Privilege Escalation", URL: "https://www.aquasec.com/blog/kubernetes-rbac-privilige-escalation/"},
			refRBACGoodPractices,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1098_001, mitreT1078_004, mitreT1550},
	}
}

// csrSignGrants describes the two halves behind a KUBE-PRIVESC-024 finding: the
// `sign` grant on one or more apiserver-trusted signers, and the
// `certificatesigningrequests/status` write that carries the issued certificate.
type csrSignGrants struct {
	Signers       []string
	SignBinding   string
	SignRole      string
	StatusBinding string
	StatusRole    string
}

// contentPrivesc024 — signer control (KUBE-PRIVESC-024).
//
// This is the other half of the certificates API, and it bypasses approval entirely.
// `sign` on the virtual `signers` resource plus `update/patch` on
// `certificatesigningrequests/status` is exactly the pair Kubernetes documents for a
// signer implementation, and exactly what the CertificateSigning admission plugin
// checks when a status write populates `status.certificate`. Where -011 asks the
// cluster's signer to issue a cert, -024 IS the cluster's signer for that signerName.
//
// The honest caveat, stated in the copy: the RBAC grant designates the signer, but the
// certificate the holder writes back must chain to a CA in the apiserver's
// `--client-ca-file` to authenticate anyone. The identities that legitimately hold this
// grant hold such a key by definition (that is what makes them the signer), which is
// why the finding treats "a workload SA is authorized to sign apiserver client certs"
// as a tier-0 exposure rather than as a hypothetical.
func contentPrivesc024(subject models.SubjectRef, grants csrSignGrants) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: `signers` is a cluster-scoped virtual resource and an issued client certificate authenticates against every apiserver in the cluster",
	}
	signerList := strings.Join(quoteEach(grants.Signers), ", ")
	arbitrarySubject := slices.Contains(grants.Signers, permissions.SignerAPIServerClient)

	gain := "node identities: certificates from the kubelet signers carry `CN=system:node:<name>` / `O=system:nodes`, which the Node authorizer accepts for every Secret, ConfigMap, and Pod object bound to that node."
	if arbitrarySubject {
		gain = "any identity in the cluster: the `kubernetes.io/kube-apiserver-client` signer places no restriction on the Subject DN beyond the `system:masters` Organization that CertificateSubjectRestriction blocks, so a CN naming a privileged ServiceAccount (`system:serviceaccount:kube-system:<sa>`) or a control-plane user is issued without challenge."
	}

	return ruleContent{
		Title: fmt.Sprintf("Signer control: `%s` can sign client certificates for %s", subjectKey(subject), signerList),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s holds the `sign` verb on the `signers` resource covering %s (via %s → %s) together with `update/patch` on `certificatesigningrequests/status` (via %s → %s). That pair is not an approval bypass so much as an approval *irrelevance*: it is the exact authorization Kubernetes defines for a certificate signer, and the CertificateSigning admission plugin checks the `sign` verb when a status write populates `status.certificate`.\n\n"+
			"Where `KUBE-PRIVESC-011` asks the cluster's signer to issue a certificate (and therefore has to pass the approval gate), this subject IS the signer for those signerNames. It writes the issued certificate itself, so no `create`, no `/approval`, and no approver identity is involved anywhere in the chain.\n\n"+
			"What that yields is %s\n\n"+
			"One condition worth stating plainly, because it decides how urgent this is for your cluster: a certificate only authenticates if it chains to a CA in the apiserver's `--client-ca-file`. This RBAC grant designates the holder as the signer for those signerNames, and any real signer implementation holds that CA key — that is what being the signer means. So the question this finding puts in front of you is 'is this identity supposed to be a certificate authority for cluster identities?'. For the kube-controller-manager or a purpose-built signer controller the answer is yes; for an application ServiceAccount it never is, and compromising that workload hands over the cluster's identity issuance.",
			subjectKey(subject), signerList, grants.SignBinding, grants.SignRole, grants.StatusBinding, grants.StatusRole, gain),
		Impact: "Certificate issuance without approval: the subject is an authorized signer for identity-bearing certificates and writes issued certs directly onto CSR status. Combined with the signing CA key its role implies, it mints credentials for arbitrary identities that outlive every RBAC change and cannot be revoked.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the grant with `kubectl auth can-i --list --as=%s | grep -E 'signers|certificatesigningrequests/status'`.", impersonationName(subject)),
			"They locate the signing key the role implies: a projected Secret or hostPath in the workload's own pod spec (`kubectl get pod -o yaml | grep -A5 -i 'ca\\|tls\\|signer'`), or the controller-manager's `/etc/kubernetes/pki/ca.key` if the workload runs on a control-plane node.",
			"They submit a CSR for the signer they control, claiming a privileged identity in the CN (a kube-system ServiceAccount, or `system:node:<name>` for the kubelet signers).",
			"They sign it with the CA key and write the result back themselves: `kubectl patch csr <name> --subresource=status --type=merge -p '{\"status\":{\"certificate\":\"<base64 PEM>\"}}'`. No approver is consulted; the CertificateSigning plugin authorizes the write because they hold `sign` on that signerName.",
			"They authenticate with the issued cert: `kubectl --client-certificate=minted.crt --client-key=minted.key auth whoami` returns the forged identity.",
		},
		Remediation: "Reserve `sign` on apiserver-trusted signers for the control plane's own signer controller. If a third-party signer genuinely needs it, scope `resourceNames` to the one signerName it handles (never `kubernetes.io/kube-apiserver-client`, never a `kubernetes.io/*` or `*/*` wildcard) and run it as a dedicated identity with no other permissions.",
		RemediationSteps: []string{
			"Find every grant of the verb: `kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.resources[]?==\"signers\") and ((.verbs[]?==\"sign\") or (.verbs[]?==\"*\"))) | {name: .metadata.name, rules}'`.",
			fmt.Sprintf("Remove the `sign` grant from %s, or scope it with `resourceNames` to a custom signerName (`example.com/my-signer`) whose CA is NOT in the apiserver's `--client-ca-file`. A cert from a CA the apiserver does not trust as a client CA authenticates no one.", subjectKey(subject)),
			"Drop `update`/`patch` on `certificatesigningrequests/status` from any identity that is not a signer controller: without the status write, the `sign` verb issues nothing.",
			"Confirm the apiserver's `--client-ca-file` bundle contains only CAs you intend to be identity authorities, and that no third-party signer's CA was added to it for convenience.",
			"Audit what was already issued: `kubectl get csr -o custom-columns=NAME:.metadata.name,SIGNER:.spec.signerName,REQUESTOR:.spec.username,ISSUED:.status.certificate` (the CSR cleaner removes issued CSRs about an hour after issuance, so treat an empty list as inconclusive).",
			"Rotate the cluster CA if you suspect misuse — there is no revocation path for an issued Kubernetes client certificate.",
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — CSR: signer authorization (`sign` on `signers`)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#authorization"},
			{Title: "Kubernetes — CSR: signers and their trust distribution", URL: "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#signers"},
			{Title: "Kubernetes — Admission Controllers: CertificateSigning", URL: "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#certificatesigning"},
			{Title: "Kubernetes — Authenticating: X509 client certificates (CN → user, O → group)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certificates"},
			refRBACGoodPractices,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1098_001, mitreT1078_004, mitreT1550},
	}
}

// quoteEach wraps each value in backticks for inline rendering in finding prose.
func quoteEach(values []string) []string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, "`"+v+"`")
	}
	return quoted
}

// impersonationName renders the --as= value for a subject: ServiceAccounts
// authenticate as `system:serviceaccount:<ns>:<name>`, other subject kinds as their
// bare name. kubectlAuthCanI deliberately uses the bare name for its shorter output;
// the CSR scenarios need the full form because the same string doubles as the
// Common Name an attacker would claim.
func impersonationName(subject models.SubjectRef) string {
	if subject.Kind == "ServiceAccount" {
		return fmt.Sprintf("system:serviceaccount:%s:%s", subject.Namespace, subject.Name)
	}
	return subject.Name
}

// contentPrivesc014 — serviceaccounts/token create (KUBE-PRIVESC-014).
func contentPrivesc014(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `create serviceaccounts/token` enables token minting (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` on the `serviceaccounts/token` subresource via %s → %s. %s.\n\n"+
			"The TokenRequest API (Kubernetes 1.22+) is the canonical way to mint a JWT ServiceAccount token, and its `create` verb is gated by RBAC on the `serviceaccounts/token` subresource. Anyone holding this verb on a ServiceAccount can mint a token authenticated as that ServiceAccount.\n\n"+
			"Datadog Security Labs published a write-up on its abuse for persistence: an attacker mints a long-lived token for the highest-privileged ServiceAccount they can reach (commonly `kube-system/clusterrole-aggregation-controller`, which holds `escalate` on ClusterRoles), and uses that token as a backdoor that survives the original RBAC binding being removed. Crucially, this verb is NOT covered by 'list secrets' detections. TokenRequest tokens are NOT stored as Secret objects; they're issued live by the apiserver and never leave a footprint on disk.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Mint a JWT for any ServiceAccount in %s. Cluster-wide variant trivially yields cluster-admin (mint a kube-system controller token). Tokens persist after the original binding is revoked.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("create", "serviceaccounts/token", ruleNamespace, subject)),
			"They enumerate high-privilege ServiceAccounts: `kubectl get clusterrolebindings -o json | jq '.items[].subjects[]?.name'` and pick one with `cluster-admin`, `system:masters`, or aggregated permissions.",
			"They mint a long-lived token via the TokenRequest API: `kubectl create token <sa-name> -n <ns> --duration=8760h` (1 year), or call `/api/v1/namespaces/<ns>/serviceaccounts/<sa>/token` directly.",
			"They `kubectl --token=<jwt> get nodes` and confirm the new identity.",
			"They cache the token off-cluster as a backdoor: rotating the original binding does NOT invalidate an issued token until its `exp` claim, which defaults to `--service-account-max-token-expiration` (often 1 year on legacy clusters).",
		},
		Remediation: "Remove `create` on `serviceaccounts/token` from non-control-plane identities; constrain any legitimate use with `resourceNames` to a tiny allowlist.",
		RemediationSteps: []string{
			"Remove the verb. Outside `kube-controller-manager` and a small set of token-broker components, nothing should hold this.",
			"If a workload genuinely needs to mint tokens, scope with `resourceNames` to the exact ServiceAccounts it issues tokens for, never `*`.",
			"Enforce a low maximum token expiration cluster-wide via `--service-account-max-token-expiration=1h` on the API server (or the cloud equivalent).",
			"Capture every `create` on `serviceaccounts/token` at `RequestResponse` audit level and SIEM-alert on issuance to ServiceAccounts with `cluster-admin/escalate/bind` rights.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "serviceaccounts/token", "kube-system", subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Service Accounts (TokenRequest API)", URL: "https://kubernetes.io/docs/concepts/security/service-accounts/"},
			{Title: "Kubernetes — Managing Service Accounts (admin)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/"},
			{Title: "Datadog Security Labs — Persistence via the TokenRequest API", URL: "https://securitylabs.datadoghq.com/articles/kubernetes-tokenrequest-api/"},
			{Title: "Kubernetes API — TokenRequest v1", URL: "https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/"},
			refRBACGoodPractices,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098_001, mitreT1528, mitreT1078_004},
	}
}

// contentPrivesc004 — Pod exec / attach (KUBE-PRIVESC-004).
func contentPrivesc004(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `pods/exec` access enables token theft from running pods (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create`/`get` the `pods/exec` (or `pods/attach`) subresource via %s → %s. %s.\n\n"+
			"Exec opens an interactive process inside an already-running container. Unlike pod creation, the attacker does not choose the ServiceAccount: they inherit whatever identity the target pod already runs as. In a shared namespace that frequently includes a pod backed by a high-privilege ServiceAccount (a controller, an operator, a CI runner), so exec becomes a credential-theft primitive: read `/var/run/secrets/kubernetes.io/serviceaccount/token` from inside the container and replay it.\n\n"+
			"If the target container is itself privileged, runs as root, or mounts the host, exec is also a direct node-escape path. The permission is doubly dangerous because it leaves a thin audit trail (the exec stream is a single API call) and is commonly granted by `edit`-style roles that operators assume are harmless.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Run commands inside any running pod in %s, inheriting that pod's ServiceAccount token (and host access if the pod is privileged). A common path to a control-plane-adjacent SA token.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("create", "pods/exec", ruleNamespace, subject)),
			"They enumerate running pods and their ServiceAccounts: `kubectl get pods -o custom-columns=NAME:.metadata.name,SA:.spec.serviceAccountName` and pick a pod with a privileged SA.",
			"They exec in: `kubectl exec -it <pod> -- /bin/sh` (or open the raw `pods/exec` WebSocket directly).",
			"They read the mounted token (`cat /var/run/secrets/kubernetes.io/serviceaccount/token`) and replay it against the API server as that ServiceAccount.",
			"If the container is privileged or mounts the host, they instead break out to the node and harvest the kubelet credentials.",
		},
		Remediation: "Remove `create`/`get` on `pods/exec` and `pods/attach` from non-operator identities; gate any legitimate debug access behind a break-glass workflow.",
		RemediationSteps: []string{
			"Audit who holds exec rights: `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.resources[]? | test(\"pods/(exec|attach)\"))'`. Most application identities should have none.",
			"Remove the verbs. For interactive debugging, prefer `kubectl debug` gated by a JIT/break-glass role granted only for the duration of an incident.",
			"Pin sensitive workloads to dedicated, least-privilege ServiceAccounts so an exec into a co-tenant pod does not yield a powerful token.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "pods/exec", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: pods/exec", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#pod-exec"},
			{Title: "Kubernetes — Get a Shell to a Running Container", URL: "https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1609, mitreT1552_007, mitreT1611, mitreT1078_004},
	}
}

// contentPrivesc006 — Secret read via get (KUBE-PRIVESC-006). The broader
// `list`/`watch` enumerate-everything case is KUBE-PRIVESC-005.
func contentPrivesc006(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `get` access to Secrets on `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `get` core `secrets` via %s → %s. %s.\n\n"+
			"`get` returns the full Secret object, including the base64-encoded `data` payload, for any Secret whose name the caller knows. It is narrower than `list`/`watch` (KUBE-PRIVESC-005), which dump every Secret in scope without needing names, but in practice Secret names are highly guessable (`<app>-tls`, `<app>-db`, `default-token-*`, registry pull secrets) and are often discoverable from pod specs, so `get` alone routinely exposes ServiceAccount tokens, TLS keys, and database credentials.\n\n"+
			"Cluster-wide `get` reaches `kube-system` ServiceAccount token Secrets, which are commonly cluster-admin-equivalent.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("%s read of any named Secret (ServiceAccount tokens, TLS keys, registry credentials), enabling identity replay once the attacker knows or guesses a Secret name.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker reaches %s and confirms the verb with `%s`.", subjectKey(subject), kubectlAuthCanI("get", "secrets", ruleNamespace, subject)),
			"They recover Secret names from pod specs they can read, from naming conventions, or from default token patterns.",
			"They `kubectl get secret <name> -o yaml` and base64-decode the `data` fields.",
			"They replay the highest-privileged token (e.g. a kube-system controller SA) against the API server.",
			"They pivot to cloud APIs using extracted IRSA / Workload Identity credentials, or persist via a backdoor binding.",
		},
		Remediation: "Scope `get` on `secrets` by `resourceNames` to the exact Secret(s) the workload needs, or remove it entirely if Secrets are consumed via volume/env injection.",
		RemediationSteps: []string{
			"Confirm the workload needs API-time Secret access. Most apps consume Secrets via volume/env injection at pod start and don't need RBAC read.",
			"If runtime access is required, scope the rule by `resourceNames` to the exact Secret name(s). Never grant `get` on all secrets.",
			"Move the binding from cluster-wide to namespace-scoped so the blast radius is bounded.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("get", "secrets", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Good practices for Kubernetes Secrets", URL: "https://kubernetes.io/docs/concepts/security/secrets-good-practices/"},
			{Title: "Kubernetes — RBAC Good Practices: Secrets read", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#secrets"},
			{Title: "Kubernetes — Encryption at Rest (KMS provider)", URL: "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_007, mitreT1528, mitreT1078_004},
	}
}

// contentPrivesc013 — Ephemeral container injection (KUBE-PRIVESC-013).
func contentPrivesc013(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s ephemeral-container injection enables takeover of running pods (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `update`/`patch` the `pods/ephemeralcontainers` subresource via %s → %s. %s.\n\n"+
			"Ephemeral containers (the engine behind `kubectl debug`) are added to an already-running pod. The injected container joins the target pod's namespaces and, crucially, can mount the pod's ServiceAccount token and (with `shareProcessNamespace` or `targetContainerName`) inspect the other containers' processes and memory. It is functionally pod creation against an existing victim: the attacker chooses the image and command but inherits the victim pod's identity and host exposure.\n\n"+
			"Because the parent pod is already scheduled and admitted, ephemeral-container injection can sidestep some admission paths that only fire on pod create, making it a quieter alternative to `pods/exec` for stealing a privileged pod's token.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Inject an attacker-controlled container into any running pod in %s, inheriting that pod's ServiceAccount token, namespaces, and host mounts.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("patch", "pods/ephemeralcontainers", ruleNamespace, subject)),
			"They pick a running pod backed by a privileged ServiceAccount (or one that mounts the host).",
			"They inject a debug container: `kubectl debug -it <pod> --image=alpine --target=<container>`.",
			"From the injected container they read the mounted SA token, or `nsenter` into the target container's namespaces.",
			"They replay the stolen token, or escape to the node if the parent pod is privileged.",
		},
		Remediation: "Remove `update`/`patch` on `pods/ephemeralcontainers` from non-operator identities; gate debugging behind a break-glass role.",
		RemediationSteps: []string{
			"Audit who can inject ephemeral containers: `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.resources[]? | test(\"pods/ephemeralcontainers\"))'`.",
			"Remove the verbs. Reserve ephemeral-container debugging for a JIT/break-glass role granted only during incidents.",
			"Pin sensitive workloads to dedicated least-privilege ServiceAccounts so an injected container does not yield a powerful token.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("patch", "pods/ephemeralcontainers", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Ephemeral Containers", URL: "https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/"},
			{Title: "Kubernetes — Debug Running Pods", URL: "https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1609, mitreT1611, mitreT1552_007},
	}
}

// contentPrivesc015 — Port-forward to internal services (KUBE-PRIVESC-015).
func contentPrivesc015(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `pods/portforward` access tunnels to internal services (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` the `pods/portforward` subresource via %s → %s. %s.\n\n"+
			"Port-forward opens a tunnel from the attacker's machine, through the API server and kubelet, to an arbitrary TCP port on a target pod. It bypasses NetworkPolicy, Service-level access controls, and any ingress restriction, because the traffic rides the kubelet's streaming channel rather than the pod network. Anything the pod can reach on `localhost` (an admin port, an unauthenticated debug endpoint, a sidecar) becomes reachable by the holder.\n\n"+
			"This is primarily a lateral-movement and data-access primitive rather than a direct RBAC escalation: it gives network reach to internal services (databases, message queues, metadata proxies, the API of another component) that were assumed to be cluster-internal.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Reach any TCP port on any pod in %s from outside the cluster network, bypassing NetworkPolicy and Service controls (internal databases, admin consoles, sidecar APIs).", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb with `%s`.", kubectlAuthCanI("create", "pods/portforward", ruleNamespace, subject)),
			"They identify a target pod exposing a sensitive port on localhost (a database, an unauthenticated admin endpoint, a metadata proxy).",
			"They open a tunnel: `kubectl port-forward pod/<target> 5432:5432`.",
			"They connect to `localhost:5432` and interact with the internal service directly, with no NetworkPolicy in the path.",
			"They exfiltrate data or pivot deeper using credentials harvested from the exposed service.",
		},
		Remediation: "Remove `create` on `pods/portforward` from application identities; reserve it for a small operator group and enforce NetworkPolicy on sensitive workloads regardless.",
		RemediationSteps: []string{
			"Audit who holds port-forward rights: `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.resources[]? | test(\"pods/portforward\"))'`.",
			"Remove the verb from application/CI identities. Port-forward is a human-debugging convenience, not a workload permission.",
			"Add authentication to internal services (do not rely on network position) and enforce NetworkPolicy so a tunnel into one pod does not expose the whole namespace.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "pods/portforward", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Use Port Forwarding to Access Applications in a Cluster", URL: "https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/"},
			{Title: "Kubernetes — RBAC Good Practices", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1090, mitreT1613, mitreT1078_004},
	}
}

// contentPrivesc002 — Pod create + escape via permissive Pod Security Admission
// (KUBE-PRIVESC-002). permissiveTarget describes where privileged pods are
// admissible: a specific namespace, or "any namespace" for a cluster-scoped grant.
func contentPrivesc002(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole, permissiveTarget string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s pod creation can launch a privileged pod and escape to the node (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` pods via %s → %s, and %s does not enforce a Pod Security Admission level that blocks privileged pods. %s.\n\n"+
			"RBAC never inspects the contents of a pod, only the `create` verb. When the target namespace has no `pod-security.kubernetes.io/enforce` label (or it is set to `privileged`), nothing at admission stops the attacker from creating a pod with `privileged: true`, `hostPID: true`, `hostNetwork: true`, or a `hostPath` mount of `/`. From inside that pod, breaking out to the node is trivial (`nsenter` into PID 1, read `/etc/kubernetes/pki`, steal the kubelet client cert).\n\n"+
			"This is the difference between KUBE-PRIVESC-001 (pod create → steal another SA's token) and this finding: here the missing Pod Security backstop turns pod-create into full node compromise. Baseline or Restricted enforcement would block the privileged pod and downgrade the risk to token theft alone.",
			subjectKey(subject), sourceBinding, sourceRole, permissiveTarget, scope.Detail),
		Impact: "Create a privileged / host-mounting pod and escape to the underlying node, then harvest every pod's token and the kubelet credentials on that node.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms pod-create with `%s` and notes the target namespace has no restrictive Pod Security `enforce` label.", kubectlAuthCanI("create", "pods", ruleNamespace, subject)),
			"They craft a pod with `securityContext.privileged: true`, `hostPID: true`, and a `hostPath` volume mounting `/`.",
			"They `kubectl apply` the pod; Pod Security Admission does not reject it because the namespace is unlabelled or set to `privileged`.",
			"They exec in and `nsenter -t 1 -m -u -i -n -p -- /bin/sh` to land a root shell on the node.",
			"They read `/var/lib/kubelet/pki/kubelet-client-current.pem` and `/etc/kubernetes/pki/*`, then pivot to the control plane.",
		},
		Remediation: "Enforce the Restricted (or at least Baseline) Pod Security Standard on the namespace, and remove direct pod-create from non-platform identities.",
		RemediationSteps: []string{
			"Label the namespace to enforce Pod Security: `kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted`. Baseline blocks privileged/hostPath/host namespaces; Restricted additionally requires non-root and seccomp.",
			"Replace direct `create` on `pods` with `create/update` on workload controllers routed through CI/CD, so a controller (not the attacker) creates the pod.",
			"Add a Kyverno/Gatekeeper/ValidatingAdmissionPolicy that rejects `privileged`, `hostPID`, `hostNetwork`, and sensitive `hostPath` mounts outside an explicit allowlist, as defence in depth behind PSA.",
			fmt.Sprintf("Verify by attempting to create a privileged pod as the subject and confirming admission rejects it, and that `%s` returns `no` for application identities.", kubectlAuthCanI("create", "pods", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
			{Title: "Kubernetes — Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
			{Title: "Bishop Fox — Bad Pods: Pod Privilege Escalation", URL: "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1611, mitreT1078_004},
	}
}

// contentPrivesc007 — Secret-creation token theft (KUBE-PRIVESC-007). Detection
// correlates `create` and `get` on secrets held by the same subject; the
// builder takes both halves' binding/role refs for the prose.
func contentPrivesc007(ruleNamespace string, subject models.SubjectRef, createBinding, createRole, getBinding, getRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `create`+`get` on Secrets mints a ServiceAccount token (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can both `create` Secrets (via %s → %s) and `get` Secrets (via %s → %s). %s.\n\n"+
			"Held together, these two verbs reconstruct the legacy ServiceAccount-token minting primitive. The attacker creates a Secret of type `kubernetes.io/service-account-token` annotated with `kubernetes.io/service-account.name: <target-sa>`. The token controller observes the new Secret and populates its `data.token` field with a valid, long-lived JWT for that ServiceAccount. The attacker then `get`s the Secret back and reads the minted token.\n\n"+
			"This sidesteps the TokenRequest API gating (KUBE-PRIVESC-014): no `serviceaccounts/token` permission is required. By targeting a privileged SA (a kube-system controller, or any SA bound to a powerful ClusterRole), the attacker obtains that SA's identity. The token is a non-expiring secret-backed token, so it persists until the Secret is deleted.",
			subjectKey(subject), createBinding, createRole, getBinding, getRole, scope.Detail),
		Impact: fmt.Sprintf("Mint and read a long-lived token for any ServiceAccount in %s by creating a token-type Secret and reading the controller-populated value: a persistence-friendly alternative to the TokenRequest API.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms both verbs with `%s` and `%s`.", kubectlAuthCanI("create", "secrets", ruleNamespace, subject), kubectlAuthCanI("get", "secrets", ruleNamespace, subject)),
			"They pick a privileged target ServiceAccount (e.g. one bound to a powerful ClusterRole).",
			"They create a Secret of type `kubernetes.io/service-account-token` annotated with `kubernetes.io/service-account.name: <target-sa>`.",
			"The token controller fills in `data.token`; the attacker `get`s the Secret and base64-decodes the JWT.",
			"They replay the token as the target ServiceAccount. The token is secret-backed and does not expire, surviving RBAC remediation until the Secret is deleted.",
		},
		Remediation: "Do not grant `create` and `get` on `secrets` to the same subject; scope each by `resourceNames` and disable legacy token-Secret auto-population where possible.",
		RemediationSteps: []string{
			"Split the two verbs across different identities, or remove one. Application workloads rarely need to create Secrets at runtime.",
			"If Secret creation is required, scope it by `resourceNames` and never pair it with broad `get` on secrets.",
			"Prefer bound TokenRequest tokens over legacy token Secrets; on modern clusters, avoid manually creating `kubernetes.io/service-account-token` Secrets.",
			"Audit existing token Secrets: `kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token` and remove any that are not expected.",
			fmt.Sprintf("Verify with `%s` returning `no` for at least one of the two verbs.", kubectlAuthCanI("create", "secrets", ruleNamespace, subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Manage Service Account Tokens (legacy token Secrets)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#manual-secret-management-for-serviceaccounts"},
			{Title: "Kubernetes — RBAC Good Practices: Secrets", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#secrets"},
			{Title: "Datadog Security Labs — Persistence via the TokenRequest API", URL: "https://securitylabs.datadoghq.com/articles/kubernetes-tokenrequest-api/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098_001, mitreT1528, mitreT1552_007},
	}
}

// contentPrivesc016 — Node-status / delete-pod migration (KUBE-PRIVESC-016).
// Detection correlates `delete pods` with cluster-scoped node manipulation
// (`update`/`patch nodes/status` or `delete nodes`); nodeAction names which
// node primitive was found.
func contentPrivesc016(subject models.SubjectRef, podsBinding, podsRole, nodeBinding, nodeRole, nodeAction string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: nodes and their scheduling are cluster-scoped resources",
	}
	return ruleContent{
		Title: fmt.Sprintf("Delete-pods + node manipulation can migrate workloads onto an attacker node (`%s`)", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `delete` pods (via %s → %s) and also `%s` (via %s → %s). %s.\n\n"+
			"Combined, these let an attacker steer where high-value pods run. By cordoning or tainting nodes (through `nodes/status` updates) or deleting nodes outright, then deleting the target pods, the attacker forces the scheduler to relocate those pods. If the attacker controls (or can compromise) the remaining schedulable node, a sensitive pod (a controller, a pod with a privileged ServiceAccount, a pod that mounts secrets) lands where they can exec into it, read its mounted token, or sniff its traffic.\n\n"+
			"This is an indirect, scheduling-level escalation: neither verb reads a Secret or binds a role directly, but together they break the assumption that a workload stays on a trusted node. It is most dangerous in clusters with a mix of trusted and lower-trust nodes (spot/burst pools, tenant-dedicated nodes).",
			subjectKey(subject), podsBinding, podsRole, nodeAction, nodeBinding, nodeRole, scope.Detail),
		Impact: "Relocate sensitive pods onto a node the attacker controls by manipulating node scheduling and evicting pods, then steal those pods' tokens or traffic from the node.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms both halves with `%s` and `%s`.", kubectlAuthCanI("delete", "pods", "", subject), kubectlAuthCanI(strings.Fields(nodeAction)[0], lastField(nodeAction), "", subject)),
			"They cordon or taint every node except one they control (`kubectl patch node <n> --subresource=status ...`), or delete the nodes outright.",
			"They `kubectl delete pod <target>` for a sensitive pod, forcing the controller to reschedule it.",
			"The scheduler places the replacement pod on the attacker-controlled node.",
			"They exec into / inspect the relocated pod from the node, harvesting its ServiceAccount token and any mounted secrets.",
		},
		Remediation: "Split `delete pods` from node-scheduling verbs across identities; reserve `nodes/status` writes and `delete nodes` for the control plane and cluster-autoscaler.",
		RemediationSteps: []string{
			"Remove `update`/`patch` on `nodes/status` and `delete` on `nodes` from application/operator identities. These belong to the kube-controller-manager and the autoscaler.",
			"Restrict `delete pods` to controllers and platform automation; application identities should manage workloads through their owning controller, not by deleting pods.",
			"Pin sensitive workloads to trusted nodes with `nodeSelector`/`nodeAffinity` + taints, so eviction cannot relocate them onto untrusted nodes.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("delete", "nodes", "", subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Safely Drain a Node", URL: "https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/"},
			{Title: "Kubernetes — Taints and Tolerations", URL: "https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/"},
			{Title: "Kubernetes — RBAC Good Practices", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1611, mitreT1078_004},
	}
}

// contentPrivesc019 is the mutating admission policy injection finding (KUBE-PRIVESC-019).
//
// A MutatingAdmissionPolicy is the webhookless, CEL/JSONPatch counterpart of a
// mutating admission webhook (GA in Kubernetes v1.36). Its mutation logic lives in
// etcd and runs in-process in the apiserver, so unlike a webhook there is no external
// endpoint, TLS cert, or backing Deployment to find. A subject that can write both the
// policy and a binding for it can rewrite every future admission request: inject
// privileged, a hostPath, or a sidecar into pods cluster-wide.
//
// The honest caveat, stated in the copy: mutating admission runs BEFORE validating
// admission, and Pod Security Admission is a validating plugin. So an injected
// privileged pod is still checked by PSA and is rejected in a namespace that enforces
// baseline or restricted. The injection therefore lands in a namespace PSA does not
// restrict (an unlabeled namespace, or a privileged-labelled one such as most clusters'
// kube-system), which is why the privesc graph gates its mutating_policy_inject edge on
// at least one such namespace existing.
func contentPrivesc019(subject models.SubjectRef, policyBinding, policyRole, bindingBinding, bindingRole string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: MutatingAdmissionPolicies and their bindings are cluster-scoped and rewrite admission for every matching request across the cluster",
	}
	return ruleContent{
		Title: fmt.Sprintf("Mutating admission policy injection: `%s` can rewrite every admitted object", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can write `mutatingadmissionpolicies` (via %s : %s) and `mutatingadmissionpolicybindings` (via %s : %s). A `MutatingAdmissionPolicy` is the in-tree, webhookless equivalent of a mutating admission webhook (GA in Kubernetes v1.36): its CEL / JSONPatch / ApplyConfiguration mutation is stored in etcd and executed in-process by the apiserver, so there is no external endpoint, no serving certificate, and no backing Deployment, only the policy object and a binding that activates it.\n\n"+
			"With write access to both, the subject authors a mutation that matches `pods` on CREATE and injects `securityContext.privileged: true`, a `hostPath` volume mounting the node root, or an extra container, then binds it. Every pod created afterwards, by any workload, controller, or user, is silently rewritten before it is persisted. One privileged pod on a node is a host escape, and from a control-plane node that is the cluster CA and every token.\n\n"+
			"Both halves are load-bearing, which is why this finding requires them together: a policy with no binding never executes, and a binding pointing at no attacker-controlled policy mutates nothing. This mirrors `KUBE-PRIVESC-010`, where a binding write escalates only alongside the `bind` verb.\n\n"+
			"One ordering detail decides where the injected pod can land, and the finding does not overstate it: mutating admission runs before validating admission, and Pod Security Admission is a validating plugin, so an injected `privileged` pod is still rejected by PSA in a namespace that enforces `baseline` or `restricted`. The mutation therefore targets a namespace PSA does not restrict (an unlabeled namespace, or a `privileged`-labelled one such as `kube-system`), which every real cluster has at least one of.",
			subjectKey(subject), policyBinding, policyRole, bindingBinding, bindingRole),
		Impact: "Cluster-wide admission-time object rewriting. The subject injects privileged settings, host mounts, or sidecars into every future pod, defeating pod-hardening for all workloads at once and reaching node, then control-plane, compromise, with no webhook or external infrastructure to detect.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms both halves with `%s` and `%s`.", kubectlAuthCanI("create", "mutatingadmissionpolicies", "", subject), kubectlAuthCanI("create", "mutatingadmissionpolicybindings", "", subject)),
			"They author a MutatingAdmissionPolicy matching `pods` CREATE whose ApplyConfiguration/JSONPatch sets `spec.containers[*].securityContext.privileged: true` and adds a `hostPath: /` volume, scoped (via matchConstraints or a namespaceSelector) to a namespace PSA does not restrict.",
			"They create a MutatingAdmissionPolicyBinding referencing the policy, activating it cluster-wide for matching requests.",
			"They wait for (or trigger) a pod create in that namespace (a Deployment rollout, a Job, their own `kubectl run`); the apiserver rewrites it in-process and admits a privileged, host-mounting pod.",
			"From the privileged pod they `chroot` into the host root, read `/etc/kubernetes/pki/*` or `/var/lib/kubelet` on a control-plane-adjacent node, and forge cluster-admin credentials.",
		},
		Remediation: "Remove write access to `mutatingadmissionpolicies` and `mutatingadmissionpolicybindings` from every non-admin identity; treat it like write access to (Cluster)RoleBindings.",
		RemediationSteps: []string{
			fmt.Sprintf("Drop `create`/`update`/`patch` on `mutatingadmissionpolicies` and `mutatingadmissionpolicybindings` from %s. These verbs belong only to cluster administrators.", subjectKey(subject)),
			"Audit who else holds them: `kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.resources[]? | test(\"mutatingadmissionpolic\")) | .metadata.name'` (add the ClusterRoleBinding subjects to see the reachable identities).",
			"Enumerate existing policies and bindings for a mutation already planted: `kubectl get mutatingadmissionpolicies,mutatingadmissionpolicybindings -o yaml` and review each `spec.mutations` block.",
			"Add a ValidatingAdmissionPolicy (or Kyverno / Gatekeeper rule) that rejects creation of MutatingAdmissionPolicies / bindings outside a tiny admin allowlist, as defence in depth.",
			fmt.Sprintf("Verify with `%s` returning `no`.", kubectlAuthCanI("create", "mutatingadmissionpolicies", "", subject)),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes: MutatingAdmissionPolicy", URL: "https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/"},
			{Title: "Kubernetes: Admission control ordering (mutating before validating)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"},
			refRBACGoodPractices,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1610, mitreT1611, mitreT1098, mitreT1078_004},
	}
}

// lastField returns the last whitespace-separated token of s (e.g. "delete
// nodes" -> "nodes", "update nodes/status" -> "nodes/status"). Used to render
// the verb/resource pair in the KUBE-PRIVESC-016 verification command.
func lastField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	return fields[len(fields)-1]
}

// contentRBACOverbroad001 — Non-system subject bound to cluster-admin (KUBE-RBAC-OVERBROAD-001).
func contentRBACOverbroad001(subject models.SubjectRef, bindingName string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide cluster-admin (full read/write to every resource in every namespace)",
	}
	return ruleContent{
		Title: fmt.Sprintf("Non-system subject `%s` directly bound to `cluster-admin`", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s is directly bound to the built-in `cluster-admin` ClusterRole via the ClusterRoleBinding `%s`. The `cluster-admin` ClusterRole grants `*` on `*` resources in `*` apiGroups, which means full read/write to every Kubernetes object: Secrets, RBAC, Nodes, Pods, and CRDs cluster-wide.\n\n"+
			"Microsoft's Threat Matrix for Kubernetes lists `Cluster-admin binding` as a top-tier privilege-escalation technique, and CIS Kubernetes Benchmark control 5.1.1 ('Ensure that the cluster-admin role is only used where required') is one of the foundational RBAC hardening checks. Common anti-patterns that produce this finding: `kubectl create clusterrolebinding admin-binding --clusterrole=cluster-admin --user=alice@example.com` for a developer; Helm charts that ship a default ClusterRoleBinding to `cluster-admin`; SaaS/operator installers that take the lazy path.\n\n"+
			"An attacker who compromises %s (stolen kubeconfig, vulnerable container, supply-chain backdoor, or OIDC token replay) immediately holds full cluster control with zero lateral movement required.",
			subjectKey(subject), bindingName, subjectKey(subject)),
		Impact: "Full cluster control: read/write every resource cluster-wide, mint any token, modify any binding, schedule on any node. Equivalent to root on the entire cluster.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises %s (stolen kubeconfig, OIDC session hijack, leaked CI credential, or compromised pod mounting the SA token).", subjectKey(subject)),
			"They run `kubectl auth can-i '*' '*' --all-namespaces` and confirm `yes`.",
			"They harvest all Secrets cluster-wide for cloud-credential pivot.",
			"They establish persistence by minting a 1-year TokenRequest for `kube-system/clusterrole-aggregation-controller`, or by creating a benign-looking ClusterRoleBinding to a backup identity.",
			"They use cluster-admin to disable audit logging or admission controllers, then move quietly through cloud APIs via IRSA/Workload-Identity-mapped credentials.",
		},
		Remediation: "Replace `cluster-admin` with a custom least-privilege ClusterRole, or scope the binding to a dedicated short-lived admin group reachable only via JIT/break-glass procedures.",
		RemediationSteps: []string{
			"Identify what the subject actually does. Audit logs over a representative window will show real verbs/resources for workloads; ask the team for humans.",
			"Author a custom ClusterRole listing only the (apiGroups, resources, verbs) actually needed. Replace the binding to point at the new ClusterRole. Bias toward namespace-scoped Role + RoleBinding wherever possible.",
			"For genuine emergency-admin needs, move to a break-glass model: a separate `cluster-admin-jit` group reachable only via approved JIT (AWS SSO, GCP IAP, HashiCorp Boundary) with mandatory MFA, time-boxed expiry, and SIEM alerting.",
			"Add a ValidatingAdmissionPolicy that rejects new ClusterRoleBindings to `cluster-admin` outside the break-glass group.",
			"Verify: `kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects'` shows only break-glass principals and `system:` subjects.",
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — RBAC Good Practices: cluster-admin restrictions", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
			{Title: "Kubernetes — User-facing roles (cluster-admin, admin, edit, view)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles"},
			{Title: "CIS Kubernetes Benchmark — 5.1.1 Cluster-admin restrictions", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			{Title: "Microsoft Threat Matrix for Kubernetes — Cluster-admin binding", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster-admin%20binding/"},
			{Title: "Elastic Detection — Kubernetes Cluster-Admin Role Binding Created", URL: "https://www.elastic.co/guide/en/security/8.19/kubernetes-cluster-admin-role-binding-created.html"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078, mitreT1078_004, mitreT1098, mitreT1548},
	}
}

// staleContext carries the binding + role + subject details a stale-binding
// content builder needs to render its prose. Keeping this in one struct avoids
// a 6-argument function signature for the two rules below.
type staleContext struct {
	BindingRef       string // formatted, e.g. "ClusterRoleBinding `crb-foo`" or "RoleBinding `ns/rb-foo`"
	BindingNamespace string // raw namespace ("" for ClusterRoleBindings), used by scopeForRule
	RoleRef          string // formatted, e.g. "ClusterRole `cr-foo`" — the role pointed at by the binding
	RoleName         string // raw role name (for kubectl commands in remediation steps)
	RoleKind         string // "Role" or "ClusterRole"
	Subject          models.SubjectRef
	OtherSubjects    []models.SubjectRef // co-subjects on the same binding (only used by STALE-001)
}

// contentRBACStale001 — Binding references a Role/ClusterRole that does not
// exist in the snapshot (KUBE-RBAC-STALE-001).
//
// A dangling roleRef is the "deleted the Role but forgot the binding" pattern.
// The binding grants no permissions while the role is missing, but the moment
// someone with `create roles` (or a routine `kubectl apply` of a cached
// manifest) re-creates a role with that exact name, every subject named on the
// binding inherits whatever rules the new role contains — without anyone
// reviewing the binding. Severity is MEDIUM: latent risk, but a real one.
func contentRBACStale001(ctx staleContext) ruleContent {
	scope := scopeForRule(ctx.BindingNamespace)
	phrase := scopePhrase(scope)
	otherCount := len(ctx.OtherSubjects)
	othersClause := ""
	if otherCount == 1 {
		othersClause = fmt.Sprintf(" The binding lists %d other subject who would also inherit the role's permissions.", otherCount)
	} else if otherCount > 1 {
		othersClause = fmt.Sprintf(" The binding lists %d other subjects who would also inherit the role's permissions.", otherCount)
	}
	kubectlScope := ""
	if ctx.BindingNamespace != "" {
		kubectlScope = fmt.Sprintf(" -n %s", ctx.BindingNamespace)
	}
	roleKindLower := strings.ToLower(ctx.RoleKind)
	bindingKindLower := "clusterrolebinding"
	bindingNameForKubectl := ""
	if strings.HasPrefix(ctx.BindingRef, "RoleBinding ") {
		bindingKindLower = "rolebinding"
	}
	if idx := strings.Index(ctx.BindingRef, "`"); idx != -1 {
		bindingNameForKubectl = strings.Trim(ctx.BindingRef[idx:], "`")
		if slash := strings.LastIndex(bindingNameForKubectl, "/"); slash != -1 {
			bindingNameForKubectl = bindingNameForKubectl[slash+1:]
		}
	}
	return ruleContent{
		Title: fmt.Sprintf("%s stale binding references non-existent %s on `%s`", phrase, ctx.RoleKind, subjectKey(ctx.Subject)),
		Scope: scope,
		Description: fmt.Sprintf("%s grants permissions from %s, but no %s named `%s` exists in this cluster. The binding currently confers no effective permissions, so an attacker who already has %s gains nothing today.%s\n\n"+
			"What makes this risky is what happens *next*. The moment any identity with `create %ss` re-creates a %s named exactly `%s` — by restoring it from version control, applying a cached manifest, or as a deliberate attack step — this binding silently activates and grants the new role's rules to every subject listed. The binding itself was never re-reviewed; the only review gate that fired was on the role definition. If the original review process that introduced this binding was looking at it in the context of a specific role's rules, that context is now gone.",
			ctx.BindingRef, ctx.RoleRef, ctx.RoleKind, ctx.RoleName, subjectKey(ctx.Subject), othersClause, roleKindLower, roleKindLower, ctx.RoleName),
		Impact: fmt.Sprintf("Latent grant: if anyone re-creates %s `%s`, %s (and every co-subject of this binding) inherits its permissions without further review.", ctx.RoleKind, ctx.RoleName, subjectKey(ctx.Subject)),
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates RBAC drift with `kubectl get clusterrolebindings,rolebindings -A -o json | jq` and identifies %s as referencing a non-existent %s `%s`.", ctx.BindingRef, ctx.RoleKind, ctx.RoleName),
			fmt.Sprintf("Attacker (or any identity with `create %ss`) crafts a %s manifest named `%s` with maximally permissive rules — `*` verbs on `*` resources, for example.", roleKindLower, ctx.RoleKind, ctx.RoleName),
			fmt.Sprintf("The new %s is created; Kubernetes immediately resolves the existing binding %s to the new rules.", ctx.RoleKind, ctx.BindingRef),
			fmt.Sprintf("%s now holds those permissions without any binding-review log entry — only the (likely-routine-looking) %s creation was reviewed.", subjectKey(ctx.Subject), ctx.RoleKind),
		},
		Remediation: fmt.Sprintf("Delete the stale binding (`kubectl delete %s %s%s`). If the %s was deleted by mistake, restore it from version control and confirm the binding's intended grant is still appropriate.", bindingKindLower, bindingNameForKubectl, kubectlScope, ctx.RoleKind),
		RemediationSteps: []string{
			fmt.Sprintf("Confirm the binding is no longer needed: `kubectl get %s %s%s -o yaml`.", bindingKindLower, bindingNameForKubectl, kubectlScope),
			fmt.Sprintf("If the %s `%s` should still exist, restore it from version control and re-review the binding's grant in the context of the restored rules.", ctx.RoleKind, ctx.RoleName),
			fmt.Sprintf("If the binding is obsolete, delete it: `kubectl delete %s %s%s`.", bindingKindLower, bindingNameForKubectl, kubectlScope),
			fmt.Sprintf("Add a CI lint (Kyverno / Gatekeeper / ValidatingAdmissionPolicy) that rejects any %s whose roleRef does not resolve to an existing %s.", bindingKindLower, ctx.RoleKind),
		},
		LearnMore: []models.Reference{
			refRBACGoodPractices,
			refRBACDocs,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1078},
	}
}

// contentRBACStale002 — Binding subject is a ServiceAccount that does not
// exist (KUBE-RBAC-STALE-002).
//
// User and Group subjects cannot be validated against the snapshot because
// Kubernetes maintains no inventory of them. Only ServiceAccount subjects
// reach this rule. Severity is LOW because realising the grant requires an
// attacker (or accidental redeploy) to also have `create serviceaccounts` in
// the target namespace — a second-order primitive, not an immediate threat.
func contentRBACStale002(ctx staleContext) ruleContent {
	scope := scopeForRule(ctx.BindingNamespace)
	phrase := scopePhrase(scope)
	saKey := fmt.Sprintf("%s/%s", ctx.Subject.Namespace, ctx.Subject.Name)
	return ruleContent{
		Title: fmt.Sprintf("%s stale binding lists non-existent ServiceAccount `%s`", phrase, saKey),
		Scope: scope,
		Description: fmt.Sprintf("%s grants permissions from %s to ServiceAccount `%s`, but no such ServiceAccount exists in namespace `%s`. No pods can mount a token for this SA today, so the binding confers no realised permissions.\n\n"+
			"This is latent privilege escalation. The moment a ServiceAccount named exactly `%s` is created in namespace `%s` — by an attacker with `create serviceaccounts` in that namespace, by a routine redeploy from a stale GitOps repo, or by an operator restoring an accidentally-deleted SA — it inherits everything %s grants. The binding itself is never re-reviewed; only the SA creation is, and that step usually looks unremarkable.\n\n"+
			"Note: kubesplaining only validates `ServiceAccount` subjects this way. `User` and `Group` subjects cannot be checked against the snapshot — Kubernetes authenticates them externally (OIDC, client certs, cloud IAM) and keeps no inventory of which identities are valid.",
			ctx.BindingRef, ctx.RoleRef, saKey, ctx.Subject.Namespace, ctx.Subject.Name, ctx.Subject.Namespace, ctx.RoleRef),
		Impact: fmt.Sprintf("Latent grant: an attacker with `create serviceaccounts -n %s` can pre-position a ServiceAccount named `%s`, mount its token in a pod they control, and instantly assume the permissions from %s.", ctx.Subject.Namespace, ctx.Subject.Name, ctx.RoleRef),
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates bindings with `kubectl get rolebindings,clusterrolebindings -A -o json` and notices %s lists a subject `ServiceAccount %s` that does not exist.", ctx.BindingRef, saKey),
			fmt.Sprintf("Attacker uses an existing `create serviceaccounts -n %s` permission (or compromises an identity that has it) to create a ServiceAccount named `%s` in that namespace.", ctx.Subject.Namespace, ctx.Subject.Name),
			fmt.Sprintf("Attacker creates a pod with `spec.serviceAccountName: %s` (or projects a TokenRequest for the new SA into a pod they control).", ctx.Subject.Name),
			fmt.Sprintf("The mounted token authenticates as ServiceAccount `%s`, which now resolves through %s into the role's permissions.", saKey, ctx.BindingRef),
		},
		Remediation: "Remove the stale ServiceAccount subject from the binding, or delete the binding entirely if it's obsolete. If the SA was deleted in error, restore it from version control.",
		RemediationSteps: []string{
			fmt.Sprintf("Confirm no workloads still depend on this SA: `kubectl get all -n %s -o yaml | rg 'serviceAccountName:\\s*%s'`.", ctx.Subject.Namespace, ctx.Subject.Name),
			"Edit the binding to drop the stale subject, or delete the binding outright if it is obsolete.",
			"If the SA was deleted by mistake, restore it (`kubectl apply -f <sa.yaml>`) and re-review whether the binding's grant is still appropriate.",
			"Add a CI lint that rejects bindings whose `ServiceAccount` subjects do not resolve to an existing SA in the named namespace.",
		},
		LearnMore: []models.Reference{
			refRBACGoodPractices,
			{Title: "Kubernetes — Managing Service Accounts", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/"},
			refRBACDocs,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1078},
	}
}
