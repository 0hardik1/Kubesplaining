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

	"github.com/hardik/kubesplaining/internal/models"
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
			Detail: "Cluster-wide — applies to every current and future namespace",
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
	refCISBenchmark = models.Reference{
		Title: "CIS Kubernetes Benchmark (RBAC controls)",
		URL:   "https://www.cisecurity.org/benchmark/kubernetes",
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
			"In a typical attack, an adversary who reaches a workload bound to this rule has full control: they read every Secret, create privileged pods on any node, bind themselves to additional ClusterRoles, and persist by minting long-lived tokens via the TokenRequest API. There is no further escalation needed — the box is already at the top.",
			sourceBinding, sourceRole, subjectKey(subject), scope.Detail),
		Impact: fmt.Sprintf("Full control over %s — read/write every Secret, RBAC, Pod, Node; equivalent to `cluster-admin` when cluster-scoped.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a workload that resolves to %s — vulnerable container image, supply-chain backdoor, or stolen kubeconfig.", subjectKey(subject)),
			fmt.Sprintf("They run `%s` and confirm wildcard permissions.", kubectlAuthCanI("'*'", "'*'", ruleNamespace, subject)),
			"They list every Secret in scope (`kubectl get secrets -A -o yaml`) to harvest cloud-provider credentials, registry pull secrets, and other ServiceAccount tokens.",
			"They create a privileged DaemonSet that mounts the host filesystem and reads `/etc/kubernetes/pki/*` to steal the cluster CA.",
			"They establish persistence by minting a long-lived token for `clusterrole-aggregation-controller` via the TokenRequest API, then optionally remove their original binding to evade detection.",
		},
		Remediation: "Replace the wildcard rule with an explicit allowlist of (apiGroups, resources, verbs) limited to what the workload actually calls.",
		RemediationSteps: []string{
			fmt.Sprintf("Inventory what %s actually needs — run `%s` and correlate with audit logs filtered on `user.username`.", subjectKey(subject), kubectlAuthCanI("--list", "", ruleNamespace, subject)),
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

// contentPrivesc005 — Secret read access (KUBE-PRIVESC-005).
func contentPrivesc005(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s read access to Secrets — `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `get`, `list`, or `watch` core `secrets` via %s → %s. %s.\n\n"+
			"The Kubernetes documentation is explicit that `list` and `watch` reveal Secret contents in the response body — they are not metadata-only verbs — so all three verbs leak the same data.\n\n"+
			"Kubernetes Secrets typically hold ServiceAccount tokens, kubeconfigs, image-pull credentials, TLS private keys, database passwords, and integration secrets for cloud APIs. Once Secret contents are exposed, the holder can authenticate as the corresponding ServiceAccount/user, which usually amplifies the original blast radius far beyond 'read access'. Cluster-wide reads include `kube-system` ServiceAccount tokens, which are routinely cluster-admin-equivalent.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("%s read of every Secret — ServiceAccount tokens, TLS keys, registry credentials, integration secrets — enabling identity replay and cross-namespace lateral movement.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker reaches %s (compromised pod, leaked kubeconfig, or stolen token).", subjectKey(subject)),
			"They run `kubectl get secrets -o yaml` in scope and base64-decode every `data` field.",
			"They identify Secrets of type `kubernetes.io/service-account-token` (legacy) or call the TokenRequest API with harvested credentials.",
			"They replay the highest-privileged token against the API server (`kubectl --token=<jwt> get clusterrolebindings`).",
			"They pivot to cloud APIs using extracted IRSA / Workload Identity / cloud-provider credentials, or persist by writing a backdoor into a privileged Deployment.",
		},
		Remediation: "Remove `get/list/watch` on `secrets` from this subject; if a specific Secret is genuinely needed, scope by `resourceNames` to that one name.",
		RemediationSteps: []string{
			"Confirm the workload genuinely needs API-time Secret access. Most apps consume Secrets via volume/env injection at pod start and don't need RBAC read.",
			"If runtime access is required, scope the rule by `resourceNames` to the exact Secret(s) the workload reads — never leave it as 'all secrets'. Drop `list` and `watch`; keep only `get`.",
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
		Title: fmt.Sprintf("%s pod creation — token-theft and node-takeover path (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` pods via %s → %s. %s.\n\n"+
			"Under Kubernetes' RBAC model, pod creation is one of the most powerful permissions because the API server does not police the privileges of the pod being created — only the create verb itself. A pod is a request to run code as a ServiceAccount; by choosing `spec.serviceAccountName` the attacker borrows the identity (and RBAC permissions) of any ServiceAccount in the target namespace, with the token mounted automatically at `/var/run/secrets/kubernetes.io/serviceaccount/token`.\n\n"+
			"Beyond identity hopping, a created pod can request `hostPath`, `hostNetwork`, `hostPID`, `privileged: true`, or `SYS_ADMIN` — none of which are blocked by RBAC; only Pod Security Admission or a policy engine (Kyverno, Gatekeeper, ValidatingAdmissionPolicy) can stop them. A typical attack mounts / from the host and reads `/etc/kubernetes/pki/admin.conf` directly.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Run arbitrary code as any ServiceAccount in %s (including privileged ones); optionally request privileged/host-mount pods to escape to the underlying node.", phrase),
		AttackScenario: []string{
			"Attacker enumerates target namespaces — `kubectl get sa -A` to find privileged ServiceAccounts (e.g. `kube-system/clusterrole-aggregation-controller`).",
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
		Title: fmt.Sprintf("%s workload-controller mutation can spawn privileged pods — `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create/update/patch` workload controllers (`deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`) via %s → %s. %s.\n\n"+
			"Anyone who can write a workload template inherits the same implicit permissions as `pods/create`: choice of ServiceAccount, choice of Pod Security context, and choice of host-level features. The specific danger of controller mutation (vs. pod create) is durability and stealth: a `kubectl edit deployment` adding a `privileged: true` sidecar produces pods continuously — restart-loop the pod and you get a fresh shell every time.\n\n"+
			"DaemonSet write is the most dangerous variant because a DaemonSet runs one pod on every node — including new nodes added later. CronJobs offer time-based persistence that survives pod evictions, node reboots, and short-lived RBAC remediations. A realistic incident: an attacker with `patch daemonsets` in `kube-system` mutates `kube-proxy` to add a malicious sidecar inheriting the existing pod's host-mounts and ServiceAccount.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Spawn (or mutate existing) pods running as any ServiceAccount in %s; DaemonSet write specifically yields one attacker pod per node, including future nodes.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates writable controllers — `%s`.", kubectlAuthCanI("patch", "daemonsets", ruleNamespace, subject)),
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
		Title: fmt.Sprintf("%s `impersonate` permission — `%s`", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s has the `impersonate` verb on `users/groups/serviceaccounts` via %s → %s. %s.\n\n"+
			"Kubernetes' impersonation lets a request set `Impersonate-User/Impersonate-Group` headers (or `kubectl --as`) so the API server processes the request as a different identity. The Kubernetes project flags this in `RBAC Good Practices` as one of three verbs (alongside `bind` and `escalate`) that override normal RBAC limits.\n\n"+
			"Most damaging is the ability to impersonate the `system:masters` group, which is hardcoded inside kube-apiserver to bypass RBAC entirely — there is no Role or RoleBinding that grants `system:masters` membership; the apiserver simply trusts the assertion. `kubectl --as=admin --as-group=system:masters get secrets -A` runs as cluster-admin, full stop. Impersonation is also stealthier than a binding change because audit logs show `user.username` as the original subject.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Act as any user/group/ServiceAccount in %s; impersonating `system:masters` bypasses all RBAC checks irrevocably.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb — `%s`.", kubectlAuthCanI("impersonate", "users", ruleNamespace, subject)),
			"They run `kubectl --as=admin --as-group=system:masters get clusterrolebindings` to confirm `system:masters` impersonation succeeds.",
			"They impersonate the highest-privileged ServiceAccount they can find (e.g. `system:serviceaccount:kube-system:clusterrole-aggregation-controller`) and exfiltrate Secrets cluster-wide.",
			"They establish persistence by creating a benign-looking ClusterRoleBinding via the impersonated identity (audit logs blame the impersonated SA, not the attacker).",
			"They optionally add their own user to a privileged group via OIDC group claims, providing identity-layer persistence that survives RBAC remediation.",
		},
		Remediation: "Remove `impersonate` entirely; if a SaaS console truly needs it, gate on `resourceNames` and never grant it on `groups`.",
		RemediationSteps: []string{
			"Remove `impersonate` on `users`, `groups`, and `serviceaccounts`. The vast majority of workloads have no need for impersonation.",
			"If impersonation is genuinely required, scope to `users` only (not `groups` — never allow `system:masters`), use `resourceNames` to allow only specific identities, and never grant cluster-wide.",
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
		Title: fmt.Sprintf("%s `bind/escalate` on roles — RBAC bypass (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s has the `bind` or `escalate` verb on `roles/clusterroles` via %s → %s. %s.\n\n"+
			"Kubernetes' RBAC normally enforces a privilege-escalation guard: you cannot create a Role/RoleBinding granting permissions you do not already hold. The `escalate` and `bind` verbs are explicit, documented exceptions to that guard.\n\n"+
			"`escalate` lets the subject author or modify a Role/ClusterRole with verbs and resources they don't currently possess — they rewrite an existing Role they're already bound to and instantly inherit whatever they wrote into it.\n\n"+
			"`bind` lets the subject create a RoleBinding/ClusterRoleBinding referencing a (Cluster)Role they don't already hold. With `bind` on `clusterroles`, an attacker creates a ClusterRoleBinding from themselves to `cluster-admin` and is done in one step.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Defeat the API-level escalation guard in %s; subject can grant itself any (Cluster)Role's permissions, including `cluster-admin`.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb — `%s`.", kubectlAuthCanI("bind", "clusterroles", ruleNamespace, subject)),
			"They write a one-line ClusterRoleBinding from their identity (or a SA they control) to the `cluster-admin` ClusterRole and `kubectl apply` it.",
			"They re-use the same token (ClusterRoleBindings take effect immediately on next request) and have full cluster control.",
			"Alternatively, with `escalate` on `clusterroles`, they `kubectl edit clusterrole/<role-they-already-have>` and add `*` verbs/resources/apiGroups, retaining the same binding.",
			"They optionally name the new ClusterRoleBinding innocuously (e.g. `cluster-monitor-binding`) so the change is less visible to operators reviewing `kubectl get clusterrolebindings`.",
		},
		Remediation: "Remove `bind` and `escalate` from non-admin identities; gate any legitimate need behind admission policy that rejects bindings to `cluster-admin` or system roles.",
		RemediationSteps: []string{
			"Audit every Role/ClusterRole that includes `bind` or `escalate` — `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.verbs[]? | IN(\"bind\",\"escalate\"))'`.",
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
		Title: fmt.Sprintf("%s write access to (Cluster)RoleBindings — self-grant path (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create/update/patch` `rolebindings/clusterrolebindings` via %s → %s. %s.\n\n"+
			"RoleBinding write is the most direct self-grant path in Kubernetes. Even with the API-level escalation guard active (binding only to roles whose permissions you already have), this permission is dangerous: if the subject already holds any powerful permission (often inherited from a default ClusterRole like `view/edit`), they can re-bind it to backup identities for persistence.\n\n"+
			"A RoleBinding can also reference a *ClusterRole*, granting that ClusterRole's permissions inside the binding's namespace — so `create rolebindings` in `kube-system` is effectively cluster-admin-on-kube-system. Combined with `bind` on `clusterroles` (KUBE-PRIVESC-009), this bypasses the escalation guard entirely and yields cluster-admin in one step. Microsoft's Threat Matrix for Kubernetes documents this as the `Cluster-admin binding` technique.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: "Self-grant any role the subject already holds (or any ClusterRole, when paired with `bind` or when binding into namespaces); cluster-wide writes are one step from cluster-admin.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates what they can already bind — `%s` and `%s`.", kubectlAuthCanI("create", "clusterrolebindings", ruleNamespace, subject), kubectlAuthCanI("--list", "", ruleNamespace, subject)),
			"If they hold a useful role, they create a ClusterRoleBinding granting that role to a backup identity for persistence.",
			"With `bind` on `cluster-admin` (often via wildcards), they create a ClusterRoleBinding from themselves to `cluster-admin`.",
			"Even without `bind`, in `kube-system` they create a RoleBinding referencing `system:controller:clusterrole-aggregation-controller` (which has `escalate` baked in) and pivot from there.",
			"They name the binding innocuously (e.g. `monitoring-readonly`) so audit logs look benign.",
		},
		Remediation: "Restrict `create/update/patch` on `rolebindings/clusterrolebindings` to a small admin boundary; require all RBAC changes to flow through GitOps with PR review.",
		RemediationSteps: []string{
			"Audit who has write access to RBAC bindings — most workloads should have zero RBAC write rights.",
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
		Title: fmt.Sprintf("`get nodes/proxy` — kubelet exec via API server (`%s`)", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `get` `nodes/proxy` via %s → %s. Despite the read-only-sounding `get` verb, this permission lets the holder execute arbitrary commands inside any pod on any node by tunneling through the API server to the kubelet's internal HTTP API — `/exec`, `/run`, `/attach`, `/portforward`.\n\n"+
			"The technical root cause: pod exec uses an HTTP-to-WebSocket upgrade. The API server authorizes the upgrade based on the initial GET against the proxy subresource — not against `pods/exec`. So a subject with `get nodes/proxy` can issue `kubectl get --raw '/api/v1/nodes/<node>/proxy/exec/...'` and end up with an interactive shell in any container, even with no `pods/exec` permission anywhere.\n\n"+
			"Worse, the resulting commands execute over a direct API-server-to-kubelet WebSocket and are NOT recorded in apiserver audit logs at the `objectRef/verb` granularity — the audit log shows only the proxy GET. Detection requires node-level eBPF/process monitoring (Falco, Tetragon, KubeArmor), not API-server logs alone. Kubernetes issue #119640 and Stream Security have published proof-of-concept exploits.",
			subjectKey(subject), sourceBinding, sourceRole),
		Impact: "Cluster-wide remote code execution: exec into any container on any node via the kubelet API, with execution invisible to standard apiserver audit logs.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb — `%s`.", kubectlAuthCanI("get", "nodes/proxy", "", subject)),
			"They list nodes (`kubectl get nodes`) and pick a high-value one — typically a control-plane node, or any node hosting `kube-apiserver/etcd`/operator pods.",
			"They issue an exec request via the proxy endpoint, e.g. `kubectl get --raw '/api/v1/nodes/<node>/proxy/run/kube-system/<pod>/<container>?cmd=id'`, or open a WebSocket to `/exec`.",
			"They land in the target container with that container's privileges (host-mounts, capabilities, ServiceAccount token).",
			"From a control-plane container they read `/etc/kubernetes/pki/admin.conf` for cluster-admin credentials. The entire chain leaves no `pods/exec` audit entries.",
		},
		Remediation: "Remove `nodes/proxy` from this subject; reserve it for the API server itself and a tiny set of trusted operators that document this need.",
		RemediationSteps: []string{
			"Remove the rule entirely. Application workloads never need `nodes/proxy` — Kubernetes documents this as a 'severe escalation hazard' in RBAC Good Practices.",
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

// contentPrivesc014 — serviceaccounts/token create (KUBE-PRIVESC-014).
func contentPrivesc014(ruleNamespace string, subject models.SubjectRef, sourceBinding, sourceRole string) ruleContent {
	scope := scopeForRule(ruleNamespace)
	phrase := scopePhrase(scope)
	return ruleContent{
		Title: fmt.Sprintf("%s `create serviceaccounts/token` — token minting (`%s`)", phrase, subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s can `create` on the `serviceaccounts/token` subresource via %s → %s. %s.\n\n"+
			"The TokenRequest API (Kubernetes 1.22+) is the canonical way to mint a JWT ServiceAccount token, and its `create` verb is gated by RBAC on the `serviceaccounts/token` subresource. Anyone holding this verb on a ServiceAccount can mint a token authenticated as that ServiceAccount.\n\n"+
			"Datadog Security Labs published a write-up on its abuse for persistence: an attacker mints a long-lived token for the highest-privileged ServiceAccount they can reach (commonly `kube-system/clusterrole-aggregation-controller`, which holds `escalate` on ClusterRoles), and uses that token as a backdoor that survives the original RBAC binding being removed. Crucially, this verb is NOT covered by 'list secrets' detections — TokenRequest tokens are NOT stored as Secret objects; they're issued live by the apiserver and never leave a footprint on disk.",
			subjectKey(subject), sourceBinding, sourceRole, scope.Detail),
		Impact: fmt.Sprintf("Mint a JWT for any ServiceAccount in %s. Cluster-wide variant trivially yields cluster-admin (mint a kube-system controller token). Tokens persist after the original binding is revoked.", phrase),
		AttackScenario: []string{
			fmt.Sprintf("Attacker confirms the verb — `%s`.", kubectlAuthCanI("create", "serviceaccounts/token", ruleNamespace, subject)),
			"They enumerate high-privilege ServiceAccounts: `kubectl get clusterrolebindings -o json | jq '.items[].subjects[]?.name'` and pick one with `cluster-admin`, `system:masters`, or aggregated permissions.",
			"They mint a long-lived token via the TokenRequest API: `kubectl create token <sa-name> -n <ns> --duration=8760h` (1 year), or call `/api/v1/namespaces/<ns>/serviceaccounts/<sa>/token` directly.",
			"They `kubectl --token=<jwt> get nodes` and confirm the new identity.",
			"They cache the token off-cluster as a backdoor: rotating the original binding does NOT invalidate an issued token until its `exp` claim — by default up to `--service-account-max-token-expiration`, often 1 year on legacy clusters.",
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

// contentRBACOverbroad001 — Non-system subject bound to cluster-admin (KUBE-RBAC-OVERBROAD-001).
func contentRBACOverbroad001(subject models.SubjectRef, bindingName string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide cluster-admin (full read/write to every resource in every namespace)",
	}
	return ruleContent{
		Title: fmt.Sprintf("Non-system subject `%s` directly bound to `cluster-admin`", subjectKey(subject)),
		Scope: scope,
		Description: fmt.Sprintf("Subject %s is directly bound to the built-in `cluster-admin` ClusterRole via the ClusterRoleBinding `%s`. The `cluster-admin` ClusterRole grants `*` on `*` resources in `*` apiGroups — full read/write to every Kubernetes object including Secrets, RBAC, Nodes, Pods, and CRDs cluster-wide.\n\n"+
			"Microsoft's Threat Matrix for Kubernetes lists `Cluster-admin binding` as a top-tier privilege-escalation technique, and CIS Kubernetes Benchmark control 5.1.1 ('Ensure that the cluster-admin role is only used where required') is one of the foundational RBAC hardening checks. Common anti-patterns that produce this finding: `kubectl create clusterrolebinding admin-binding --clusterrole=cluster-admin --user=alice@example.com` for a developer; Helm charts that ship a default ClusterRoleBinding to `cluster-admin`; SaaS/operator installers that take the lazy path.\n\n"+
			"An attacker who compromises %s (stolen kubeconfig, vulnerable container, supply-chain backdoor, or OIDC token replay) immediately holds full cluster control with zero lateral movement required.",
			subjectKey(subject), bindingName, subjectKey(subject)),
		Impact: "Full cluster control: read/write every resource cluster-wide, mint any token, modify any binding, schedule on any node. Equivalent to root on the entire cluster.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises %s — stolen kubeconfig, OIDC session hijack, leaked CI credential, or compromised pod mounting the SA token.", subjectKey(subject)),
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
