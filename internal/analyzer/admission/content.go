// Content for admission-webhook findings. Each rule has a builder that takes runtime context
// (webhook configuration kind/name and webhook name, plus selector summary text) and returns
// a ruleContent with scope-aware language, an attacker walkthrough, ordered remediation steps,
// and structured references / MITRE technique citations.
//
// Sources: Kubernetes Admission Controller Reference, CVE-2019-11253 (Billion-Laughs), Aqua
// Security & Snyk research on bypass-via-failurePolicy / objectSelector, NSA/CISA Hardening
// Guide v1.2, kube-apiserver `--enable-admission-plugins` docs.
package admission

import (
	"fmt"

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
	mitreT1556 = models.MitreTechnique{ID: "T1556", Name: "Modify Authentication Process", URL: "https://attack.mitre.org/techniques/T1556/"}
	mitreT1562 = models.MitreTechnique{ID: "T1562", Name: "Impair Defenses", URL: "https://attack.mitre.org/techniques/T1562/"}
	mitreT1578 = models.MitreTechnique{ID: "T1578", Name: "Modify Cloud Compute Infrastructure", URL: "https://attack.mitre.org/techniques/T1578/"}
	mitreT1611 = models.MitreTechnique{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"}
	mitreT1525 = models.MitreTechnique{ID: "T1525", Name: "Implant Internal Image", URL: "https://attack.mitre.org/techniques/T1525/"}
)

var (
	refK8sAdmission   = models.Reference{Title: "Kubernetes — Dynamic Admission Control", URL: "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"}
	refK8sAdmissionFP = models.Reference{Title: "Kubernetes — failurePolicy semantics", URL: "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy"}
	refNSAHardening   = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refOPABestPrac    = models.Reference{Title: "OPA Gatekeeper — Production best practices", URL: "https://open-policy-agent.github.io/gatekeeper/website/docs/operations"}
	refK8sPSA         = models.Reference{Title: "Kubernetes — Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"}
	refK8sPSS         = models.Reference{Title: "Kubernetes — Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"}
	refK8sVAP         = models.Reference{Title: "Kubernetes — ValidatingAdmissionPolicy (CEL)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/"}
	refKyvernoIntro   = models.Reference{Title: "Kyverno — Introduction", URL: "https://kyverno.io/docs/introduction/"}
)

// scopeForWebhook returns the scope label for an admission webhook configuration.
// Webhook configurations are cluster-scoped — they intercept admission for every matching
// resource cluster-wide unless a namespaceSelector narrows them. The Detail names the
// configuration so the reader can navigate directly to it.
func scopeForWebhook(configKind, configName, webhookName string) models.Scope {
	return models.Scope{
		Level:  models.ScopeCluster,
		Detail: fmt.Sprintf("%s `%s` (webhook entry `%s`): applies to admission across the entire cluster", configKind, configName, webhookName),
	}
}

func contentAdmission001(configKind, configName, webhookName string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("%s `%s/%s` is fail-open (`failurePolicy: Ignore`) on security-critical resources", configKind, configName, webhookName),
		Scope: scopeForWebhook(configKind, configName, webhookName),
		Description: fmt.Sprintf("The webhook `%s` in `%s/%s` intercepts create/update on security-critical resources (pods, deployments, daemonsets, statefulsets, jobs, cronjobs, or podtemplates) but its `failurePolicy` is set to `Ignore`. The Kubernetes admission docs are explicit: `Ignore` means \"any error from the webhook is silently ignored, and the API request is allowed to continue\". In practice, this means that if the webhook backend is unavailable, slow, or denies the request with an error, the offending pod/workload is admitted as if no policy existed.\n\n"+
			"Concretely, if the policy backend pod crashes, is rolling, has a network partition, fails its own admission, or returns an HTTP 500, then any pod can ship. That includes pods that violate Pod Security Standards, run as root, mount the host filesystem, or use hostNetwork. Beyond that, an attacker who can already trigger a denial-of-service against the webhook backend (high traffic, OOM via large requests, killing its pods) can deliberately disable enforcement and then admit privileged pods.\n\n"+
			"The `failurePolicy` choice is one of two: `Fail` (deny when the webhook is unavailable: the conservative production default) or `Ignore` (allow when unavailable: only appropriate for non-security webhooks like cosmetic mutators). Security webhooks (PSA replacements, image signing, network-policy injection, secret encryption) should always use `Fail` paired with `objectSelector/namespaceSelector` carve-outs that ensure the policy backend itself can come up before any other workload is admitted.",
			webhookName, configKind, configName),
		Impact: "Any outage or DoS of the webhook backend silently disables policy enforcement cluster-wide on the targeted resources. Privileged pods, root containers, and PSS-violating workloads can be admitted while monitoring shows the webhook \"installed.\"",
		AttackScenario: []string{
			fmt.Sprintf("Attacker enumerates webhook configurations (`kubectl get %s`) and identifies that `%s` has `failurePolicy: Ignore`.", configKind, configName),
			"They induce backend failure: kill the webhook's backing pods if they have RBAC for it, send oversized AdmissionReview payloads to OOM the backend, or simply wait for a deploy-time outage.",
			"While the webhook is unhealthy, they apply a privileged pod manifest (hostPID, hostNetwork, hostPath `/`, runAsUser 0).",
			"The API server calls the webhook, gets a connection-refused/timeout error, applies `Ignore`, and admits the pod. There is no audit trail noting that the webhook was bypassed beyond the API-server logs (which most teams do not alert on).",
			"From the privileged pod the attacker pivots: chroot into `/host` for full node compromise, dump secrets, persist a daemonset.",
		},
		Remediation: fmt.Sprintf("Switch `%s.failurePolicy` to `Fail` and confirm the webhook backend has the availability/HA characteristics needed for the cluster's admission rate.", webhookName),
		RemediationSteps: []string{
			fmt.Sprintf("Edit `%s/%s` and set `webhooks[name=%s].failurePolicy: Fail`.", configKind, configName, webhookName),
			"Make sure the webhook backend is highly available (≥2 replicas, PodDisruptionBudget, anti-affinity, dedicated nodepool if it is on the critical admission path).",
			"Add a `namespaceSelector` carve-out so the webhook does not fight itself during cold start (e.g., exclude the namespace where the webhook backend runs).",
			"Add a SLO/alert for AdmissionReview latency and 5xx rate; failure-mode is now \"deploys halt\" instead of \"policy silently disabled,\" which is preferable but needs visible monitoring.",
			"Consider migrating PSS-style enforcement to the in-tree Pod Security Admission so you have a non-webhook backstop that remains active even if the webhook fails to come up.",
		},
		LearnMore: []models.Reference{
			refK8sAdmissionFP,
			refK8sAdmission,
			refNSAHardening,
			refOPABestPrac,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1562, mitreT1556, mitreT1525, mitreT1611},
	}
}

func contentAdmission002(configKind, configName, webhookName string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("%s `%s/%s` can be bypassed by omitting the workload-controlled labels in `objectSelector`", configKind, configName, webhookName),
		Scope: scopeForWebhook(configKind, configName, webhookName),
		Description: fmt.Sprintf("Webhook `%s` in `%s/%s` uses an `objectSelector`, which limits its admission rules to objects whose own labels match the selector. Because Kubernetes lets the workload author set arbitrary labels on the object they are creating, an `objectSelector` that gates security policy is opt-in: an attacker (or a careless developer) creates the same pod without the matching labels and the webhook never sees it.\n\n"+
			"This is structurally different from `namespaceSelector` (which gates by namespace labels; namespaces are a higher-trust object that workload authors typically can't relabel). `objectSelector` checks the labels on the resource being admitted, so a pod manifest that simply omits the policy's gating label slips past untouched. The Kubernetes API reference notes this explicitly: \"If you skip the security label, the webhook is not called.\"\n\n"+
			"For policy-enforcing webhooks (PSS replacements, image-signing, sidecar injection of security tooling) this is the wrong tool. The right pattern is to inversely scope the webhook: select *all* objects (`objectSelector: {}` or absent) and use a `namespaceSelector` plus carefully targeted opt-out labels (e.g., `policy.example.com/exempt: true`) that are themselves gated by RBAC on the namespace, not on the pod author.",
			webhookName, configKind, configName),
		Impact: "Workload authors (legitimate or hostile) can opt out of admission enforcement simply by not setting the gating labels on their pods. This defeats the point of the webhook for any user with create permission on the targeted resources.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker reads `%s/%s` and notes the `objectSelector` requires e.g. `app.kubernetes.io/managed-by: platform`.", configKind, configName),
			"They author a pod manifest that omits the `app.kubernetes.io/managed-by` label entirely.",
			"They `kubectl apply` it; the API server evaluates the objectSelector, finds it does not match, skips the webhook, and admits the pod.",
			"The pod runs with whatever the namespace defaults allow, including PSS-violating settings the webhook was supposed to block.",
			"Because nothing logs \"webhook skipped due to objectSelector,\" the bypass is invisible in the SIEM unless the team explicitly audits AdmissionReview misses.",
		},
		Remediation: fmt.Sprintf("Replace `objectSelector`-based gating on `%s` with `namespaceSelector` plus an RBAC-protected exemption label, or remove the selector and let the webhook see every object.", webhookName),
		RemediationSteps: []string{
			fmt.Sprintf("Audit what `%s` is trying to gate. If the goal is \"only apply to pods in tenant namespaces,\" use `namespaceSelector` (namespace labels are higher-trust).", webhookName),
			"If you need an exemption mechanism, add a `policy.example.com/exempt: true` label *on the namespace* and protect it with RBAC so workload authors cannot grant their own exemption.",
			fmt.Sprintf("Edit `%s/%s` and either drop `webhooks[name=%s].objectSelector` or invert it to a default-on form.", configKind, configName, webhookName),
			"Re-test by attempting to create a pod that previously bypassed admission; it should now be evaluated.",
			"If the webhook ships with the cluster's admission stack, document the new exemption flow so platform users know how to request one.",
		},
		LearnMore: []models.Reference{
			refK8sAdmission,
			{Title: "Aqua Security — Bypassing Admission Controllers", URL: "https://blog.aquasec.com/kubernetes-admission-control-cve-policy-bypass"},
			refNSAHardening,
			refOPABestPrac,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1562, mitreT1556, mitreT1578},
	}
}

func contentAdmission003(configKind, configName, webhookName string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("%s `%s/%s` exempts sensitive system namespaces via `namespaceSelector`", configKind, configName, webhookName),
		Scope: scopeForWebhook(configKind, configName, webhookName),
		Description: fmt.Sprintf("Webhook `%s` in `%s/%s` has a `namespaceSelector` that uses `NotIn` or `DoesNotExist` to exempt `kube-system` (or another `*-system` namespace) from admission control. The exemption is sometimes a deliberate cold-start workaround (the webhook backend itself runs in `kube-system` and would deadlock if the webhook applied to it), but it routinely outlives the cold-start need and is rarely revisited.\n\n"+
			"Sensitive namespaces are exactly where admission control matters most. `kube-system` hosts coredns, kube-proxy, the cloud-controller-manager, CNI agents, the metrics-server, and most clusters' add-on operators: workloads that already run with high privilege. An attacker who can create resources in `kube-system` (e.g., via a stolen `system:` ServiceAccount token, an over-permissive `roles/clusterroles` create rule, or a privileged operator) finds the admission webhooks deliberately turned off for them.\n\n"+
			"This is also a defense-in-depth gap: even if a future privesc finding (`KUBE-PRIVESC-*`) is mitigated, the namespace-selector exemption keeps the door open. The right pattern is to scope the exemption to the *single* control-plane namespace the backend itself needs (and only at boot), not to every `-system` namespace by suffix.",
			webhookName, configKind, configName),
		Impact: "An attacker who can create pods or other resources in the exempted system namespace bypasses every check this webhook implements: root containers, hostPath mounts, and arbitrary images all admit silently.",
		AttackScenario: []string{
			"Attacker compromises a workload with `create pods` permission scoped to `kube-system` (typical of operators, addon managers, or stolen control-plane tokens).",
			"They submit a pod manifest with `hostPath: /`, `runAsUser: 0`, and `securityContext.privileged: true`.",
			fmt.Sprintf("The API server evaluates `%s`'s `namespaceSelector`, sees the exemption for `kube-system`, and admits the pod without invoking the webhook.", webhookName),
			"The pod schedules on a control-plane-adjacent node, mounts the host root filesystem, and reads `/etc/kubernetes/pki/*` (etcd CA, apiserver cert, kubelet client cert).",
			"With those keys the attacker forges admin credentials and assumes full cluster control.",
		},
		Remediation: fmt.Sprintf("Narrow `%s.namespaceSelector` to the exact namespace the webhook backend needs to skip during cold start, or remove the exemption entirely once the backend is bootstrapped.", webhookName),
		RemediationSteps: []string{
			fmt.Sprintf("Check why `%s` excludes the namespace. Is it a cold-start workaround or a permanent carve-out?", webhookName),
			"If cold-start: scope the exemption to the *exact* namespace the webhook backend runs in (e.g., `kubernetes.io/metadata.name NotIn [policy-system]`), not every `*-system`.",
			"If permanent carve-out: replace it with the in-tree Pod Security Admission level for that namespace so privileged pods still face *some* check.",
			"Validate by dry-running a privileged pod manifest in the previously-exempted namespace; the webhook should now process the request.",
			"Wire a Kyverno or OPA Gatekeeper rule that fails any future webhook configuration that exempts `kube-system` or a `*-system` namespace without a documented justification annotation.",
		},
		LearnMore: []models.Reference{
			refK8sAdmission,
			refNSAHardening,
			{Title: "Kubernetes — Pod Security Admission (in-tree, non-bypassable)", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
			refOPABestPrac,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1562, mitreT1611, mitreT1578},
	}
}

// contentNoPolicyEngine is the cluster-wide posture finding emitted when a
// snapshot has no PSA enforce labels in any namespace and no detected policy
// engine (ValidatingAdmissionPolicy, Kyverno, or Gatekeeper). The remediation
// names every option so operators can pick the one that fits their stack.
func contentNoPolicyEngine() ruleContent {
	return ruleContent{
		Title: "Cluster has no Pod Security Admission labels and no detected policy engine",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Applies cluster-wide. No namespace carries `pod-security.kubernetes.io/enforce=baseline|restricted` and no ValidatingAdmissionPolicy / Kyverno / Gatekeeper resources were observed in the snapshot.",
		},
		Description: "Kubesplaining inspected every namespace in this snapshot and found zero `pod-security.kubernetes.io/enforce` labels at the `baseline` or `restricted` level. It also found zero `ValidatingAdmissionPolicy` resources, zero Kyverno `(Cluster)Policy` resources, and zero Gatekeeper `ConstraintTemplate` resources. Together these are the four statically-detectable defenses against privileged or otherwise dangerous pod specs being admitted to the cluster.\n\n" +
			"With none of them in place, an attacker (or a careless developer) who can `create pods` in any namespace can submit a manifest with `securityContext.privileged: true`, `hostPID: true`, `hostNetwork: true`, `hostPath: /`, or `runAsUser: 0` and the API server will admit it without challenge. There is no in-tree backstop: the legacy PodSecurityPolicy admission controller was removed in Kubernetes v1.25, and Pod Security Admission only enforces what each namespace's labels ask for. A namespace without an enforce label is a permissive namespace.\n\n" +
			"This finding is *posture*, not workload-specific. The reason every other host-level finding in this report (KUBE-ESCAPE-*, KUBE-PODSEC-*, KUBE-HOSTPATH-*) is unmitigated by admission is that this cluster has no admission control to mitigate them. Fixing this one finding is the highest-leverage action: it does not patch any individual workload, but it prevents the next privileged pod from being admitted at all.\n\n" +
			"There are three viable paths, in order of decreasing operational cost: (1) apply Pod Security Admission labels to every namespace (in-tree, no install required, but you have to label every namespace and decide on the right level per namespace); (2) install Kyverno or Gatekeeper for richer policy expression with audit + warn + enforce modes (an operator install plus per-rule authoring); (3) author one or more `ValidatingAdmissionPolicy` resources for K8s-native CEL-based policies (no install but requires v1.30+ and CEL fluency). Most teams pair (1) with one of (2)/(3) for defense in depth.",
		Impact: "Any user with `create pods` in any namespace can admit a pod that mounts the host filesystem, runs as root, or shares the host's network/PID/IPC namespaces — all without admission-time intervention. From there the standard escape-to-host kill chain is available cluster-wide.",
		AttackScenario: []string{
			"Attacker compromises a workload, ServiceAccount token, or developer kubeconfig that has `create pods` permission in any namespace (most internal namespaces grant this by default).",
			"They craft a pod manifest with `hostPID: true`, `hostNetwork: true`, `securityContext.privileged: true`, and `volumes: [{hostPath: {path: /}}]` mounted at `/host`.",
			"They `kubectl apply` the manifest. The API server runs through built-in admission, finds no PSA enforce label and no policy-engine webhook, and admits the pod.",
			"The pod schedules on a node, mounts the host root filesystem, and the attacker `chroot`s into `/host` — they now have root on a Kubernetes node with full visibility into every container, secret, and network connection on it.",
			"From the node they read `/var/lib/kubelet/pki/*` and `/etc/kubernetes/*` (when present), enumerate other nodes via the kubelet API, and pivot to control-plane material for full cluster takeover.",
		},
		Remediation: "Apply Pod Security Admission labels to every namespace at the appropriate level (`baseline` minimum, `restricted` for tenant workloads), or install Kyverno / Gatekeeper, or author ValidatingAdmissionPolicy resources. Pair PSA with a policy engine for defense in depth.",
		RemediationSteps: []string{
			"Inventory namespaces: `kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'`. Decide a default level per namespace — `restricted` for application workloads, `baseline` only where a workload genuinely needs it, `privileged` only for control-plane components that must run with host access.",
			"Label namespaces: `kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/audit=restricted pod-security.kubernetes.io/warn=restricted`. PSA only checks creates and updates, so existing pods continue to run; you'll see `audit`/`warn` log entries for the survivors so you can roll them out gradually.",
			"For richer policy expression, install Kyverno (`helm install kyverno kyverno/kyverno -n kyverno --create-namespace`) or Gatekeeper (`helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace`) and adopt one of the published policy bundles (Kyverno's `pod-security` set, Gatekeeper's `gatekeeper-library`).",
			"For K8s-native CEL policies on v1.30+, author `ValidatingAdmissionPolicy` resources for the rules you care about most (e.g. block `securityContext.privileged: true` cluster-wide). Bind them with `ValidatingAdmissionPolicyBinding` and use `audit` mode first to size the impact before flipping to `deny`.",
			"Re-run kubesplaining: this posture finding will disappear, and individual workload findings will start being suppressed (default) or attenuated (`--admission-mode=attenuate`) when the admission controls would block them.",
		},
		LearnMore: []models.Reference{
			refK8sPSA,
			refK8sPSS,
			refK8sVAP,
			refKyvernoIntro,
			refOPABestPrac,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1562, mitreT1611, mitreT1525},
	}
}
