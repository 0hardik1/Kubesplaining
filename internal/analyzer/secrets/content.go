// Content for Secret/ConfigMap hygiene findings. Each builder takes runtime context
// (namespace, name, matched keys, Corefile snippet) and returns a ruleContent with
// scope, attacker walkthrough, ordered remediation, and authoritative references.
//
// Sources: Kubernetes Secret docs, KEP-1205 (BoundServiceAccountTokens), CIS Kubernetes
// Benchmark 5.4.1 / 5.1.5, NSA/CISA Hardening Guide v1.2, MITRE ATT&CK T1552.001/.007,
// CoreDNS docs, Aqua/Sysdig writeups on DNS rebinding inside clusters.
package secrets

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
	mitreT1552_001 = models.MitreTechnique{ID: "T1552.001", Name: "Credentials In Files", URL: "https://attack.mitre.org/techniques/T1552/001/"}
	mitreT1552_007 = models.MitreTechnique{ID: "T1552.007", Name: "Container API", URL: "https://attack.mitre.org/techniques/T1552/007/"}
	mitreT1078_004 = models.MitreTechnique{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"}
	mitreT1539     = models.MitreTechnique{ID: "T1539", Name: "Steal Web Session Cookie", URL: "https://attack.mitre.org/techniques/T1539/"}
	mitreT1071_004 = models.MitreTechnique{ID: "T1071.004", Name: "DNS", URL: "https://attack.mitre.org/techniques/T1071/004/"}
	mitreT1556_004 = models.MitreTechnique{ID: "T1556.004", Name: "Network Provider DLL", URL: "https://attack.mitre.org/techniques/T1556/"}
	mitreT1565_002 = models.MitreTechnique{ID: "T1565.002", Name: "Transmitted Data Manipulation", URL: "https://attack.mitre.org/techniques/T1565/002/"}
)

var (
	refK8sSecrets       = models.Reference{Title: "Kubernetes — Secrets", URL: "https://kubernetes.io/docs/concepts/configuration/secret/"}
	refK8sConfigMap     = models.Reference{Title: "Kubernetes — ConfigMaps", URL: "https://kubernetes.io/docs/concepts/configuration/configmap/"}
	refBoundSATokens    = models.Reference{Title: "Kubernetes — Bound Service Account Tokens (KEP-1205)", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens"}
	refLegacyTokens     = models.Reference{Title: "Kubernetes — LegacyServiceAccountTokenCleaner & deprecated token controller", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#legacy-serviceaccount-token-tracking-and-cleaning"}
	refSecretsHardening = models.Reference{Title: "Kubernetes — Good practices for Secrets", URL: "https://kubernetes.io/docs/concepts/security/secrets-good-practices/"}
	refNSAHardening     = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refCoreDNSPlugins   = models.Reference{Title: "CoreDNS — plugin reference (rewrite, forward)", URL: "https://coredns.io/plugins/"}
)

func contentSecrets001(namespace, name string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Secret `%s/%s` is a long-lived `kubernetes.io/service-account-token` (legacy, no expiry)", namespace, name),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `%s/%s`: credential is valid until manually deleted; readable by any subject with `get/list secrets` in `%s`", namespace, name, namespace),
		},
		Description: fmt.Sprintf("Secret `%s/%s` has type `kubernetes.io/service-account-token`. This is the legacy ServiceAccount token model: the token-controller persists a JWT into a Secret, the token has *no expiry* (the audience is the API server, the validity is open-ended), and it is readable by any subject with `get/list secrets` permission in the namespace.\n\n"+
			"Since Kubernetes v1.22, Bound ServiceAccount Tokens (KEP-1205) replaced this model: the kubelet projects a *new* token into the pod's filesystem with a short TTL (default 1h) and the token is bound to the pod object, so deleting the pod invalidates the token. v1.24 stopped auto-creating these legacy Secret tokens, and v1.27+ ships the `LegacyServiceAccountTokenCleaner` controller that removes unused ones automatically. A legacy token Secret today is either an artifact of a pre-1.24 cluster, a manually-created `serviceAccountToken` Secret, or a controller that explicitly created one. None of these carry the bind-to-pod, time-bounded properties of projected tokens.\n\n"+
			"The risk profile: a leaked legacy token grants whatever permissions its ServiceAccount has, *forever*, with no automatic revocation. It survives Pod restarts, node reboots, audit events, and rotation of the SA itself. Detection of misuse requires explicit audit-log monitoring against the SA name; rotation requires deleting the Secret and reissuing.",
			namespace, name),
		Impact: "Anyone who exfiltrates this Secret holds a non-expiring credential with the ServiceAccount's full RBAC; rotation requires manual `kubectl delete secret` and re-issue, and there is no time-based mitigation.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any subject with `get secrets` in `%s` (e.g., a forgotten `view`-style role, an over-permissive ConfigMap-reader role that wildcards resources, or a pod token with secret-read).", namespace),
			fmt.Sprintf("They `kubectl get secret %s -n %s -o jsonpath='{.data.token}' | base64 -d` and obtain the raw JWT.", name, namespace),
			"They use the token against the kube-apiserver from outside the cluster (`kubectl --token=...`). No pod, no node, no IMDS hop required.",
			"Because the token has no `exp` claim and no audience binding to a Pod, it remains valid weeks or months later. Rotation in IR is manual: delete the Secret + recreate, and any cached copies attacker has are *still valid until that delete*.",
			"Attacker uses the SA's RBAC to read other Secrets, list pods cluster-wide (if SA has it), exec into pods, or escalate via any of the privesc paths the SA enables.",
		},
		Remediation: fmt.Sprintf("Migrate the consumer of `%s/%s` to a projected ServiceAccount token, then delete the Secret. Enable `LegacyServiceAccountTokenCleaner` on the cluster.", namespace, name),
		RemediationSteps: []string{
			fmt.Sprintf("Identify what reads `%s/%s`: `kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.secret.secretName == \"%s\") | .metadata.namespace + \"/\" + .metadata.name'`. Also check Jobs, CronJobs, and external systems that might have copied the token out.", namespace, name, name),
			"Migrate each consumer to a projected SA token (`serviceAccountToken` projection in `volumes`) with a sensible `expirationSeconds` (e.g., 3600). The kubelet will refresh it automatically.",
			"For external consumers (CI runners, dashboards) that need a long-lived token, use TokenRequest API on demand instead of a stored Secret, or rotate via a sealed-secret / external-secret-store flow.",
			fmt.Sprintf("`kubectl delete secret %s -n %s` once consumers are migrated. Confirm no pod has a CrashLoopBackOff that mentions the missing token.", name, namespace),
			"Enable the `LegacyServiceAccountTokenCleaner` (default on v1.29+) so future stragglers get garbage-collected after their last-used timestamp ages out.",
		},
		LearnMore: []models.Reference{
			refBoundSATokens,
			refLegacyTokens,
			refK8sSecrets,
			refSecretsHardening,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004, mitreT1539},
	}
}

func contentSecrets002(name string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Opaque Secret `kube-system/%s` likely holds control-plane or addon credentials", name),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("Secret `kube-system/%s`: control-plane namespace; readers in `kube-system` are typically system controllers and high-privilege operators", name),
		},
		Description: fmt.Sprintf("Secret `kube-system/%s` has type `Opaque`. The `kube-system` namespace is reserved for control-plane workloads and cluster add-ons (cloud-controller-manager, CNI, CSI, ingress controllers, certificate operators, observability agents). Opaque Secrets there are almost always one of: cloud IAM credentials for the cloud-controller-manager, registry pull secrets for system images, TLS client certs for an etcd snapshot agent, kubeconfigs for an external-DNS controller, or addon-vendor API keys.\n\n"+
			"Because of where they live, these Secrets carry outsized blast radius compared to a workload Secret. A leak here typically grants either (a) credentials to the cloud account hosting the cluster, (b) the ability to publish or pull from the cluster's container registry, or (c) durable access to control-plane components that can be used to subvert further controls.\n\n"+
			"Two specific concerns: (1) `kube-system` Secrets are often forgotten when teams set up Vault or external-secret-store integrations, so they live on as the bootstrap credential, never rotated; (2) RBAC for `kube-system` is typically broad (operator service accounts often `cluster-admin`-adjacent) so the set of subjects that can read them is much larger than the team realizes.",
			name),
		Impact: "This Secret likely encodes credentials with cluster-wide or cloud-account reach. A read by any subject with `get secrets` in `kube-system` (operator SAs, kube-system pods, cluster-admin tokens) escalates to whatever the credential authorizes.",
		AttackScenario: []string{
			"Attacker gains a `kube-system` ServiceAccount token with `get secrets` (e.g., compromised addon, addon-installer Job, helm-release Secret reader).",
			fmt.Sprintf("They `kubectl get secret %s -n kube-system -o yaml` and decode each `data` key.", name),
			"They identify the credential type: AWS access key (`aws_access_key_id/aws_secret_access_key`), GCP service-account JSON, Azure tenant/client ID, Docker config (registry credentials), or an inline kubeconfig.",
			"They authenticate out-of-cluster with the credential: cloud account compromise, registry image-publishing for supply-chain implant, or a parallel kubeconfig that survives in-cluster RBAC revocation.",
			"They persist by issuing a new IAM key / pushing an unsigned image / writing a kubeconfig to a hidden location, then cover by deleting their access logs.",
		},
		Remediation: fmt.Sprintf("Audit `kube-system/%s`'s contents and consumers; rotate the credential; move long-lived credentials to a sealed-secret or external secret store; restrict who can `get secrets` in `kube-system`.", name),
		RemediationSteps: []string{
			fmt.Sprintf("Inspect the Secret's content shape (key names, not values) to identify the credential type via `kubectl get secret %s -n kube-system -o jsonpath='{.data}' | jq 'keys'`.", name),
			fmt.Sprintf("Find consumers: `kubectl get pods -n kube-system -o json | jq '.items[] | select(.spec.volumes[]?.secret.secretName == \"%s\" or .spec.containers[].envFrom[]?.secretRef.name == \"%s\") | .metadata.name'`.", name, name),
			"Rotate the underlying credential at its source (cloud IAM, registry, etc.) and update the Secret with the new value, preferably by switching to External Secrets Operator (Vault/SecretsManager backend) so the Secret becomes a generated artifact instead of source-of-truth.",
			"Tighten RBAC on `kube-system` Secrets so each operator SA only sees its own Secret, not `secrets` cluster-wide. Audit with `kubectl auth can-i get secrets -n kube-system --as=system:serviceaccount:kube-system:<sa>` for each one.",
			"Wire enforcement: a Kyverno or OPA Gatekeeper policy that flags any Pod referencing a long-lived `kube-system` Secret name not on an allowlist.",
		},
		LearnMore: []models.Reference{
			refSecretsHardening,
			refK8sSecrets,
			refNSAHardening,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004},
	}
}

func contentConfigMap001(namespace, name string, matchedKeys []string) ruleContent {
	keysList := strings.Join(matchedKeys, ", ")
	return ruleContent{
		Title: fmt.Sprintf("ConfigMap `%s/%s` exposes credential-shaped keys (`%s`) in plaintext", namespace, name, keysList),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("ConfigMap `%s/%s`: readable by every subject with `get configmaps` in `%s`, ships unencrypted in etcd, surfaces in `kubectl describe` and audit logs", namespace, name, namespace),
		},
		Description: fmt.Sprintf("ConfigMap `%s/%s` contains keys with names matching credential-like patterns: `%s`. The Kubernetes API treats ConfigMaps as non-sensitive: etcd stores them unencrypted by default (encryption-at-rest is opt-in and almost always limited to Secrets), `kubectl describe configmap` prints values inline, audit logs include the data on get/list, and RBAC defaults give workload service accounts much wider read on ConfigMaps than on Secrets.\n\n"+
			"Storing a credential in a ConfigMap therefore violates the basic Kubernetes data-classification model in three ways simultaneously: (1) it appears in plaintext to anyone with `get configmaps` (a much larger set of subjects than `get secrets`); (2) it ends up in cluster backups, etcd dumps, and platform observability tooling that explicitly excludes Secrets; (3) it does not benefit from any of the surface area Kubernetes builds around Secrets (envelope encryption, file-mode 0600 projection, KMS provider, External Secrets Operator).\n\n"+
			"The matched keys are heuristic, since `key` matches both `apiKey` and `public_key`, so review is required before assuming compromise. In practice the pattern is strong: in production clusters this finding correlates with real leaks the majority of the time. Treat as exposed-until-proven-otherwise.",
			namespace, name, keysList),
		Impact: fmt.Sprintf("If any of the flagged keys (`%s`) actually hold a credential, that credential is exposed to a wide audience: every workload SA in `%s`, every backup operator, every audit log consumer, and possibly cluster-mirroring tooling.", keysList, namespace),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a workload in `%s` whose ServiceAccount has `get configmaps` (the typical default `view` role grants it).", namespace),
			fmt.Sprintf("They `kubectl get cm %s -n %s -o yaml` and read the matched keys directly. No decoding needed since ConfigMap data is plaintext.", name, namespace),
			"They identify the credential class (DB connection string, API key, OAuth client_secret, signing key) from the key name and value shape.",
			"They use the credential immediately: DB connection strings often grant the same write permission the application has; API keys often have no IP restriction; client_secrets unlock the upstream identity provider.",
			"Because audit-log review on ConfigMaps is rare, the read goes unnoticed until the upstream credential is rotated for unrelated reasons.",
		},
		Remediation: fmt.Sprintf("Move the credential out of `%s/%s` into a Kubernetes Secret (or, better, an external secret store) and remove the keys from the ConfigMap.", namespace, name),
		RemediationSteps: []string{
			fmt.Sprintf("Inspect each matched key (`%s`) to confirm whether it is a real credential. Some keys like `cache_key_prefix` are false positives.", keysList),
			fmt.Sprintf("For real credentials, create a Secret in `%s` and update consumers (envFrom or volume mounts) to read from the Secret.", namespace),
			"Rotate the credential at its source: if it was already in plaintext in a ConfigMap, treat it as compromised (assume any subject with view-on-configmaps had access).",
			fmt.Sprintf("Remove the credential keys from `%s/%s`. Verify the consumer still works (`kubectl rollout status`).", namespace, name),
			"Wire prevention: a Kyverno cluster policy that warns on `ConfigMap.data` keys matching `password|secret|token|credential|api_?key|access_?key|client_secret|connection_string|dsn`. Pair with External Secrets Operator so the right path of least resistance is to use a real secret store.",
		},
		LearnMore: []models.Reference{
			refK8sConfigMap,
			refK8sSecrets,
			refSecretsHardening,
			{Title: "External Secrets Operator", URL: "https://external-secrets.io/latest/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1552_007, mitreT1078_004},
	}
}

func contentConfigMap002() ruleContent {
	return ruleContent{
		Title: "CoreDNS Corefile contains rewrite or external-forward directives that make the cluster DNS plane mutable from `kube-system/coredns`",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "ConfigMap `kube-system/coredns`: every pod in the cluster uses this Corefile for resolution; a change here is a cluster-wide effect",
		},
		Description: "The CoreDNS Corefile in `kube-system/coredns` contains directives that change DNS behavior in ways that warrant explicit review: `rewrite` directives mutate query names or response data, and `forward` directives that send queries to external resolvers (`8.8.8.8`, `1.1.1.1`, `tls://...`) bypass the cluster's authoritative records and the cluster's egress firewall.\n\n" +
			"Two threat models matter here. (1) **Defensive misconfiguration**: a `rewrite` rule that maps an internal name to an external one can cause apps to talk to attacker-controlled hosts when the rule's intent was something else (typo, copy-paste from a tutorial). External `forward` to public resolvers means DNS queries (which often contain pod names, namespace names, internal service topology) leave the cluster perimeter unencrypted to a third-party operator with no DPA. (2) **Active subversion**: an attacker with write access to the `kube-system/coredns` ConfigMap (a far rarer condition, but exactly the prize for `KUBE-PRIVESC-005` chains) can add a `rewrite` rule that redirects `*.svc.cluster.local` to attacker pods, then capture every connection that does not pin TLS. The result is full cluster-wide MITM, and CoreDNS reloads the Corefile automatically with no operator action needed.\n\n" +
			"This is the most common active-subversion path discussed in DNS-rebinding-in-Kubernetes research: the CoreDNS ConfigMap is structurally a one-shot to compromise resolution for every pod, and clusters often grant `kube-system` ConfigMap write to addon installers, helm-controllers, and network operators that the security team hasn't audited.",
		Impact: "If the Corefile is malicious, every DNS query in the cluster can be silently redirected (including queries for in-cluster services, cloud APIs, and external SaaS), enabling MITM and data exfiltration. If the Corefile is merely sloppy, internal DNS names may leak to public resolvers.",
		AttackScenario: []string{
			"Attacker gains write access to `kube-system/coredns` (often via an over-broad `configmaps` permission on a control-plane SA, or a `KUBE-PRIVESC-005` secret-reads-then-token-theft chain that ends at a kube-system SA).",
			"They edit the Corefile to add `rewrite name regex (.*)\\.cluster\\.local\\. attacker-pod.poc.svc.cluster.local. answer auto`.",
			"CoreDNS reloads automatically (`reload` plugin), and within ~30 seconds every cluster service-discovery query is misdirected.",
			"Apps that don't pin TLS-SNI-to-IP fall over to attacker-pod, which terminates TLS with a self-signed cert (acceptable for many in-cluster integrations using `InsecureSkipVerify: true`).",
			"The attacker harvests credentials from the redirected traffic, then quietly removes the rewrite rule when done. `kube-system/coredns` change history is not audited by most teams.",
		},
		Remediation: "Audit each `rewrite` and `forward` directive against expected DNS topology, lock down write access to the `kube-system/coredns` ConfigMap, and add change detection.",
		RemediationSteps: []string{
			"`kubectl get cm coredns -n kube-system -o yaml` and review every `rewrite/forward` line. Confirm with the platform/networking team that each is intentional.",
			"For `forward` to public resolvers: prefer the cloud provider's private resolver (which respects VPC routing and is logged) over `8.8.8.8/1.1.1.1`. If public is required, restrict via egress NetworkPolicy.",
			"`kubectl auth can-i update configmaps -n kube-system --as=system:serviceaccount:<ns>:<sa>` for every SA. Most do not need this; tighten RBAC and remove cluster-wide `*` resource grants.",
			"Wire change detection: an admission policy (Kyverno) that alerts on any ConfigMap update in `kube-system` named `coredns`, or a GitOps source-of-truth so manual edits diverge visibly.",
			"Add a periodic CronJob that diffs the live Corefile against the GitOps version and pages on drift.",
		},
		LearnMore: []models.Reference{
			refCoreDNSPlugins,
			{Title: "Sysdig — Kubernetes DNS-based MITM via CoreDNS", URL: "https://sysdig.com/blog/kubernetes-coredns-attack/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1071_004, mitreT1556_004, mitreT1565_002},
	}
}
