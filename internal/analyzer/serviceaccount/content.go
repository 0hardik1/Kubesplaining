// Content for ServiceAccount findings. Each builder takes runtime context (subject,
// usage workloads, dangerous capability summary) and returns ruleContent with explicit
// scope, attacker walkthrough, and ordered remediation.
//
// Sources: Kubernetes ServiceAccount docs, Bound ServiceAccount Tokens (KEP-1205), CIS
// Kubernetes Benchmark 5.1.5 / 5.1.6, NSA/CISA Hardening Guide v1.2, MITRE ATT&CK T1078.004,
// "kube-default-deny-sa" patterns, Aqua/CyberArk research on SA-mediated privesc.
package serviceaccount

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
	mitreT1098_004 = models.MitreTechnique{ID: "T1098.004", Name: "Account Manipulation: SSH Authorized Keys / Token Re-use", URL: "https://attack.mitre.org/techniques/T1098/"}
	mitreT1552_007 = models.MitreTechnique{ID: "T1552.007", Name: "Container API", URL: "https://attack.mitre.org/techniques/T1552/007/"}
	mitreT1611     = models.MitreTechnique{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"}
	mitreT1068     = models.MitreTechnique{ID: "T1068", Name: "Exploitation for Privilege Escalation", URL: "https://attack.mitre.org/techniques/T1068/"}
)

var (
	refK8sSAGood       = models.Reference{Title: "Kubernetes — ServiceAccount admin: good practices", URL: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/"}
	refRBACGoodPrac    = models.Reference{Title: "Kubernetes — RBAC good practices", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"}
	refMSThreatMatrix  = models.Reference{Title: "Microsoft — Threat Matrix for Kubernetes", URL: "https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/"}
	refNSAHardening    = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refDisableAutomont = models.Reference{Title: "Kubernetes — automountServiceAccountToken", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server"}
)

// scopeForSubject reports a Cluster scope for cluster-bound subjects (namespace empty)
// and a Namespace scope for namespaced ServiceAccounts. The Detail names the SA so the
// reader can navigate directly.
func scopeForSubject(subject models.SubjectRef) models.Scope {
	if subject.Namespace == "" {
		return models.Scope{
			Level:  models.ScopeCluster,
			Detail: fmt.Sprintf("ServiceAccount `%s` — bound at the cluster scope; permissions apply across every namespace", subject.Name),
		}
	}
	return models.Scope{
		Level:  models.ScopeNamespace,
		Detail: fmt.Sprintf("ServiceAccount `%s/%s` — namespace-scoped subject; mounted by pods in `%s`", subject.Namespace, subject.Name, subject.Namespace),
	}
}

func contentSADefault002(subject models.SubjectRef, workloads, ruleSummary string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Default ServiceAccount `%s/default` carries explicit RBAC — every pod that omits `serviceAccountName` inherits these rights", subject.Namespace),
		Scope: models.Scope{
			Level:  models.ScopeNamespace,
			Detail: fmt.Sprintf("Namespace `%s` — every Pod that does not set `serviceAccountName` mounts the `default` SA's token", subject.Namespace),
		},
		Description: fmt.Sprintf("ServiceAccount `%s/default` has explicit RBAC bindings. Every Pod created in `%s` that does not set `spec.serviceAccountName` is silently bound to this SA, the kubelet projects its token into the pod, and the workload can call kube-apiserver with whatever permissions the bindings grant — without anyone explicitly asking for them.\n\n"+
			"Aggregated rules:\n%s\n\n"+
			"This is one of the most common privilege-escalation gateways in Kubernetes for two reasons: (1) the `default` SA is the *implicit* identity for every misconfigured manifest, so a single binding to it propagates to every team in the namespace; (2) developers iterating on a deployment regularly forget to set `serviceAccountName` and never notice the elevated identity because the API behaves as expected. The Kubernetes RBAC good-practices guide is explicit: \"Avoid granting RBAC to the default service account in any namespace,\" precisely because it converts \"forgetting a field\" into \"granting privilege.\"\n\n"+
			"The right model is to leave the default SA permissionless and require every workload to declare its identity explicitly — turning the implicit-default into a fail-closed signal that something is misconfigured.",
			subject.Namespace, subject.Namespace, ruleSummary),
		Impact: fmt.Sprintf("Any Pod in `%s` that omits `serviceAccountName` quietly mounts a token for these RBAC rules. Compromise of any such pod (RCE in any app) yields immediate API access at the granted privileges. Workloads attached: %s.", subject.Namespace, workloads),
		AttackScenario: []string{
			fmt.Sprintf("Attacker exploits a workload in `%s` that did not set `spec.serviceAccountName` (a common omission).", subject.Namespace),
			"They read `/var/run/secrets/kubernetes.io/serviceaccount/token` from the pod filesystem.",
			"They `curl` the kube-apiserver with the token's bearer header — the granted RBAC applies, even though the developer never knew the SA had any permissions.",
			"They use the granted rights (typical patterns: list secrets in the namespace, list pods cluster-wide, exec into other pods) to extend reach.",
			fmt.Sprintf("Because the binding is to `default` rather than a named SA, future pods in `%s` *also* inherit this identity — every redeploy of every workload in the namespace becomes a potential privesc point.", subject.Namespace),
		},
		Remediation: fmt.Sprintf("Remove all RoleBindings/ClusterRoleBindings to `%s/default`, create dedicated ServiceAccounts per workload, and set `automountServiceAccountToken: false` on the default SA.", subject.Namespace),
		RemediationSteps: []string{
			fmt.Sprintf("List the bindings: `kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]? | .kind == \"ServiceAccount\" and .name == \"default\" and .namespace == \"%s\")'`.", subject.Namespace),
			"For each binding, identify the workloads that actually need the right and create a dedicated SA for them (`kubectl create sa <workload>-sa -n <ns>`); rebind to the dedicated SA.",
			"Delete the bindings to `default` once consumers are migrated.",
			fmt.Sprintf("Patch the default SA to disable token automounting: `kubectl patch sa default -n %s -p '{\"automountServiceAccountToken\": false}'`. Combined with the next step, any pod that forgets `serviceAccountName` will fail closed instead of inheriting tokens.", subject.Namespace),
			"Wire enforcement: a Kyverno policy that warns/denies any new RoleBinding whose subjects contain `default` SA, and any Pod missing an explicit `serviceAccountName`.",
		},
		LearnMore: []models.Reference{
			refK8sSAGood,
			refRBACGoodPrac,
			refDisableAutomont,
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1552_007, mitreT1098_004},
	}
}

func contentSAPrivileged001(subject models.SubjectRef, workloads, ruleSummary string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("ServiceAccount `%s` holds wildcard verbs on wildcard resources (cluster-admin equivalent)", subject.Key()),
		Scope: scopeForSubject(subject),
		Description: fmt.Sprintf("ServiceAccount `%s` is bound to a Role/ClusterRole that grants `verbs: [*]` on `resources: [*]` (and typically `apiGroups: [*]`). This is structurally indistinguishable from `cluster-admin` — every API operation on every resource is authorized.\n\n"+
			"Aggregated rules:\n%s\n\n"+
			"Wildcard-on-wildcard bindings are almost never the right design. They are typically the result of: (a) copy-pasting `cluster-admin` for an operator the team didn't have time to scope down; (b) a wildcard added \"temporarily\" during integration that never got rotated; (c) a third-party operator's installer that ships with `*/*` and assumes the operator runs in a dedicated cluster. None of those reasons survive a security review, but the binding survives because there is no concrete reason to break it. CIS Kubernetes 5.1.1 / 5.1.2 explicitly call out wildcard-on-wildcard as a finding.\n\n"+
			"Workloads using this SA: %s. Any compromise of any of those workloads — a single CVE, a poisoned container image, a leaked configuration file containing the SA token — becomes full cluster compromise immediately. There is no defense-in-depth left.",
			subject.Key(), ruleSummary, workloads),
		Impact: "A single compromise of any pod mounting this SA grants full cluster control: read every Secret, exec into any pod, mutate RBAC, drain nodes, taint scheduling, install backdoor DaemonSets — every API operation succeeds.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any of the workloads using `%s` (or finds the token in any storage that touched it: backup, CI logs, a developer's kubeconfig).", subject.Key()),
			"They `kubectl auth can-i '*' '*' --all-namespaces --token=<stolen-token>` and confirm full reach.",
			"They `kubectl get secrets -A -o yaml` to harvest all credentials cluster-wide (cloud IAM keys, registry pull secrets, application DB passwords, third-party SaaS API keys).",
			"They install a persistent foothold: a DaemonSet using a benign-looking image that runs an attacker reverse-shell on every node, plus a malicious mutating webhook with `failurePolicy: Ignore` so removal does not break clusters.",
			"They cover by deleting their own audit-log entries via `kubectl delete events` (allowed under `*/*`) and rotating the SA's token to invalidate IR's existing copies.",
		},
		Remediation: fmt.Sprintf("Replace the wildcard binding on `%s` with the smallest concrete role that satisfies the workload's actual needs. Treat the existing token as compromised.", subject.Key()),
		RemediationSteps: []string{
			fmt.Sprintf("Identify the binding: `kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]? | .kind == \"ServiceAccount\" and .name == \"%s\" and .namespace == \"%s\")'`.", subject.Name, subject.Namespace),
			"Generate a least-privilege role from the workload's actual API calls — capture them with `audit2rbac` (https://github.com/liggitt/audit2rbac) over a representative window, or read the operator's source for the API verbs it issues.",
			fmt.Sprintf("Create a Role/ClusterRole with the minimum verbs and bind it to `%s`. Verify with `kubectl auth can-i` for the actual operations the workload needs (and only those).", subject.Key()),
			"Delete the wildcard binding and rotate the SA's token (delete and recreate the SA, or rely on projected SA token TTL). Audit-log review for the SA over the last 30 days to gauge possible misuse.",
			"Wire enforcement: a Kyverno cluster policy that fails any RoleBinding/ClusterRoleBinding granting `verbs: ['*']` on `resources: ['*']` to a non-system subject.",
		},
		LearnMore: []models.Reference{
			refRBACGoodPrac,
			refK8sSAGood,
			refMSThreatMatrix,
			refNSAHardening,
			{Title: "audit2rbac — generate minimal RBAC from audit logs", URL: "https://github.com/liggitt/audit2rbac"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1098_004, mitreT1068},
	}
}

func contentSAPrivileged002(subject models.SubjectRef, workloads string, dangerous []string) ruleContent {
	dangerList := strings.Join(dangerous, ", ")
	return ruleContent{
		Title: fmt.Sprintf("ServiceAccount `%s` is mounted by live workloads and has dangerous permissions: %s", subject.Key(), dangerList),
		Scope: scopeForSubject(subject),
		Description: fmt.Sprintf("ServiceAccount `%s` carries one or more dangerous RBAC capabilities (%s) *and* is actively mounted by workloads (%s). The combination matters: a dangerous permission on an unused SA is latent risk; the same permission on an SA that ships in a running pod is a pre-positioned exploitation primitive — the attacker does not need to find the SA token, the pod is the SA token.\n\n"+
			"The flagged capabilities map directly to known privesc paths:\n"+
			"- `secrets` → read service-account tokens of higher-privileged SAs (`KUBE-PRIVESC-005`).\n"+
			"- `create pods` → mount any SA in a new pod, run as root, or set `hostPath: /` to escape (`KUBE-PRIVESC-001`, `KUBE-ESCAPE-*`).\n"+
			"- `mutate workloads` → modify a Deployment to swap its image / SA, gaining the workload's identity (`KUBE-PRIVESC-003`).\n"+
			"- `bind roles` / `bind/escalate` → grant yourself or any SA arbitrary permissions, cluster-wide (`KUBE-PRIVESC-009`, `KUBE-PRIVESC-010`).\n"+
			"- `impersonate` → assume any user/group/SA, instantly bypassing RBAC (`KUBE-PRIVESC-008`).\n"+
			"- `nodes/proxy` → kubelet API access to read all pod logs/exec on a node (`KUBE-PRIVESC-012`).\n\n"+
			"Workloads using this SA: %s. Each is a starting point: any RCE, any leaked container image layer, any logs accidentally containing the token are equivalent to the SA's RBAC.",
			subject.Key(), dangerList, workloads, workloads),
		Impact: fmt.Sprintf("Compromise of any workload using `%s` immediately grants the listed dangerous capabilities — typically a one- or two-hop chain to cluster-admin equivalent (see correlated `KUBE-PRIVESC-*` findings on the same subject).", subject.Key()),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any of the workloads (`%s`) — RCE in the application, malicious image layer, leaked manifest with embedded token.", workloads),
			"They read `/var/run/secrets/kubernetes.io/serviceaccount/token` from the pod.",
			fmt.Sprintf("They use the token to invoke the dangerous capabilities (%s) directly — the token already authenticates as `%s`, no further escalation needed.", dangerList, subject.Key()),
			"For each capability they convert into the matching privesc path: `secrets`→token theft → impersonate higher SA; `bind`→grant self cluster-admin; `pods/create`→privileged pod with hostPath /.",
			"Within minutes they hold an identity equivalent to the most privileged subject reachable from this SA's chain — typically `cluster-admin` if any privesc path connects.",
		},
		Remediation: fmt.Sprintf("Split `%s` into one SA per workload, remove the dangerous capabilities that aren't actually used, and ensure each workload's SA holds only the minimum verbs.", subject.Key()),
		RemediationSteps: []string{
			fmt.Sprintf("Audit which of the workloads (%s) actually exercises each dangerous capability — start with `audit2rbac` over a 7-day window, then ask the workload's owner to confirm.", workloads),
			"For each unique workload, create a dedicated SA and a least-privilege Role/ClusterRole with only the verbs that audit-2rbac observed. Bind only that Role to the new SA.",
			fmt.Sprintf("Migrate workloads to the new dedicated SA (set `spec.serviceAccountName`). Delete the bindings against the original `%s` and rotate its token.", subject.Key()),
			"For capabilities that *no* workload actually exercises, delete the binding entirely.",
			"Wire enforcement: a Kyverno policy that warns when `pods.spec.serviceAccountName` references an SA whose RBAC binding includes any of `[secrets:get, pods:create, rolebindings:create, escalate, impersonate, nodes/proxy:get]`.",
		},
		LearnMore: []models.Reference{
			refRBACGoodPrac,
			refK8sSAGood,
			refMSThreatMatrix,
			refNSAHardening,
			{Title: "audit2rbac — generate minimal RBAC from audit logs", URL: "https://github.com/liggitt/audit2rbac"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1078_004, mitreT1552_007, mitreT1098_004, mitreT1068},
	}
}

func contentSADaemonset001(subject models.SubjectRef, workloads, ruleSummary string, hasRules bool) ruleContent {
	rulesPart := "no aggregated rules"
	if hasRules {
		rulesPart = ruleSummary
	}
	return ruleContent{
		Title: fmt.Sprintf("ServiceAccount `%s` is mounted by a DaemonSet — the SA token lives on every node the DaemonSet schedules to", subject.Key()),
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: fmt.Sprintf("ServiceAccount `%s` — DaemonSet places its token on every node in the cluster (or every node matching the DaemonSet's nodeSelector)", subject.Key()),
		},
		Description: fmt.Sprintf("ServiceAccount `%s` is mounted by a DaemonSet (%s). DaemonSets schedule one pod per matching node, so the kubelet projects this SA's token onto every one of those nodes. From an attacker's perspective, that turns any single node compromise (kernel CVE, runtime escape, host-mount-via-misconfigured-pod, malicious workload that escapes its sandbox) into immediate possession of the SA's identity, scaled by node count.\n\n"+
			"Aggregated rules: %s\n\n"+
			"DaemonSet-mounted SAs are special-case for two reasons:\n"+
			"1. **Distribution**: a typical cluster has tens to thousands of nodes. The token is on each one, in `/var/lib/kubelet/pods/<uid>/volumes/...`. Any node compromise — including ones the security team would normally call \"contained to one node\" — exfiltrates the same token, and rotating one node's token does not invalidate the others (until the next pod re-projection cycle, ~1h with default token TTL).\n"+
			"2. **Privilege**: DaemonSets are typically infrastructure agents (logging, monitoring, CNI, CSI, cluster-autoscaler) that legitimately need cluster-wide reads. So the SA tends to carry above-average permissions: `nodes:get`, `pods:list`, `events:create`, sometimes `secrets:get` for image-pull credentials. Combined with cluster-wide distribution this is a high-leverage credential.",
			subject.Key(), workloads, rulesPart),
		Impact: "A single node compromise yields a token that authorizes whatever this SA's RBAC says, anywhere in the cluster. With DaemonSet-typical permissions (cluster-wide reads, sometimes node-level controls) this is a fast pivot from one host to cluster-wide visibility/influence.",
		AttackScenario: []string{
			"Attacker compromises one node — could be a kernel CVE in a tenant workload, an outdated containerd, or a misconfigured pod with `hostPath: /` they were able to schedule there.",
			fmt.Sprintf("From the host they read `/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected-volumes/token` (the projected token of `%s`).", subject.Key()),
			"They use the token from outside the cluster (`kubectl --token=...`) — the token still works because projection-renewal does not invalidate already-extracted copies until the original expiration.",
			"They use the SA's RBAC for whatever it grants — typically `nodes:get`, `pods:list`, `secrets:get` for image pulls — to locate higher-value targets.",
			"Scale: every node has a copy. Cleanup is per-node, and the team typically only rotates the compromised node's token, leaving the same SA active on all the others.",
		},
		Remediation: fmt.Sprintf("Tighten `%s`'s RBAC to the literal minimum the DaemonSet needs, set short token TTL (`expirationSeconds: 600`) on the projected token, and treat the DaemonSet's image and host mounts as part of the SA's effective trust boundary.", subject.Key()),
		RemediationSteps: []string{
			fmt.Sprintf("Audit `%s`'s actual API calls with `audit2rbac` and pare the bindings down to the minimum verbs. Remove any `secrets:get` unless explicitly required for image pulls.", subject.Key()),
			"In the DaemonSet pod template, project the token with `expirationSeconds: 600` (10 min) instead of the default 1h — this caps the leak window for any single token theft.",
			"Audit the DaemonSet's container image and host mounts: a DaemonSet with `hostPath: /` is itself an escape primitive. Disallow privileged containers, `hostPath`, `hostPID`, `hostNetwork` in the DaemonSet's PodSpec.",
			"Add per-node detection: alert on `kubectl create token <sa>` invocations from outside expected control-plane subjects, and on usage of the SA's name from IPs that are not pod CIDR.",
			fmt.Sprintf("If the DaemonSet does not actually need an API token, set `automountServiceAccountToken: false` on its PodSpec and on `%s` itself.", subject.Key()),
		},
		LearnMore: []models.Reference{
			refK8sSAGood,
			refRBACGoodPrac,
			refDisableAutomont,
			refMSThreatMatrix,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_007, mitreT1078_004},
	}
}
