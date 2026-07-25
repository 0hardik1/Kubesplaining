# Findings Library

The complete catalog of rules Kubesplaining can emit. See [README](../README.md) for usage; this doc is the reference for *what* gets detected.

The tool currently emits **70 distinct rule IDs across 10 modules**. Rule IDs are a public surface: they are stable across releases and referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.

**Structured remediation hints.** Every rule below also ships with an optional `RemediationHint` (kubectl patch, Kyverno / Gatekeeper policy, or RBAC diff) when you pass `--remediation-patches` to `scan`, `scan-resource`, or `report`. The hint appears in JSON / SARIF and as a "Structured remediation" section in the HTML report. Off by default to keep the output minimal; see the per-rule "Remediation" column for the human-readable summary that always renders.

## Findings Library — Implemented

Each rule produces zero or more findings against a given snapshot.

### RBAC ([internal/analyzer/rbac/analyzer.go](../internal/analyzer/rbac/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-PRIVESC-017 | CRITICAL | Wildcard cluster-admin style permissions | Wildcard verbs AND resources AND apiGroups on a subject | Replace wildcards with the minimal explicit set |
| KUBE-PRIVESC-008 | CRITICAL | Impersonation permissions | `impersonate` on users/groups/serviceaccounts | Grant impersonate only to tightly controlled admin workflows |
| KUBE-PRIVESC-009 | CRITICAL | RBAC `bind` or `escalate` permission | `bind`/`escalate` on roles/clusterroles | Remove from non-admin identities |
| KUBE-PRIVESC-010 | CRITICAL | Role binding modification can self-grant access | create/update/patch on rolebindings/clusterrolebindings | Limit binding writes to a tight admin boundary |
| KUBE-PRIVESC-011 | HIGH | CSR create + approve mints a `system:masters` cert | Cluster-scoped `create certificatesigningrequests` AND `update/patch certificatesigningrequests/approval` held by the same subject | Split the two halves across different subjects; reserve approval for the kube-controller-manager auto-approver or a strict admin allowlist |
| KUBE-PRIVESC-012 | CRITICAL | Node proxy access | `get` on `nodes/proxy` (kubelet abuse) | Keep kubelet-facing permissions off application identities |
| KUBE-PRIVESC-001 | HIGH | Pod creation access can be used for token theft | `create` on pods | Route deployments through controlled automation |
| KUBE-PRIVESC-002 | HIGH | Pod creation can launch a privileged escape pod | `create` on pods AND the target namespace's Pod Security Admission does not block privileged pods (no `enforce` label, or `enforce=privileged`). Emitted in addition to -001: token theft and host escape are distinct impacts of the same grant | Enforce PSA `baseline`/`restricted` on the namespace; route pod creation through controlled automation |
| KUBE-PRIVESC-004 | HIGH | Pod exec/attach enables token theft | `create`/`get` on `pods/exec` or `pods/attach` | Remove exec/attach from application identities; reserve for break-glass debugging |
| KUBE-PRIVESC-013 | HIGH | Ephemeral container injection bypasses pod hardening | `update`/`patch` on `pods/ephemeralcontainers` | Remove the grant; an injected debug container ignores the target pod's `securityContext` |
| KUBE-PRIVESC-015 | MEDIUM | Port-forward reaches internal-only services | `create` on `pods/portforward` (lateral movement, not a cluster sink) | Remove from application identities; port-forward tunnels past NetworkPolicy to internal databases / dashboards |
| KUBE-PRIVESC-003 | HIGH | Workload controller modification can create privileged pods | create/update/patch on deployments/daemonsets/statefulsets/jobs/cronjobs | Separate deploy automation from runtime identities |
| KUBE-PRIVESC-005 | HIGH | Secret listing (enumerate every Secret) | `list`/`watch` on secrets — one call returns every Secret's contents | Scope to namespaces/workloads that actually need it |
| KUBE-PRIVESC-006 | HIGH | Secret read (named get) | `get` on secrets without `list`/`watch` (the narrower, named-read counterpart to -005) | Scope to the specific Secrets the workload needs |
| KUBE-PRIVESC-007 | HIGH | Secret create + get mints a ServiceAccount token | `create` AND `get` on secrets held by the same subject in composing scopes — mint a legacy token Secret pointed at a privileged SA, then read the controller-populated token | Split the two halves across subjects; prefer the TokenRequest API over legacy token Secrets |
| KUBE-PRIVESC-014 | HIGH | Service account token creation | `create` on `serviceaccounts/token` | Limit to trusted control-plane components |
| KUBE-PRIVESC-016 | HIGH | Pod delete + node manipulation migrates pods to an attacker node | `delete` on pods AND cluster-scoped `update`/`patch` on `nodes/status` (cordon/taint) or `delete` on nodes — evict a sensitive pod and force it to reschedule onto a controlled node | Separate node-lifecycle automation from workload identities |
| KUBE-RBAC-OVERBROAD-001 | CRITICAL | Non-system subject bound to cluster-admin | Direct binding of human/SA to the `cluster-admin` ClusterRole | Replace with a least-privilege custom role |
| KUBE-RBAC-STALE-001 | MEDIUM | Binding references missing Role/ClusterRole | (Cluster)RoleBinding whose `roleRef` points at a Role/ClusterRole absent from the snapshot (built-in `cluster-admin`/`admin`/`edit`/`view` are allowlisted) | Delete the binding or restore the role from version control |
| KUBE-RBAC-STALE-002 | LOW | Binding lists non-existent ServiceAccount subject | Binding subject is a ServiceAccount that does not exist in the cluster (User/Group subjects are not checked — Kubernetes has no User/Group inventory) | Delete the binding or restore the ServiceAccount |

### Least Privilege ([internal/analyzer/leastprivilege/analyzer.go](../internal/analyzer/leastprivilege/analyzer.go))

These rules compare granted RBAC permissions against observed usage from a kube-apiserver audit log. They fire only when `--audit-log` is supplied — see [`docs/audit-logs.md`](audit-logs.md) for how to obtain one on self-managed, kind, and EKS clusters. Findings are advisory recommendations (Medium / Low severity) and bypass the privesc chain-amplification pass.

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-RBAC-UNUSED-ROLE-001 | MEDIUM | Role granted to mounted SA but never exercised | A workload's ServiceAccount has zero observed API calls in the audit window — the entire Role binding is latent privesc surface | Remove the binding (or replace with a no-op until the workload is retired) |
| KUBE-RBAC-UNUSED-RULE-001 | LOW | Every rule in a Role is unused | The SA is active elsewhere but no observed call matches any (verb, resource) triple in this particular Role | Drop the binding that links the SA to the Role |
| KUBE-RBAC-UNUSED-VERB-001 | LOW | Some verbs in a Role are unused | A subset of granted verbs were never exercised; the Role can be narrowed | Replace with a Role that lists only the observed verbs |
| KUBE-RBAC-WILDCARD-USED-PARTIAL-001 | MEDIUM | Wildcard `verbs: ["*"]` only partially exercised | The Role grants `*` on a resource, but the SA only uses a small subset of verbs there | Replace `*` with the explicit observed verb list |

### Pod Security ([internal/analyzer/podsec/analyzer.go](../internal/analyzer/podsec/analyzer.go))

> **Admission-aware reweight.** Every pod-security finding below is filtered through [`internal/analyzer/admission/mitigation/`](../internal/analyzer/admission/mitigation/psa.go) before the report is written. The default `--admission-mode=suppress` drops findings that the namespace's `pod-security.kubernetes.io/enforce` label would block at admission time (e.g. `restricted` blocks `privileged`, `hostPath`, `hostNetwork/PID/IPC`, `allowPrivilegeEscalation`, `runAsRoot`; `baseline` blocks the first four but not `allowPrivilegeEscalation` or `runAsRoot`). The suppression count appears in the HTML report header banner and `admission-summary.json`. Use `--admission-mode=attenuate` to keep findings visible at reduced severity (severity drops exactly one bucket, score snaps to the new bucket's floor) with an `admission:mitigated-psa-<level>` tag. Use `--admission-mode=off` to disable the reweight entirely. Namespaces with only `audit`/`warn` labels are never suppressed — they pick up `admission:audit-psa-<level>` / `admission:warn-psa-<level>` tags so the report can flag "logged but not blocked."

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-ESCAPE-001 | CRITICAL | Privileged container | `securityContext.privileged: true` | Drop privileged, add only the specific capabilities needed |
| KUBE-ESCAPE-002 | CRITICAL | Host PID enabled | `hostPID: true` on pod/pod template | Remove unless workload is a debug/sidecar on trusted nodes |
| KUBE-ESCAPE-005 | CRITICAL | Docker socket mount | hostPath `/var/run/docker.sock` | Remove; use CSI / image-build sidecars instead |
| KUBE-CONTAINERD-SOCKET-001 | CRITICAL | Containerd socket mount | hostPath `/var/run/containerd/containerd.sock` | Remove; equivalent to giving the pod node-root |
| KUBE-ESCAPE-006 | CRITICAL | Root filesystem hostPath mount | hostPath mounting `/` | Replace with scoped ConfigMaps/Secrets/CSI |
| KUBE-ESCAPE-003 | HIGH | Host network enabled | `hostNetwork: true` | Use pod networking unless genuinely required |
| KUBE-ESCAPE-004 | HIGH | Host IPC enabled | `hostIPC: true` | Disable unless trusted node-level component |
| KUBE-ESCAPE-008 | HIGH | Host log directory mounted | hostPath `/var/log` | Use a log collector sidecar instead |
| KUBE-HOSTPATH-001 | HIGH | HostPath volume mount | Generic hostPath mount | Prefer ConfigMaps/Secrets/CSI |
| KUBE-PV-HOSTPATH-001 | HIGH | PVC mounts a PV backed by a sensitive hostPath | PSA cannot see through PVC -> PV; flagged when the bound PV uses a sensitive hostPath (`/`, `/etc`, `/proc`, `/var/run/{docker,containerd}.sock`, `/var/lib/kubelet`, `/var/log`, ...) | Replace `spec.hostPath` on the PV with a CSI driver / `local` volume; restrict who can create hostPath PVs cluster-wide |
| KUBE-PODSEC-APE-001 | HIGH | Privilege escalation allowed in container | `allowPrivilegeEscalation` missing or `true` | Set `allowPrivilegeEscalation: false` |
| KUBE-PODSEC-CAPS-001 | CRITICAL/HIGH/MEDIUM | Container adds a dangerous Linux capability | `capabilities.add` (or `add: [ALL]`) includes any of `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `NET_ADMIN`, `BPF`, `SYS_PTRACE`, `DAC_OVERRIDE`, `MKNOD`, `SYS_CHROOT`, `NET_RAW`, `AUDIT_WRITE` (one finding per container × capability) | Drop the capability; set `capabilities.drop: [ALL]` and add back only what's required (typically nothing, or `NET_BIND_SERVICE`) |
| KUBE-PODSEC-PROCMOUNT-001 | HIGH | Container requests Unmasked /proc | `securityContext.procMount: Unmasked` (explicit opt-in) | Remove the field (default `Default` is safe); enforce PSA `baseline` |
| KUBE-PODSEC-ROOT-001 | MEDIUM | Container runs as root | UID 0 or `runAsNonRoot: false` | Set a non-zero UID and `runAsNonRoot: true` |
| KUBE-PODSEC-READONLY-001 | MEDIUM | Container has a writable root filesystem | `readOnlyRootFilesystem` missing or `false` | Set `readOnlyRootFilesystem: true`; mount `emptyDir` for legitimate write paths |
| KUBE-PODSEC-SECCOMP-001 | MEDIUM | Container runs without a seccomp profile | `seccompProfile` missing or `Unconfined` at both pod and container level | Set `seccompProfile.type: RuntimeDefault` (or `Localhost` with a profile) |
| KUBE-PSA-LABELS-001 | MEDIUM | Namespace runs Baseline violators but has no PSA `enforce` label | Namespace has at least one Pod that triggers a PSA Baseline check (`privileged`/`hostNetwork`/`hostPID`/`hostIPC`/`hostPath`/`procMount`) AND `pod-security.kubernetes.io/enforce` is missing or set to `privileged` | Apply `pod-security.kubernetes.io/{enforce,audit,warn}` labels at `baseline` (or `restricted`); use `enforce: privileged` paired with `audit/warn: baseline` only when permissive workloads are intentional |
| KUBE-SA-DEFAULT-001 | MEDIUM | Default service account in use | Workload mounts the namespace `default` SA | Bind a dedicated least-privilege SA |
| KUBE-IMAGE-LATEST-001 | LOW | Mutable image tag used | `:latest` or no tag | Pin to an immutable tag or digest |

### Container Security ([internal/analyzer/containersec/analyzer.go](../internal/analyzer/containersec/analyzer.go))

This module surfaces container-template settings that weaken runtime hardening without granting RBAC. Findings aggregate per workload (controller-owned pods are skipped to avoid duplicate findings, mirroring the podsec module). The image-pin rule is intentionally scoped to digest pinning so it does not duplicate `KUBE-IMAGE-LATEST-001` above, which already flags mutable image tags.

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-CONTAINER-LIFECYCLE-001 | MEDIUM | Container declares a non-trivial lifecycle exec hook | `lifecycle.postStart.exec` or `lifecycle.preStop.exec` with a command beyond `sleep N` | Move the work into the image or an init container; if needed, replace inline `sh -c` with a small auditable script |
| KUBE-CONTAINER-LIMITS-001 | MEDIUM | Container missing CPU / memory limits or requests | One or more of `resources.{limits,requests}.{cpu,memory}` is unset on a container template | Set explicit `requests` + `limits`; add a namespace `LimitRange` default and a `ResourceQuota` |
| KUBE-CONTAINER-IMAGE-001 | MEDIUM | Container image is not digest-pinned and pulled `Always` | Image lacks `@sha256:` and `imagePullPolicy: Always` (explicit or kubelet default for `:latest`) | Pin to `registry/app@sha256:<digest>`; sign and verify with cosign / Sigstore |
| KUBE-CONTAINER-PROBE-001 | LOW | Container has neither liveness nor readiness probe | Both `livenessProbe` and `readinessProbe` are absent on a container template | Add a readiness probe gated on real dependencies and a small liveness probe; tune `initialDelaySeconds` |

### Network Policy ([internal/analyzer/network/analyzer.go](../internal/analyzer/network/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-NETPOL-COVERAGE-001 | HIGH | Namespace has no NetworkPolicies | Non-system namespace with zero policies | Add a default-deny, then allow explicitly |
| KUBE-NETPOL-WEAKNESS-002 | HIGH | NetworkPolicy permits internet egress | Egress rule targets `0.0.0.0/0` or `::/0` | Restrict to required CIDRs or services |
| KUBE-NETPOL-IMDS-001 | HIGH | Workload egress can reach cloud IMDS `169.254.169.254` | No egress policy applies OR an explicit ipBlock admits the IMDS endpoint without an `except:` carve-out | Apply a default-deny-egress policy and carve out IMDS with `except: [169.254.169.254/32]`; pair with IMDSv2 hop-limit = 1 |
| KUBE-NETPOL-COVERAGE-002 | MEDIUM | Workload is not selected by any NetworkPolicy | Pod in a policy-bearing namespace but no policy matches it | Add a selector or apply a baseline policy |
| KUBE-NETPOL-COVERAGE-003 | MEDIUM | Ingress policies present but egress remains open | Namespace has ingress rules but no egress | Add explicit egress rules or a default-deny egress |
| KUBE-NETPOL-WEAKNESS-001 | MEDIUM | NetworkPolicy allows ingress from all namespaces | Empty namespace selector in ingress | Use explicit namespace labels |
| KUBE-NETPOL-CROSSNS-001 | MEDIUM | NetworkPolicy bridges a sensitive namespace | Ingress or egress peer's `namespaceSelector` matches a sensitive namespace (`kube-system`, `kube-public`, `kube-node-lease`, `default`, `gatekeeper-system`) other than the policy's own, or is empty (matches all) | Replace the cross-namespace peer with a narrow `matchLabels` + `podSelector` pair |

### Admission Webhooks ([internal/analyzer/admission/analyzer.go](../internal/analyzer/admission/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-ADMISSION-001 | HIGH | Security-critical webhook uses `failurePolicy: Ignore` | Webhook targets pods/workloads but fails open | Use `failurePolicy: Fail` for security webhooks |
| KUBE-ADMISSION-002 | MEDIUM | Webhook can be bypassed via object labels | `objectSelector` keys on a workload-controlled label | Move rule to fields the workload cannot forge |
| KUBE-ADMISSION-003 | MEDIUM | Webhook excludes sensitive namespaces | `namespaceSelector` exempts `kube-system` / `*-system` | Confirm exemption is intentional, narrow if not |
| KUBE-ADMISSION-NO-POLICY-ENGINE-001 | MEDIUM | Cluster has no PSA enforce labels and no detected policy engine | No namespace carries `pod-security.kubernetes.io/enforce=baseline\|restricted` AND zero ValidatingAdmissionPolicy / Kyverno / Gatekeeper resources observed | Apply PSA labels per namespace, install Kyverno/Gatekeeper, or author ValidatingAdmissionPolicy resources |

#### Admission tags

These appear on `Finding.Tags` (visible in JSON, CSV, and SARIF output) and describe the relationship between a finding and the cluster's admission controls. None change the score.

- `admission:audit-psa-<level>` / `admission:warn-psa-<level>` — the finding's namespace has a PSA `audit` or `warn` label at the given level. PSA logs the violation but does not block the workload, so the finding stays at full severity.
- `admission:mitigated-psa-<level>` — `--admission-mode=attenuate` dropped the finding's severity by one bucket because the namespace's PSA `enforce` label would block the spec.
- `admission:policy-engine-detected:<engine>` — appended when an admission policy engine (`kyverno`, `gatekeeper`, `vap`) was observed in the snapshot but kubesplaining didn't evaluate its rules. One tag per detected engine. Score is unchanged. Findings already suppressed by PSA do not receive this tag (they're gone from the slice before this stage runs).

### Secrets & ConfigMaps ([internal/analyzer/secrets/analyzer.go](../internal/analyzer/secrets/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-SECRETS-001 | HIGH | Long-lived service account token secret | `type: kubernetes.io/service-account-token` | Prefer projected tokens; delete legacy secrets |
| KUBE-CONFIGMAP-002 | HIGH | CoreDNS configuration contains risky directives | `rewrite` / `forward` in Corefile | Review intent; restrict write access to coredns configmap |
| KUBE-CONFIGMAP-CREDS-001 | HIGH | ConfigMap key matches a high-confidence credential pattern | Per-key match on `password`/`passwd`/`secret`/`token`/`api_key`/`apikey`/`aws_secret_access_key`/`dsn`/`connection_string`/`client_secret`/`private_key`/`access_key` | Move credential to a Secret or external secret store; remove the key |
| KUBE-SECRETS-002 | MEDIUM | Opaque secret stored in kube-system | User `Opaque` secret in `kube-system` | Move to an app namespace and restrict readers |
| KUBE-CONFIGMAP-001 | MEDIUM | ConfigMap contains credential-like keys | Key name matches `password`/`token`/`key`/`api_key`/… | Move to a Secret or external secret manager |
| KUBE-SECRETS-CROSSNS-001 | MEDIUM | Workload SA can read Secrets in another namespace | Pod-mounted ServiceAccount has `get`/`list`/`watch` on `secrets` in a namespace other than where the workload runs (one finding per `(subject, target_namespace)`) | Move workload into target ns, narrow to Role + `resourceNames`, or use operator selector mechanisms |
| KUBE-SECRETS-TLS-EXPIRY-001 | MEDIUM | TLS Secret expired or expires within 30 days | `type: kubernetes.io/tls` with `cert-manager.io/not-after` (or `notafter`/`expiration`) annotation in the past or within 30d. Best-effort: secrets without the annotation are silently skipped | Force renewal via cert-manager (`cmctl renew`), check Issuer health, add expiry alerts |
| KUBE-SECRETS-STALE-001 | LOW | Secret unreferenced by any Pod or ServiceAccount | Secret name not found in pod env / envFrom / volumes / SA `secrets` / SA `imagePullSecrets`. Skips `service-account-token` type | Confirm no out-of-snapshot consumer; rotate at source; delete |

### Service Account ([internal/analyzer/serviceaccount/analyzer.go](../internal/analyzer/serviceaccount/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-SA-PRIVILEGED-001 | CRITICAL | Service account has cluster-admin style permissions | SA with wildcard verbs on wildcard resources | Replace wildcards with tightly scoped roles |
| KUBE-SA-PRIVILEGED-002 | HIGH/CRITICAL | Workload-mounted SA has dangerous permissions | Mounted SA with secret reads / pod create / RBAC mutation / impersonate | Split by workload, drop the high-risk permissions |
| KUBE-SA-DEFAULT-002 | HIGH | Default service account has explicit RBAC permissions | Namespace `default` SA carries non-trivial bindings | Create dedicated SAs; keep `default` unprivileged |
| KUBE-SA-DAEMONSET-001 | MEDIUM/HIGH | Service account used by a DaemonSet | Token mounted on every node | Scope SA narrowly; treat as per-node credential |

### Privilege Escalation Paths ([internal/analyzer/privesc/analyzer.go](../internal/analyzer/privesc/analyzer.go))

These findings are emitted **per `(source subject, sink)` pair** found by BFS on the escalation graph. Severity is attenuated by chain length: hops ≥ 3 drop one bucket, and score is `base − 0.5 × (hops − 1)`, clamped to `[1, 10]`.

| Rule ID | Base Sev | Title template | Sink reached |
| --- | --- | --- | --- |
| KUBE-PRIVESC-PATH-CLUSTER-ADMIN | CRITICAL (9.8) | `<subject>` can reach cluster-admin equivalent in N hop(s) | Wildcard `*/*/*` holder or cluster-admin-bound subject |
| KUBE-PRIVESC-PATH-SYSTEM-MASTERS | CRITICAL (9.6) | `<subject>` can reach system:masters in N hop(s) | Impersonation chain ending in the `system:masters` group |
| KUBE-PRIVESC-PATH-NODE-ESCAPE | CRITICAL (9.4) | `<subject>` can reach node escape in N hop(s) | Ability to create/exec a pod with privileged / hostPID / hostNetwork / hostIPC / sensitive hostPath |
| KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS | HIGH (8.6) | `<subject>` can reach kube-system secrets in N hop(s) | Cluster-wide or kube-system `get`/`list` on secrets |
| KUBE-PRIVESC-PATH-NAMESPACE-ADMIN | HIGH (7.6) | `<subject>` can reach namespace-admin in `<ns>` in N hop(s) | Namespace-scoped `create rolebindings` or `bind/escalate roles` (one sink per affected namespace) |
| KUBE-PRIVESC-PATH-AWS-IAM-ROLE | HIGH (8.0) | `<subject>` can assume an external AWS IAM role in N hop(s) | Paths terminating at an external `aws-iam` node introduced by an IRSA binding. EKS-only. The external IAM node is treated as a terminal sink by the pathfinder, so every IRSA-annotated SA produces one finding per (SA, IAM role) pair. When aws-auth ALSO maps the same ARN onward (to `system:masters` or a cluster-admin-bound custom group), the pathfinder continues traversal through the external node so the longer `KUBE-PRIVESC-PATH-SYSTEM-MASTERS` / `KUBE-PRIVESC-PATH-CLUSTER-ADMIN` chain surfaces as a separate finding. |
| KUBE-CONFUSED-DEPUTY-001 | HIGH | `<subject>` can reach `<sink>` in N hop(s) via an operator it can steer | Any path whose **first** hop is the `operator_reconcile` action. This is a technique overlay, not a distinct sink: the rule ID is substituted in `findingFromPath` when the chain opens with a confused-deputy bridge, and the chain still terminates at whatever the controller itself reaches. Detection: the subject holds `create`/`update`/`patch` on a catalogued operator custom resource AND that operator's controller ServiceAccount exists in the cluster. Catalog and precision gate live in [`internal/analyzer/privesc/deputy.go`](../internal/analyzer/privesc/deputy.go). Remediation: scope the tenant's CR write access, or run the reconciler with impersonation so it acts as the requester rather than as itself. |

Edge techniques that can appear in a hop chain: `KUBE-PRIVESC-001` (pod create), `-002` (pod create into a privileged-allowing namespace → node escape), `-004` (pod exec/attach), `-005`/`-006` (secrets list/read), `-007` (secret create + get → token mint), `-008` (impersonate), `-009` (bind/escalate), `-010` (rolebinding modify, and the `colocated_sa_token_theft` continuation out of a namespace-admin sink), `-011` (CSR create + approve), `-012` (nodes/proxy), `-013` (ephemeral container injection), `-014` (serviceaccounts/token), `-016` (delete pods + node manipulation → node escape), `-017` (wildcard), `KUBE-CONFUSED-DEPUTY-001` (operator reconcile bridge), `KUBE-ESCAPE-CONTROLPLANE-001` (control-plane PKI theft / static-pod admission bypass, emitted only when the snapshot has a control-plane node with no `NoSchedule` taint), plus `KUBE-ESCAPE-00{1,2,3,4,5,6,8}` / `KUBE-HOSTPATH-001` for the pod-escape terminal edge.

`system:*` subjects are skipped as traversable intermediates so paths do not launder through the control plane. Non-`system:` ServiceAccounts in `kube-system` / `kube-public` / `kube-node-lease` ARE traversable as intermediates (a co-located controller SA is what real escalations launder through) but are never seeded as path-search sources, which would report the control plane escalating to itself.

Each path finding ships with an `escalation_path` array: one `EscalationHop` per step, with `from_subject`, `to_subject`, `action`, `permission`, and a human-readable `gains` line.

### Cloud Provider Integration: EKS ([internal/analyzer/cloud/eks/](../internal/analyzer/cloud/eks/))

These rules fire only when the snapshot's `metadata.cloudProvider` resolves to `eks`. The collector auto-detects EKS from node labels (`eks.amazonaws.com/nodegroup`, `eks.amazonaws.com/compute-type`); operators can force or disable detection with `--cloud-provider auto|eks|gke|aks|none` on `scan`. Cloud findings also feed the privesc BFS, so an IRSA-annotated ServiceAccount whose IAM role is mapped onward via aws-auth surfaces as a `KUBE-PRIVESC-PATH-AWS-IAM-ROLE` (terminal) or chains into `KUBE-PRIVESC-PATH-SYSTEM-MASTERS` when aws-auth maps the same ARN to `system:masters`.

**Known limitation: EKS Access Entries are not yet modeled.** AWS introduced [EKS Access Entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html) in 2023 as the modern replacement for the `aws-auth` ConfigMap, and AWS recommends migrating to them. The `KUBE-CLOUD-AWSAUTH-*` rule family reads the `kube-system/aws-auth` ConfigMap only. A cluster that has been fully migrated to Access Entries will look like "no aws-auth ConfigMap present" to the collector and the analyzer falls silent on the entire IAM-to-RBAC class. Detecting Access Entries requires an AWS API call (the entries live in the EKS control plane, not in the cluster snapshot), which is outside the scope of the offline static analyzer; tracked as a follow-up issue (see [PLAN.md](../PLAN.md)). Until then, pair kubesplaining with an AWS-side audit (`aws eks list-access-entries`, AWS Config rule `eks-access-entry-no-admin`, or Prowler's EKS checks) when assessing newer EKS clusters.

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001 | HIGH | aws-auth maps IAM principal to `system:masters` | `kube-system/aws-auth` ConfigMap has a `mapRoles` or `mapUsers` entry whose `groups` includes `system:masters` (the built-in cluster-admin group on EKS) | Remove the `system:masters` group from the entry; create a least-privilege ClusterRoleBinding for the IAM principal instead, or use AWS Access Entries which sidestep aws-auth entirely |
| KUBE-CLOUD-AWSAUTH-OVERBROAD-001 | MEDIUM | aws-auth maps IAM principal to a group bound to an admin-equivalent ClusterRole | Entry's custom group (not `system:masters`) is the subject of a ClusterRoleBinding whose `roleRef` is the built-in `cluster-admin` ClusterRole OR any custom ClusterRole containing a `verbs:[*], resources:[*], apiGroups:[*]` rule. Indirect admin reach via aws-auth + a custom group. Evidence carries `viaBinding` (the CRB name) and `viaClusterRole` (the actual role behind it) so operators can disambiguate built-in from custom admin paths | Replace the admin-equivalent ClusterRoleBinding for that group with a scoped ClusterRole, or drop the IAM principal's aws-auth membership |
| KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001 | INFO | aws-auth ConfigMap contains malformed YAML | `mapRoles` or `mapUsers` payload fails YAML decode. Diagnostic only: surfaces that downstream aws-auth detectors skipped this key | Repair the malformed YAML so kubesplaining can re-evaluate it; validate with `yq` / `yamllint` before re-applying |
| KUBE-CLOUD-IRSA-ADMIN-ROLE-001 | HIGH | ServiceAccount bound to admin-flavored IAM role via IRSA | SA's `eks.amazonaws.com/role-arn` annotation points at an IAM role matching `AWSReservedSSO_AdministratorAccess_<hex>` (score 9.2, reason `reserved-sso-admin`) or a role name containing `Administrator`, `FullAccess`, or `PowerUserAccess` (score 7.8, reason `admin-substring`). **Detection scope:** this is a name heuristic. kubesplaining reads role ARNs from the snapshot and never calls the AWS IAM API, so a role with admin-equivalent policies but a non-suggestive name (e.g. `DataPlatform`, `BreakGlass`, `OpsRole`) will not be flagged. Pair this rule with an IAM-side auditor (`iam-policy-reader`, AWS Access Analyzer, Prowler) so the offline detection plus the live policy review cover both shapes of risk | Replace the admin role with a least-privilege IAM role scoped to the API actions the workload actually needs; trust policy should pin the SA's OIDC subject |
| KUBE-CLOUD-IRSA-MISSING-001 | LOW | Pod talks to AWS but its ServiceAccount has no IRSA annotation | Pod (or controller pod template) has AWS-SDK hints (image basename `aws-cli`/`awscli`/`aws-sdk` or `amazon/aws-*` prefix, or any `AWS_*` env var other than `AWS_REGION`/`AWS_DEFAULT_REGION`) AND the SA it would run as carries no `eks.amazonaws.com/role-arn` annotation | Create a least-privilege IAM role for the workload and annotate its ServiceAccount with `eks.amazonaws.com/role-arn` so AWS SDK calls hit STS AssumeRoleWithWebIdentity instead of falling back to the node IAM role |
| KUBE-CLOUD-IMDS-PIVOT-001 | HIGH | Pod can reach IMDS without IRSA carve-out (EKS node-IAM pivot) | Provider is EKS AND `network.IMDSReachable` says the pod can reach `169.254.169.254` AND the pod's SA has no IRSA annotation AND the pod is not scheduled to a Fargate node. Fargate detection prefers `node.Spec.ProviderID` (prefix `aws:///fargate/`, set by the EKS control plane and not user-patchable) over the mutable `eks.amazonaws.com/compute-type=fargate` label. `network.IMDSReachable` reports `host-network` as a third reason when `pod.Spec.HostNetwork: true` regardless of NetworkPolicy posture, since NetPol does not apply to host-network pods | Bind the SA to a least-privileged IRSA role AND apply an egress NetworkPolicy that carves IMDS out (`except: [169.254.169.254/32]`); enforce IMDSv2 hop-limit 1 on the EKS nodegroup. For host-network workloads, drop `hostNetwork: true` if not strictly required (IMDSv2 hop-limit is the only line of defense otherwise) |
| KUBE-CLOUD-PROVIDER-UNKNOWN-001 | INFO | Cloud provider could not be detected | Reserved diagnostic for clusters where node labels do not match any known provider shape. Currently emitted only via explicit override; the auto-detection path stays silent on unknown providers | None: operator may pass `--cloud-provider none` to suppress the slot, or supply the correct provider via `--cloud-provider <eks\|gke\|aks>` to enable provider-specific rules |

## Findings Library — Planned

The following rules are on the roadmap but not yet implemented. See [PLAN.md](../PLAN.md) for status and priority.

For a deep gap analysis of privilege-escalation methodologies kubesplaining does **not** yet model — new RBAC/API primitives, confused-deputy paths through privileged controllers, admission-layer abuse, MITM sinks, node/PKI escapes, multi-cloud identity, and long multi-hop chains the current BFS cannot surface, each mapped to a proposed sink / graph edge / rule ID — see [`privesc-research.md`](privesc-research.md).

**Pod Security** — exhaustive dangerous-capability list (SYS_PTRACE, DAC_OVERRIDE, SYS_MODULE, SYS_RAWIO, MKNOD, AUDIT_WRITE, …); legacy PSP permissiveness. (PersistentVolume hostPath bypass is now `KUBE-PV-HOSTPATH-001`; PSA namespace label assessment is now `KUBE-PSA-LABELS-001`.)

**Network** — cross-namespace communication map; egress to cloud metadata endpoint `169.254.169.254`.

**Secrets** — `aws-auth` ConfigMap analysis; EncryptionConfiguration audit. (Stale/unreferenced secrets, cross-namespace secret references, TLS secret expiry, and ConfigMap credential heuristics shipped in Wave 1 slot #12 above.)

**Service Account** — cross-module risk correlation; DaemonSet blast-radius flag.

**Admission** — "no mutating webhook present" / "no policy engine detected" posture findings; ValidatingAdmissionPolicy (v1 CEL) collection + cel-go evaluation; operator-attestation flow for Kyverno / Gatekeeper effect that cannot be reproduced offline (see Phase 4 of the admission-aware design).

**Container Security** — missing resource limits/requests (DoS), missing probes, lifecycle exec commands, image registry allowlist / digest pinning.

**Node** — kubelet version CVE hints, control-plane taints, workloads on control-plane nodes.

**etcd & Control Plane** — API server LB/NodePort exposure, `/var/lib/etcd` hostPath, kubelet anonymous auth / read-only port.

**Namespace Isolation** — per-namespace security score, cross-namespace risk matrix.

**Cloud Provider** (remaining): GKE Workload Identity; AKS managed identities. (EKS aws-auth + IRSA + IMDS-pivot + privesc cloud-identity edges shipped in slot #15 above.)
