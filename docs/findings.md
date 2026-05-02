# Findings Library

The complete catalog of rules Kubesplaining can emit. See [README](../README.md) for usage; this doc is the reference for *what* gets detected.

The tool currently emits **41 distinct rule IDs across 7 modules**. Rule IDs are a public surface — they are stable across releases and referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.

## Findings Library — Implemented

Each rule produces zero or more findings against a given snapshot.

### RBAC ([internal/analyzer/rbac/analyzer.go](../internal/analyzer/rbac/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-PRIVESC-017 | CRITICAL | Wildcard cluster-admin style permissions | Wildcard verbs AND resources AND apiGroups on a subject | Replace wildcards with the minimal explicit set |
| KUBE-PRIVESC-008 | CRITICAL | Impersonation permissions | `impersonate` on users/groups/serviceaccounts | Grant impersonate only to tightly controlled admin workflows |
| KUBE-PRIVESC-009 | CRITICAL | RBAC `bind` or `escalate` permission | `bind`/`escalate` on roles/clusterroles | Remove from non-admin identities |
| KUBE-PRIVESC-010 | CRITICAL | Role binding modification can self-grant access | create/update/patch on rolebindings/clusterrolebindings | Limit binding writes to a tight admin boundary |
| KUBE-PRIVESC-012 | CRITICAL | Node proxy access | `get` on `nodes/proxy` (kubelet abuse) | Keep kubelet-facing permissions off application identities |
| KUBE-PRIVESC-001 | HIGH | Pod creation access can be used for token theft | `create` on pods | Route deployments through controlled automation |
| KUBE-PRIVESC-003 | HIGH | Workload controller modification can create privileged pods | create/update/patch on deployments/daemonsets/statefulsets/jobs/cronjobs | Separate deploy automation from runtime identities |
| KUBE-PRIVESC-005 | HIGH | Secret read access | `get`/`list`/`watch` on secrets | Scope to namespaces/workloads that actually need it |
| KUBE-PRIVESC-014 | HIGH | Service account token creation | `create` on `serviceaccounts/token` | Limit to trusted control-plane components |
| KUBE-RBAC-OVERBROAD-001 | CRITICAL | Non-system subject bound to cluster-admin | Direct binding of human/SA to the `cluster-admin` ClusterRole | Replace with a least-privilege custom role |

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
| KUBE-PODSEC-APE-001 | HIGH | Privilege escalation allowed in container | `allowPrivilegeEscalation` missing or `true` | Set `allowPrivilegeEscalation: false` |
| KUBE-PODSEC-ROOT-001 | MEDIUM | Container runs as root | UID 0 or `runAsNonRoot: false` | Set a non-zero UID and `runAsNonRoot: true` |
| KUBE-SA-DEFAULT-001 | MEDIUM | Default service account in use | Workload mounts the namespace `default` SA | Bind a dedicated least-privilege SA |
| KUBE-IMAGE-LATEST-001 | LOW | Mutable image tag used | `:latest` or no tag | Pin to an immutable tag or digest |

### Network Policy ([internal/analyzer/network/analyzer.go](../internal/analyzer/network/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-NETPOL-COVERAGE-001 | HIGH | Namespace has no NetworkPolicies | Non-system namespace with zero policies | Add a default-deny, then allow explicitly |
| KUBE-NETPOL-WEAKNESS-002 | HIGH | NetworkPolicy permits internet egress | Egress rule targets `0.0.0.0/0` or `::/0` | Restrict to required CIDRs or services |
| KUBE-NETPOL-COVERAGE-002 | MEDIUM | Workload is not selected by any NetworkPolicy | Pod in a policy-bearing namespace but no policy matches it | Add a selector or apply a baseline policy |
| KUBE-NETPOL-COVERAGE-003 | MEDIUM | Ingress policies present but egress remains open | Namespace has ingress rules but no egress | Add explicit egress rules or a default-deny egress |
| KUBE-NETPOL-WEAKNESS-001 | MEDIUM | NetworkPolicy allows ingress from all namespaces | Empty namespace selector in ingress | Use explicit namespace labels |

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
| KUBE-SECRETS-002 | MEDIUM | Opaque secret stored in kube-system | User `Opaque` secret in `kube-system` | Move to an app namespace and restrict readers |
| KUBE-CONFIGMAP-001 | MEDIUM | ConfigMap contains credential-like keys | Key name matches `password`/`token`/`key`/`api_key`/… | Move to a Secret or external secret manager |

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

Edge techniques that can appear in a hop chain: `KUBE-PRIVESC-001` (pod create), `-005` (secrets read), `-008` (impersonate), `-009` (bind/escalate), `-010` (rolebinding modify), `-012` (nodes/proxy), `-014` (serviceaccounts/token), `-017` (wildcard), plus `KUBE-ESCAPE-00{1,2,3,4,5,6,8}` / `KUBE-HOSTPATH-001` for the pod-escape terminal edge. `system:*` subjects are skipped as traversable intermediates so paths do not launder through the control plane.

Each path finding ships with an `escalation_path` array: one `EscalationHop` per step, with `from_subject`, `to_subject`, `action`, `permission`, and a human-readable `gains` line.

## Findings Library — Planned

The following rules are on the roadmap but not yet implemented. See [PLAN.md](../PLAN.md) for status and priority.

**RBAC** — KUBE-PRIVESC-002 (pod create + PSA bypass), -004 (pods/exec), -006 (secrets get), -007 (secret creation token theft), -011 (CSR), -013 (ephemeral containers), -015 (portforward), -016 (node drain); stale/dangling bindings.

**Pod Security** — `readOnlyRootFilesystem`, `seccompProfile`, `procMount`, exhaustive dangerous-capability list (SYS_PTRACE, DAC_OVERRIDE, SYS_MODULE, SYS_RAWIO, MKNOD, AUDIT_WRITE, …); PersistentVolume hostPath bypass (KUBE-ESCAPE-011); PSA namespace label checks; legacy PSP permissiveness.

**Network** — cross-namespace communication map; egress to cloud metadata endpoint `169.254.169.254`.

**Secrets** — stale/unreferenced secrets; cross-namespace secret references; TLS secret expiry; `aws-auth` ConfigMap analysis; EncryptionConfiguration audit.

**Service Account** — cross-module risk correlation; DaemonSet blast-radius flag.

**Admission** — "no mutating webhook present" / "no policy engine detected" posture findings; ValidatingAdmissionPolicy (v1 CEL) collection + cel-go evaluation; operator-attestation flow for Kyverno / Gatekeeper effect that cannot be reproduced offline (see Phase 4 of the admission-aware design).

**Container Security** — missing resource limits/requests (DoS), missing probes, lifecycle exec commands, image registry allowlist / digest pinning.

**Node** — kubelet version CVE hints, control-plane taints, workloads on control-plane nodes.

**etcd & Control Plane** — API server LB/NodePort exposure, `/var/lib/etcd` hostPath, kubelet anonymous auth / read-only port.

**Namespace Isolation** — per-namespace security score, cross-namespace risk matrix.

**Cloud Provider** — EKS aws-auth + IRSA trust-policy cross-check; GKE Workload Identity; AKS managed identities; IMDS exposure edges in the escalation graph.
