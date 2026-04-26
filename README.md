# Kubesplaining

Kubesplaining is a Kubernetes security assessment CLI inspired by Salesforce's [Cloudsplaining](https://github.com/salesforce/cloudsplaining) (which does the same job for AWS IAM). It reads a live cluster or a previously captured snapshot, analyzes it against a library of techniques, and produces a prioritized list of findings as HTML, JSON, CSV, or SARIF.

It focuses on the things that matter most for *offensive-realistic* Kubernetes hardening:

- **Overly permissive RBAC** — wildcards, impersonation, bind/escalate, secret reads, pod creation.
- **Pod-escape surface area** — privileged containers, host namespaces, sensitive hostPath mounts, container socket mounts.
- **Privilege escalation paths** — graph-based chains of "subject A can become subject B can reach sink X."
- **Network isolation gaps** — namespaces with no NetworkPolicy, policies that allow broad internet egress.
- **Admission-control bypass risks** — webhooks that fail open, objectSelector bypasses, exempt sensitive namespaces.
- **Secrets and service-account hygiene** — legacy token secrets, credentials in ConfigMaps, default-SA mounting.

The guiding goal of the project is **explanation, not just detection**: every finding names the technique, shows the evidence, and includes remediation — hence "kube-splaining."

## Status

This is an initial implementation, not the full specification yet. The current analyzers focus on:

- RBAC dangerous permissions such as wildcard access, secrets access, pod/workload creation, impersonation, binding escalation, `nodes/proxy`, and service account token creation.
- Pod security issues such as privileged containers, host namespace sharing, dangerous `hostPath` usage, default service account usage, root execution, and mutable image tags.

See [PLAN.md](PLAN.md) for the full roadmap and what is/isn't done yet.

## Quick Start

```bash
make setup
make test
make lint
make build
make e2e
```

`make setup` downloads Go module dependencies. `make lint` runs `gofmt` checks and `go vet`. `make e2e` requires a reachable Docker daemon because `kind` depends on it.

## Why It Is Useful

Kubesplaining does **cluster-wide attacker-path analysis against collected state**. It takes the cluster as-is — no admission policies required, no workload access required beyond listing — and answers:

> *Given this RBAC and these pods, how would an attacker reach cluster-admin / node root / kube-system secrets? Which subjects are the blast-radius amplifiers?*

This is the same question Cloudsplaining answers for AWS IAM.

Concretely it is useful for:

- **Pentest / red-team engagements** — the escalation paths output is the attack plan.
- **Security reviews before giving a workload broader access** — see if the new binding closes the graph from someone untrusted to a sink.
- **Continuous assurance in CI** — `--ci-mode` with `--ci-max-critical` / `--ci-max-high` fails the pipeline when high-severity findings cross a budget.
- **Post-incident rationalization** — replay a captured snapshot to explain how an actor could have moved.

## How It Works

The tool is a four-stage pipeline:

```
┌────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│ Connection │ →  │  Collection  │ →  │   Analysis   │ →  │   Report    │
│ kubeconfig │    │ snapshot.json│    │ 7 modules ∥  │    │ html/json/  │
│ / in-cluster    │ RBAC+workload│    │ findings[]   │    │ csv/sarif   │
└────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
```

### Stage 1 — Connection ([internal/connection/](internal/connection/))

Resolves credentials in the standard client-go order: `--kubeconfig` flag → `KUBECONFIG` env → `~/.kube/config` → in-cluster service account. Also accepts direct `--api-server` + `--token` for audit scenarios. **Read-only access is sufficient** for the full analysis; no admission webhook registration, no CRD install, no pod creation.

### Stage 2 — Collection ([internal/collector/collector.go](internal/collector/collector.go))

In parallel (capped by `--parallelism`), lists every supported resource kind and dumps them into a `models.Snapshot`:

- RBAC: Roles, ClusterRoles, RoleBindings, ClusterRoleBindings
- Workloads: Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs
- Networking: NetworkPolicies, Services, Ingresses
- Admission: ValidatingWebhookConfigurations, MutatingWebhookConfigurations
- Identity: ServiceAccounts, Secrets (metadata only unless `--include-secret-values`), ConfigMaps
- Platform: Nodes, Namespaces

Forbidden/Unauthorized errors are **downgraded to warnings**, not fatal — a partial snapshot still produces useful output. This matters in locked-down clusters where the scanning credential cannot list everything.

The snapshot is a plain JSON file. `kubesplaining download` writes it; `kubesplaining scan --input-file` consumes it. This separation means you can capture a snapshot on a jumphost and analyze it offline, or diff snapshots over time.

### Stage 3 — Analysis ([internal/analyzer/engine.go](internal/analyzer/engine.go))

The engine runs seven modules **in parallel** against the snapshot. Each module implements the same interface:

```go
type Module interface {
    Name() string
    Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}
```

The modules are:

1. **rbac** — effective-permission aggregation, then pattern-matches against the Technique Database.
2. **podsec** — per-container / per-pod-template security context inspection.
3. **network** — NetworkPolicy coverage and weakness detection.
4. **admission** — webhook inventory, failurePolicy, bypass surface.
5. **secrets** — long-lived SA tokens, credential-like ConfigMap keys, CoreDNS tampering.
6. **serviceaccount** — default-SA risk, workload-mounted SA blast radius, DaemonSet amplification.
7. **privesc** — **the differentiator.** Builds a directed graph where nodes are RBAC subjects and sinks like `cluster-admin`, `node-escape`, `kube-system-secrets`, `system:masters`. Edges are labeled with the technique that enables the hop. Runs BFS from every non-system subject (capped at `--max-privesc-depth`, default 5) and emits one finding per `(source, sink)` pair with the full hop-by-hop chain attached.

Findings are filtered by `--threshold` and sorted by severity → score → rule ID → title.

### Stage 4 — Report ([internal/report/](internal/report/))

The same finding list is serialized into:

- **HTML** — self-contained (CSS/JS inlined via `embed`), executive summary, per-module sections, severity counts, category breakdown.
- **JSON** — the raw `[]Finding` for programmatic consumption.
- **CSV** — triage-friendly, one row per finding.
- **SARIF** — for GitHub code-scanning / IDE integration.

### Data Model ([internal/models/](internal/models/))

- `Snapshot` — the cluster dump.
- `Finding` — the unit every analyzer emits. Carries ID, RuleID, Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), Score (0–10), Category, Subject/Resource references, Evidence (JSON blob), Remediation, References, Tags, and optionally an `EscalationPath`.
- `SubjectRef` / `ResourceRef` — canonical `Kind/[Namespace/]Name` identifiers.
- `EscalationGraph` / `EscalationNode` / `EscalationEdge` / `EscalationPath` / `EscalationHop` — the graph types consumed by the privesc module.

## Risk Categories

Every finding is tagged with a `RiskCategory` for report grouping:

| Category | Meaning |
| --- | --- |
| `privilege_escalation` | Subject can gain additional privileges or identities. |
| `data_exfiltration` | Access to secrets, tokens, or credential-bearing data. |
| `lateral_movement` | Cross-namespace or cross-workload reach. |
| `infrastructure_modification` | Can alter control-plane behavior, admission, policy. |
| `defense_evasion` | Can bypass admission / logging / enforcement. |

## Findings Library — Implemented

The tool currently emits **41 distinct rule IDs across 7 modules**. Each rule produces zero or more findings against a given snapshot.

### RBAC ([internal/analyzer/rbac/analyzer.go](internal/analyzer/rbac/analyzer.go))

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

### Pod Security ([internal/analyzer/podsec/analyzer.go](internal/analyzer/podsec/analyzer.go))

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

### Network Policy ([internal/analyzer/network/analyzer.go](internal/analyzer/network/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-NETPOL-COVERAGE-001 | HIGH | Namespace has no NetworkPolicies | Non-system namespace with zero policies | Add a default-deny, then allow explicitly |
| KUBE-NETPOL-WEAKNESS-002 | HIGH | NetworkPolicy permits internet egress | Egress rule targets `0.0.0.0/0` or `::/0` | Restrict to required CIDRs or services |
| KUBE-NETPOL-COVERAGE-002 | MEDIUM | Workload is not selected by any NetworkPolicy | Pod in a policy-bearing namespace but no policy matches it | Add a selector or apply a baseline policy |
| KUBE-NETPOL-COVERAGE-003 | MEDIUM | Ingress policies present but egress remains open | Namespace has ingress rules but no egress | Add explicit egress rules or a default-deny egress |
| KUBE-NETPOL-WEAKNESS-001 | MEDIUM | NetworkPolicy allows ingress from all namespaces | Empty namespace selector in ingress | Use explicit namespace labels |

### Admission Webhooks ([internal/analyzer/admission/analyzer.go](internal/analyzer/admission/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-ADMISSION-001 | HIGH | Security-critical webhook uses `failurePolicy: Ignore` | Webhook targets pods/workloads but fails open | Use `failurePolicy: Fail` for security webhooks |
| KUBE-ADMISSION-002 | MEDIUM | Webhook can be bypassed via object labels | `objectSelector` keys on a workload-controlled label | Move rule to fields the workload cannot forge |
| KUBE-ADMISSION-003 | MEDIUM | Webhook excludes sensitive namespaces | `namespaceSelector` exempts `kube-system` / `*-system` | Confirm exemption is intentional, narrow if not |

### Secrets & ConfigMaps ([internal/analyzer/secrets/analyzer.go](internal/analyzer/secrets/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-SECRETS-001 | HIGH | Long-lived service account token secret | `type: kubernetes.io/service-account-token` | Prefer projected tokens; delete legacy secrets |
| KUBE-CONFIGMAP-002 | HIGH | CoreDNS configuration contains risky directives | `rewrite` / `forward` in Corefile | Review intent; restrict write access to coredns configmap |
| KUBE-SECRETS-002 | MEDIUM | Opaque secret stored in kube-system | User `Opaque` secret in `kube-system` | Move to an app namespace and restrict readers |
| KUBE-CONFIGMAP-001 | MEDIUM | ConfigMap contains credential-like keys | Key name matches `password`/`token`/`key`/`api_key`/… | Move to a Secret or external secret manager |

### Service Account ([internal/analyzer/serviceaccount/analyzer.go](internal/analyzer/serviceaccount/analyzer.go))

| Rule ID | Sev | Title | What it detects | Remediation |
| --- | --- | --- | --- | --- |
| KUBE-SA-PRIVILEGED-001 | CRITICAL | Service account has cluster-admin style permissions | SA with wildcard verbs on wildcard resources | Replace wildcards with tightly scoped roles |
| KUBE-SA-PRIVILEGED-002 | HIGH/CRITICAL | Workload-mounted SA has dangerous permissions | Mounted SA with secret reads / pod create / RBAC mutation / impersonate | Split by workload, drop the high-risk permissions |
| KUBE-SA-DEFAULT-002 | HIGH | Default service account has explicit RBAC permissions | Namespace `default` SA carries non-trivial bindings | Create dedicated SAs; keep `default` unprivileged |
| KUBE-SA-DAEMONSET-001 | MEDIUM/HIGH | Service account used by a DaemonSet | Token mounted on every node | Scope SA narrowly; treat as per-node credential |

### Privilege Escalation Paths ([internal/analyzer/privesc/analyzer.go](internal/analyzer/privesc/analyzer.go))

These findings are emitted **per `(source subject, sink)` pair** found by BFS on the escalation graph. Severity is attenuated by chain length: hops ≥ 3 drop one bucket, and score is `base − 0.5 × (hops − 1)`, clamped to `[1, 10]`.

| Rule ID | Base Sev | Title template | Sink reached |
| --- | --- | --- | --- |
| KUBE-PRIVESC-PATH-CLUSTER-ADMIN | CRITICAL (9.8) | `<subject>` can reach cluster-admin equivalent in N hop(s) | Wildcard `*/*/*` holder or cluster-admin-bound subject |
| KUBE-PRIVESC-PATH-SYSTEM-MASTERS | CRITICAL (9.6) | `<subject>` can reach system:masters in N hop(s) | Impersonation chain ending in the `system:masters` group |
| KUBE-PRIVESC-PATH-NODE-ESCAPE | CRITICAL (9.4) | `<subject>` can reach node escape in N hop(s) | Ability to create/exec a pod with privileged / hostPID / hostNetwork / hostIPC / sensitive hostPath |
| KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS | HIGH (8.6) | `<subject>` can reach kube-system secrets in N hop(s) | Cluster-wide or kube-system `get`/`list` on secrets |

Edge techniques that can appear in a hop chain: `KUBE-PRIVESC-001` (pod create), `-005` (secrets read), `-008` (impersonate), `-009` (bind/escalate), `-010` (rolebinding modify), `-012` (nodes/proxy), `-014` (serviceaccounts/token), `-017` (wildcard), plus `KUBE-ESCAPE-00{1,2,3,4,5,6,8}` / `KUBE-HOSTPATH-001` for the pod-escape terminal edge. `system:*` subjects are skipped as traversable intermediates so paths do not launder through the control plane.

Each path finding ships with an `escalation_path` array: one `EscalationHop` per step, with `from_subject`, `to_subject`, `action`, `permission`, and a human-readable `gains` line.

## Findings Library — Planned

The following rules are on the roadmap but not yet implemented. See [PLAN.md](PLAN.md) for status and priority.

**RBAC** — KUBE-PRIVESC-002 (pod create + PSA bypass), -004 (pods/exec), -006 (secrets get), -007 (secret creation token theft), -011 (CSR), -013 (ephemeral containers), -015 (portforward), -016 (node drain); stale/dangling bindings.

**Pod Security** — `readOnlyRootFilesystem`, `seccompProfile`, `procMount`, exhaustive dangerous-capability list (SYS_PTRACE, DAC_OVERRIDE, SYS_MODULE, SYS_RAWIO, MKNOD, AUDIT_WRITE, …); PersistentVolume hostPath bypass (KUBE-ESCAPE-011); PSA namespace label checks; legacy PSP permissiveness.

**Network** — cross-namespace communication map; egress to cloud metadata endpoint `169.254.169.254`.

**Secrets** — stale/unreferenced secrets; cross-namespace secret references; TLS secret expiry; `aws-auth` ConfigMap analysis; EncryptionConfiguration audit.

**Service Account** — cross-module risk correlation; DaemonSet blast-radius flag.

**Admission** — "no mutating webhook present" / "no policy engine detected" posture findings.

**Container Security** — missing resource limits/requests (DoS), missing probes, lifecycle exec commands, image registry allowlist / digest pinning.

**Node** — kubelet version CVE hints, control-plane taints, workloads on control-plane nodes.

**etcd & Control Plane** — API server LB/NodePort exposure, `/var/lib/etcd` hostPath, kubelet anonymous auth / read-only port.

**Namespace Isolation** — per-namespace security score, cross-namespace risk matrix.

**Cloud Provider** — EKS aws-auth + IRSA trust-policy cross-check; GKE Workload Identity; AKS managed identities; IMDS exposure edges in the escalation graph.

## Output Formats

| Format | Flag | Use case |
| --- | --- | --- |
| HTML | `--output-html` | Human review; self-contained, works offline |
| JSON | `--output-json` | Programmatic consumption, diffing between runs |
| CSV | `--output-csv` | Triage spreadsheets |
| SARIF | `--output-sarif` | GitHub code scanning, IDE integration |

## Commands

| Command | Purpose |
| --- | --- |
| `kubesplaining download` | Capture a `snapshot.json` from the live cluster. Read-only. |
| `kubesplaining scan` | Analyze (live or `--input-file`) and write reports. |
| `kubesplaining scan-resource` | Scan a single resource manifest for quick checks. |
| `kubesplaining report` | Re-render reports from an existing findings JSON. |
| `kubesplaining create-exclusions-file` | Emit a starter exclusions YAML. |
| `kubesplaining version` | Print build info. |

Key flags:

- `--threshold {info|low|medium|high|critical}` — severity floor.
- `--only <module>` / `--skip <module>` — scope to modules (`rbac`, `podsec`, `network`, `admission`, `secrets`, `serviceaccount`, `privesc`).
- `--max-privesc-depth N` — BFS depth cap for the privesc module (default 5).
- `--ci-mode` with `--ci-max-critical` / `--ci-max-high` — exit non-zero when over budget.

## Scoring

Today every rule carries a hand-picked base score clamped to `[0, 10]`. The privesc module already attenuates by chain length. The planned composite formula:

```
score = base × exploitability × blast_radius + chain_modifier
```

where:

- `exploitability` is higher when the subject is a ServiceAccount *actually mounted by a pod* (the SA's credential is sitting on disk somewhere),
- `blast_radius` is higher for cluster-scoped rules and for subjects in `kube-system` or on a DaemonSet (token on every node),
- `chain_modifier` comes from the privesc module's hop count.

Implementing this centrally is the **next goal** in [PLAN.md](PLAN.md).

## Exclusions

Findings can be suppressed via a YAML exclusions file. See [internal/exclusions/](internal/exclusions/) and `kubesplaining create-exclusions-file`. Preset profiles (`minimal` / `standard` / `strict`) and snapshot-driven pre-population are planned.

## Access Requirements

Kubesplaining needs **cluster-wide read** on the resource kinds listed under Stage 2 above. A suitable ClusterRole is a subset of the built-in `view` role plus `get`/`list` on RBAC objects and webhook configurations. Forbidden listings are recorded as `missing_permissions` warnings in the snapshot and do not abort the run; the affected modules just operate on a partial view.

No admission webhooks, CRDs, or agent pods are installed. The tool is safe to point at production.

## Where To Go Next

- Status of each module / roadmap item: [PLAN.md](PLAN.md).
- End-to-end verification: `make e2e` — provisions a local `kind` cluster with intentionally risky manifests in [testdata/](testdata/) and asserts expected findings.
