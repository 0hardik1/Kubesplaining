# Kubesplaining

Kubesplaining is a Kubernetes security assessment CLI inspired by Salesforce's [Cloudsplaining](https://github.com/salesforce/cloudsplaining) (which does the same job for AWS IAM). It reads a live cluster or a previously captured snapshot, analyzes it against a library of techniques, and produces a prioritized list of findings as HTML, JSON, CSV, or SARIF.

It focuses on the things that matter most for *offensive-realistic* Kubernetes hardening:

- **Overly permissive RBAC** — wildcards, impersonation, bind/escalate, secret reads, pod creation.
- **Pod-escape surface area** — privileged containers, host namespaces, sensitive hostPath mounts, container socket mounts.
- **Privilege escalation paths** — graph-based chains of "subject A can become subject B can reach sink X."
- **Network isolation gaps** — namespaces with no NetworkPolicy, policies that allow broad internet egress.
- **Admission-control bypass risks** — webhooks that fail open, objectSelector bypasses, exempt sensitive namespaces.
- **Secrets and service-account hygiene** — legacy token secrets, credentials in ConfigMaps, default-SA mounting.

Every finding names the technique, shows the evidence, and includes remediation — explanation, not just detection.

**See an example report:** the e2e suite scans a deliberately misconfigured cluster and publishes the result at <https://0hardik1.github.io/Kubesplaining/> — open it to see how findings, the attack graph, and remediation copy actually render before installing anything.

## Quickstart

The repo pins its developer tools (Go, kubectl, kind, ripgrep) with [Hermit](https://cashapp.github.io/hermit/), so you do **not** need a system Go install. The `./bin/` directory ships shim symlinks; the first invocation of any of them auto-downloads the pinned version into `~/Library/Caches/hermit` (macOS) or `~/.cache/hermit` (Linux). No global install required, no `sudo`.

Activate the environment once per shell so plain `go`, `kubectl`, etc. resolve to the pinned versions:

```bash
. ./bin/activate-hermit          # adds ./bin to PATH for this shell
```

> Don't want to activate? Skip the line above and call shims directly: `./bin/go ...`, `./bin/kubectl ...`. Either path works; everything below assumes you've activated.

Build the CLI and scan your current `kubectl` context — one command:

```bash
make scan                                   # builds if needed, then scans the current context
open kubesplaining-report/report.html       # macOS; xdg-open on Linux
```

`make scan` builds the binary on first run (Hermit auto-fetches Go) and then re-runs incrementally. Pass extra CLI flags via `ARGS`, e.g. `make scan ARGS="--threshold high --only-modules privesc"`. To run the binary directly instead:

```bash
make build
./bin/kubesplaining scan
```

Or capture a snapshot first and analyze it offline (good for jumphosts, audits, diffs):

```bash
./bin/kubesplaining download --output-file snapshot.json
./bin/kubesplaining scan --input-file snapshot.json
```

Useful flags:

- `--threshold high` — hide everything below HIGH.
- `--only-modules privesc` / `--skip-modules network` — scope to specific analyzers.
- `--output-format html,json,csv,sarif` — pick output formats (default: `html,json`).
- `--ci-mode --ci-max-critical 0 --ci-max-high 0` — non-zero exit when over budget, for CI.
- `--max-privesc-depth 7` — deeper BFS on the escalation graph (default 5).

For one-off manifest checks without cluster access:

```bash
./bin/kubesplaining scan-resource --input-file deployment.yaml
```

### Developer setup

With Hermit activated (see Quickstart), the standard loop is:

```bash
make setup                        # download Go module deps into ./.tmp
make test                         # go test ./...
make lint                         # gofmt -l + go vet
make e2e                          # spin up kind, apply risky manifests, assert findings (needs Docker)
```

Docker is intentionally not Hermit-managed — install the Docker daemon on the host. To add or change a pinned tool, run `./bin/hermit install <pkg>` and commit the resulting symlinks under `bin/`.

## Status

Initial implementation, not the full specification yet — see [PLAN.md](PLAN.md) for the roadmap and what is/isn't done. The current focus is RBAC dangerous-permission detection and pod-security misconfiguration, plus the privilege-escalation graph that ties them together.

## Why It Is Useful

Kubesplaining does **cluster-wide attacker-path analysis against collected state**. It takes the cluster as-is — no admission policies required, no workload access required beyond listing — and answers:

> *Given this RBAC and these pods, how would an attacker reach cluster-admin / node root / kube-system secrets? Which subjects are the blast-radius amplifiers?*

This is the same question Cloudsplaining answers for AWS IAM.

Concretely it is useful for:

- **Pentest / red-team engagements** — the escalation paths output is the attack plan.
- **Security reviews before giving a workload broader access** — see if the new binding closes the graph from someone untrusted to a sink.
- **Continuous assurance in CI** — `--ci-mode` with `--ci-max-critical` / `--ci-max-high` fails the pipeline when high-severity findings cross a budget.
- **Post-incident rationalization** — replay a captured snapshot to explain how an actor could have moved.

## What It Detects

41 rules across 7 modules today, plus the privilege-escalation graph that chains them.

| Module | Rules | Focus |
| --- | --- | --- |
| rbac | 10 | wildcard / impersonate / bind-escalate / secret-read / pod-create / nodes-proxy / token-create |
| podsec | 13 | privileged, host namespaces, hostPath, container sockets, runAsRoot, mutable tags |
| network | 5 | namespaces missing NetworkPolicy, broad-internet egress, unselected workloads |
| admission | 3 | failurePolicy: Ignore, objectSelector bypass, sensitive-namespace exemptions |
| secrets | 4 | legacy SA token secrets, credential-like ConfigMap keys, CoreDNS tampering |
| serviceaccount | 4 | privileged SAs, default-SA RBAC, DaemonSet token blast-radius |
| privesc | 4 sinks | graph chains to cluster-admin / system:masters / node-escape / kube-system-secrets |

Full per-rule severity, detection, remediation, and the roadmap of planned rules: [docs/findings.md](docs/findings.md).

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

`scan`, `scan-resource`, and `report` **auto-apply the `standard` exclusions preset by default**, so findings about built-in Kubernetes plumbing — kube-system / kube-public / kube-node-lease namespaces, kube-controller-manager service accounts (`clusterrole-aggregation-controller`, `generic-garbage-collector`, …), `system:*` users/groups/roles, `kubeadm:*` groups and bootstrap roles — are suppressed up front. None of that is something an operator can change without breaking their cluster, so showing it as risk just buries the things that are actionable.

Pick a different baseline with `--exclusions-preset`:

| Preset | Behavior |
| --- | --- |
| `standard` (default) | Auto-applied. Filters kube-system / system:* / kubeadm:* noise. |
| `minimal` | Filters only `kube-public`, `kube-node-lease`, and `system:*`. |
| `none` (alias `strict`) | No built-in filtering — every finding surfaces, including control-plane noise. |

Layer custom rules on top with `--exclusions-file path.yml`. The user file is **merged** with the preset, so you keep the defaults and add your own suppressions (specific service accounts, expected workloads, custom rule-ID patterns). Generate a starter file with `kubesplaining create-exclusions-file --preset standard --output-file exclusions.yml`. See [internal/exclusions/](internal/exclusions/) for the YAML schema (Global / RBAC / PodSecurity / NetworkPolicy sections, all matchers support shell-style globs).

Excluded findings are dropped from the report entirely — totals reflect actionable findings only. To audit what the defaults are hiding, re-run with `--exclusions-preset=none` and diff.

## Access Requirements

Kubesplaining needs **cluster-wide read** on the resource kinds listed under Stage 2 above. A suitable ClusterRole is a subset of the built-in `view` role plus `get`/`list` on RBAC objects and webhook configurations. Forbidden listings are recorded as `missing_permissions` warnings in the snapshot and do not abort the run; the affected modules just operate on a partial view.

No admission webhooks, CRDs, or agent pods are installed. The tool is safe to point at production.

## Where To Go Next

- Full rule catalog (implemented + planned): [docs/findings.md](docs/findings.md).
- Status of each module / roadmap item: [PLAN.md](PLAN.md).
- End-to-end verification: `make e2e` — provisions a local `kind` cluster with intentionally risky manifests in [testdata/](testdata/) and asserts expected findings.
