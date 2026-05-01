# Architecture

How Kubesplaining is wired internally. For *what* it does (rule library, install, usage), see the [README](../README.md). For the implementation roadmap, see [PLAN.md](../PLAN.md).

## The four-stage pipeline

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Connection   │ →  │  Collection   │ →  │   Analysis    │ →  │    Report     │
│  kubeconfig   │    │ snapshot.json │    │  7 modules ∥  │    │  html/json/   │
│ / in-cluster  │    │ RBAC+workload │    │  findings[]   │    │   csv/sarif   │
└───────────────┘    └───────────────┘    └───────────────┘    └───────────────┘
```

The boundary that matters most: the **collector is the only thing that talks to the Kubernetes API**; analyzers consume `models.Snapshot` and never make network calls. That separation is what makes `download` → `scan --input-file` work for offline analysis.

## Stage 1 — Connection ([internal/connection/](../internal/connection/))

Resolves credentials in the standard client-go order: `--kubeconfig` flag → `KUBECONFIG` env → `~/.kube/config` → in-cluster service account. Also accepts direct `--api-server` + `--token` for audit scenarios. **Read-only access is sufficient** for the full analysis; no admission webhook registration, no CRD install, no pod creation.

## Stage 2 — Collection ([internal/collector/collector.go](../internal/collector/collector.go))

In parallel (capped by `--parallelism`), lists every supported resource kind and dumps them into a `models.Snapshot`:

- **RBAC** — Roles, ClusterRoles, RoleBindings, ClusterRoleBindings.
- **Workloads** — Pods, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs.
- **Networking** — NetworkPolicies, Services, Ingresses.
- **Admission** — ValidatingWebhookConfigurations, MutatingWebhookConfigurations.
- **Identity** — ServiceAccounts, Secrets (metadata only — raw values are never read), ConfigMaps.
- **Platform** — Nodes, Namespaces.

Forbidden / Unauthorized errors are **downgraded to warnings**, not fatal — a partial snapshot still produces useful output. This matters in locked-down clusters where the scanning credential cannot list everything.

The snapshot is a plain JSON file. `kubesplaining download` writes it; `kubesplaining scan --input-file` consumes it. This separation means you can capture a snapshot on a jumphost and analyze it offline, or diff snapshots over time.

## Stage 3 — Analysis ([internal/analyzer/engine.go](../internal/analyzer/engine.go))

The engine runs seven modules **in parallel** against the snapshot. Each module implements the same interface:

```go
type Module interface {
    Name() string
    Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}
```

The modules:

1. **rbac** — effective-permission aggregation via [`internal/permissions/`](../internal/permissions/), then pattern-matches against the technique database.
2. **podsec** — per-container / per-pod-template security context inspection.
3. **network** — NetworkPolicy coverage and weakness detection.
4. **admission** — webhook inventory, failurePolicy, bypass surface.
5. **secrets** — long-lived SA tokens, credential-like ConfigMap keys, CoreDNS tampering.
6. **serviceaccount** — default-SA risk, workload-mounted SA blast radius, DaemonSet amplification.
7. **privesc** — **the differentiator.** Builds a directed graph where nodes are RBAC subjects and sinks like `cluster-admin`, `node-escape`, `kube-system-secrets`, `system:masters`. Edges are labeled with the technique that enables the hop. Runs BFS from every non-system subject (capped at `--max-privesc-depth`, default 5) and emits one finding per `(source, sink)` pair with the full hop-by-hop chain attached.

After modules return, the engine post-processes the combined findings list:

1. **Admission-aware reweight** — for every pod-security finding, looks up the namespace's `pod-security.kubernetes.io/{enforce,audit,warn}` label in the snapshot via [`analyzer/admission/mitigation/`](../internal/analyzer/admission/mitigation/psa.go). When `enforce` would block the spec (e.g. `restricted` rejects `privileged: true`, `hostPath`, host namespaces; `baseline` rejects host namespaces and privileged containers), the stage either drops the finding (`--admission-mode=suppress`, default) or drops its severity by exactly one bucket via `models.Severity.Down()`, snaps the score to the new bucket's floor via `scoring.MinScoreForSeverity`, and tags it `admission:mitigated-psa-<level>` (`--admission-mode=attenuate`). Audit/warn-mode labels never suppress or attenuate — they tag findings as `admission:audit-psa-<level>` / `admission:warn-psa-<level>` so the report can flag "logged but not blocked." Counts surface on `models.AdmissionSummary` and are written to `admission-summary.json` alongside the findings file.
2. **Correlate** — bumps the score of any non-privesc finding whose `Subject` appears as the source of a privesc path, tagging it `chain:amplified` (see [`analyzer/correlate.go`](../internal/analyzer/correlate.go) and `scoring.ChainModifier`). Runs after admission so chain amplification builds on already-attenuated scores.
3. **Dedupe** — collapses cross-module duplicates keyed by `(RuleID, SubjectKey, ResourceKey)`, keeping the highest score and merging tags.
4. **Threshold filter** via `scoring.AboveThreshold` (`--severity-threshold`).
5. **Stable sort** by severity rank → score → rule ID → title.

## Stage 4 — Report ([internal/report/](../internal/report/))

The same finding list is serialized into:

- **HTML** — self-contained (CSS/JS inlined via Go's `embed`), executive summary, per-module sections, severity counts, category breakdown, per-finding educational copy.
- **JSON** — the raw `[]Finding` for programmatic consumption.
- **CSV** — triage-friendly, one row per finding.
- **SARIF** — for GitHub code scanning / IDE integration.

Educational copy in the HTML report (Glossary entries, Technique explainers, Category copy) is presentation-only and lives in [`internal/report/glossary.go`](../internal/report/glossary.go) — it is deliberately not on `models.Finding`, so JSON / CSV / SARIF stay clean and copy can iterate without re-running scans.

## Data Model ([internal/models/](../internal/models/))

- **`Snapshot`** — the cluster dump.
- **`Finding`** — the unit every analyzer emits. Carries `ID`, `RuleID`, Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), Score (0–10), Category, Subject/Resource references, Evidence (JSON blob), Remediation, References, Tags, and optionally an `EscalationPath`.
- **`SubjectRef`** / **`ResourceRef`** — canonical `Kind/[Namespace/]Name` identifiers.
- **`EscalationGraph`** / **`EscalationNode`** / **`EscalationEdge`** / **`EscalationPath`** / **`EscalationHop`** — the graph types consumed by the privesc module.

`Finding.ID` is a deterministic per-instance key (`RULE:ns:name`); `RuleID` is shared across instances of the same rule and is treated as a public surface — stable across releases, referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.

## Scoring ([internal/scoring/scorer.go](../internal/scoring/scorer.go))

The composite formula is:

```
score = base × exploitability × blast_radius + chain_modifier
```

`Compose(Factors{...})` clamps to `[0, 10]`. Where:

- `exploitability` is higher when the subject is a ServiceAccount *actually mounted by a pod* (the SA's credential is sitting on disk somewhere the attacker can already reach).
- `blast_radius` is higher for cluster-scoped rules and for subjects in `kube-system` or on a DaemonSet (token replicated to every node).
- `chain_modifier` comes from the privesc module's hop count — longer chains reduce severity (`base − 0.5 × (hops − 1)`, hops ≥ 3 drop one severity bucket).

Most analyzers currently emit a hand-picked `Score` directly; the engine's correlation pass adds `ChainModifier` post-hoc. New rules should prefer populating the factor inputs over a fixed score so cross-module ordering stays meaningful.

## Access requirements

Kubesplaining needs **cluster-wide read** on the resource kinds listed under Stage 2. A suitable ClusterRole is a subset of the built-in `view` role plus `get`/`list` on RBAC objects and webhook configurations. Forbidden listings are recorded as `missing_permissions` warnings in the snapshot and do not abort the run; the affected modules just operate on a partial view.

No admission webhooks, CRDs, or agent pods are installed. The tool is safe to point at production.

## Exclusions ([internal/exclusions/](../internal/exclusions/))

Exclusions are applied **after** analysis. `exclusions.Apply` walks each finding through the matcher; on a hit, the finding is dropped from the slice the report writer sees. The `standard` preset is auto-applied even without `--exclusions-file` so control-plane noise (kube-system, `system:*`, `kubeadm:*`) doesn't bury actionable findings; pass `--exclusions-preset=none` to opt out. User-supplied YAML loaded with `--exclusions-file` is merged on top of the preset rather than replacing it.

The full schema — `global` / `rbac` / `pod_security` / `network_policy` sections, glob semantics, evaluation order — is in [docs/exclusions.md](exclusions.md).
