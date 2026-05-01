# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Kubesplaining is a Go CLI for Kubernetes security assessment, modeled on Salesforce's Cloudsplaining. It reads cluster state (live or from a snapshot file) and emits scored findings as HTML, JSON, CSV, or SARIF.

`README.md` is the operator-facing overview. The comprehensive per-rule catalog (rule IDs, severity, detection logic, remediation, owning analyzer file) lives in [`docs/findings.md`](docs/findings.md) — read that first when adding or renaming a rule. The architectural deep-dive is in [`docs/architecture.md`](docs/architecture.md), the exclusions YAML schema in [`docs/exclusions.md`](docs/exclusions.md). The implementation roadmap and current status of every spec item is in `PLAN.md`. The full functional spec is `KUBESPLAINING_SPEC.md`.

## Common commands

Developer tooling (Go, kubectl, kind, ripgrep) is pinned via [Hermit](https://cashapp.github.io/hermit/) under `bin/`. Either activate the environment once per shell with `. ./bin/activate-hermit`, or invoke binaries directly as `./bin/go ...`, `./bin/rg ...`, etc. The Hermit shims auto-download the pinned versions on first use into `~/Library/Caches/hermit`. Docker is not Hermit-managed.

All build/test commands route through the `Makefile`, which pins `GOCACHE` / `GOMODCACHE` under `.tmp/` so module downloads stay inside the repo.

```bash
make setup           # go mod download + create bin/ and .tmp/
make build           # builds ./bin/kubesplaining from ./cmd/kubesplaining
make test            # go test ./...
make lint            # gofmt -l check + go vet ./...
make e2e             # boots a kind cluster, applies testdata/e2e/vulnerable.yaml, runs the CLI, asserts expected rule IDs
make clean           # removes ./bin, ./kubesplaining-report, ./.tmp
make install-hooks   # activate .githooks/ pre-commit + commit-msg hooks (one-time per clone)
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) — the `commit-msg` hook enforces it once `make install-hooks` has run. The `pre-commit` hook runs `gofmt -l` and `golangci-lint` over the packages of staged `.go` files; install the linter once with `./bin/hermit install golangci-lint`. See `.githooks/README.md` for details and bypass.

Single-package or single-test runs (use the same `GOCACHE` / `GOMODCACHE` env so you do not redownload modules):

```bash
GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/rbac/...

GOCACHE=$(pwd)/.tmp/go-build-cache GOMODCACHE=$(pwd)/.tmp/go-mod-cache \
  go test ./internal/analyzer/privesc -run TestFindPaths -v
```

`make e2e` requires a reachable Docker daemon (see `scripts/kind-e2e.sh`); `kind`, `kubectl`, and `rg` come from Hermit once the environment is activated. The script greps `findings.json` for specific rule IDs — when you add or rename a rule that the e2e fixture should produce, update the `rg -q "KUBE-..."` assertions and/or `testdata/e2e/vulnerable.yaml` together.

`gofmt -l` is the lint gate; the Makefile lists Go files via `rg --files -g '*.go'` (Hermit-managed).

## Architecture

Four-stage pipeline: **connection → collection → analysis → report**. The boundary that matters most: the **collector is the only thing that talks to the Kubernetes API**; analyzers consume `models.Snapshot` and never make network calls. This is what enables `download` → `scan --input-file` for offline analysis.

```
cmd/kubesplaining/main.go            # entrypoint, ldflags-injected version
└── internal/cli/                     # cobra commands: download, scan, scan-resource, report, create-exclusions-file, version
    └── internal/connection/          # client-go credentials resolution
    └── internal/collector/           # parallel API listing → models.Snapshot (single ~657-line collector.go)
    └── internal/manifest/            # offline alternative to collector: reads a YAML/JSON manifest into a Snapshot for `scan-resource`
    └── internal/analyzer/            # the engine + 7 modules; see below
    └── internal/exclusions/          # YAML-driven post-analysis muting; matched findings are dropped from output (see docs/exclusions.md for schema)
    └── internal/report/              # html/json/csv/sarif writers; HTML rendering is split across summary.go, evidence_render.go, attack_graph.go, glossary.go (each 400-850 lines because all CSS/JS is embedded)
    └── internal/scoring/             # composite formula + clamp + threshold helper, shared by analyzers and engine
    └── internal/permissions/         # aggregate.go: collapses (Cluster)RoleBindings × (Cluster)Roles into per-subject EffectiveRules
    └── internal/models/              # Snapshot, Finding, Severity, EscalationGraph/Path/Hop — the cross-package vocabulary
```

### The analyzer engine (`internal/analyzer/engine.go`)

Every analyzer module implements:

```go
type Module interface {
    Name() string
    Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}
```

`Engine.Analyze` runs all selected modules **in parallel goroutines**, then post-processes:

1. `correlate` — bumps the score of any non-privesc finding whose `Subject` appears as the source of a privesc path, tagging it `chain:amplified` (see `analyzer/correlate.go` and `scoring.ChainModifier`).
2. `dedupe` — collapses cross-module duplicates keyed by `(RuleID, SubjectKey, ResourceKey)`, keeping the highest score and merging `Tags`.
3. Threshold filter via `scoring.AboveThreshold`.
4. Stable sort by severity rank → score → rule ID → title.

The seven modules live under `internal/analyzer/{rbac,podsec,network,admission,secrets,serviceaccount,privesc}`. The list is hard-coded in `NewWithConfig`. The `--only-modules` / `--skip-modules` flags select against `Module.Name()`.

### `privesc` is the differentiator

`internal/analyzer/privesc/` builds a directed graph (`graph.go`) where nodes are RBAC subjects plus five synthetic sinks (`cluster_admin`, `kube_system_secrets`, `node_escape`, `system_masters`, `token_mint`). Edges are RBAC techniques (impersonate, bind/escalate, pod-create-then-token-theft, token mint, etc.). `pathfinder.go` BFS's from every non-`system:*` subject up to `MaxDepth` (default 5, flag: `--max-privesc-depth`), and `analyzer.go` emits one finding per `(source, sink)` pair with the full hop chain as `EscalationPath`. Severity is attenuated by chain length: `score = base − 0.5 × (hops − 1)` (then clamped to `[1, 10]`), and hops ≥ 3 drop one severity bucket. Subjects flagged `IsSystem` (built-in `system:*`) are skipped as intermediate hops — they're only valid as terminal sinks via explicit edges — so paths can't launder through the control plane.

### Data flow contract

- `models.Snapshot` is plain JSON-serializable. `collector.WriteSnapshot` / `collector.ReadSnapshot` round-trip it. The `download` command writes one; `scan --input-file` and the e2e script consume one.
- Secrets are collected as `SecretMetadata` only — **raw secret values are never read**. ConfigMaps go through `redactConfigMapValues` in the collector: **keys are preserved, values are blanked to empty strings** so analyzers can pattern-match credential-like key names without ever storing the payloads. Do not change this without re-reading the privacy notes in `README.md`.
- Forbidden/Unauthorized list errors in the collector are **downgraded to warnings** and recorded in `Snapshot.Metadata.CollectionWarnings` / `PermissionsMissing`. Don't promote these to fatal — locked-down clusters depend on partial-snapshot behavior.
- `permissions.Aggregate(snapshot)` is the canonical way to get effective RBAC per subject; the `rbac` and `serviceaccount` analyzers both use it. Don't re-traverse bindings/roles ad hoc.

### Scoring

`internal/scoring/scorer.go` defines the composite formula:

```
score = base × exploitability × blast_radius + chain_modifier
```

`Compose(Factors{...})` clamps to `[0, 10]`. Most analyzers currently emit a hand-picked `Score` directly; the engine's correlation pass adds `ChainModifier` post-hoc. When adding a new rule, prefer populating the factor inputs over a fixed score so cross-module ordering stays meaningful.

### Findings

Every analyzer emits `models.Finding` with a stable `RuleID`. Rule IDs are referenced from [`docs/findings.md`](docs/findings.md), the e2e assertions in `scripts/kind-e2e.sh`, and likely downstream consumers — treat them as a public surface. The naming convention is `KUBE-<AREA>-<SUFFIX>`, where the suffix is either a zero-padded number (`KUBE-ESCAPE-001`) or, for privesc graph paths, a descriptive sink name (`KUBE-PRIVESC-PATH-CLUSTER-ADMIN`). Multi-segment areas are common when a module covers several axes — e.g. `KUBE-PODSEC-APE-001`, `KUBE-PODSEC-ROOT-001`, `KUBE-NETPOL-COVERAGE-001`, `KUBE-NETPOL-WEAKNESS-001`, `KUBE-SA-DEFAULT-001`, `KUBE-SA-PRIVILEGED-001`. Other prefixes in use today: `KUBE-PRIVESC-`, `KUBE-ESCAPE-`, `KUBE-CONTAINERD-SOCKET-`, `KUBE-HOSTPATH-`, `KUBE-IMAGE-LATEST-`, `KUBE-ADMISSION-`, `KUBE-SECRETS-`, `KUBE-CONFIGMAP-`, `KUBE-RBAC-OVERBROAD-`. See [`docs/findings.md`](docs/findings.md) for the authoritative list.

`Finding.ID` is the deterministic per-instance key (`RULE:ns:name`); `RuleID` is shared across instances of the same rule. Exclusions are evaluated *after* analysis: `exclusions.Apply` drops matched findings from the output slice (the matcher sets `Excluded=true` + `ExclusionReason` on the in-memory copy first, but the field isn't surfaced to the report writer because the finding is gone). The `standard` preset is auto-applied; pass `--exclusions-preset=none` to opt out. See [`docs/exclusions.md`](docs/exclusions.md) for the YAML schema.

### Report-layer educational content (`internal/report/glossary.go`)

Three maps carry presentation-only copy that deliberately does **not** live on `models.Finding`, so JSON/CSV/SARIF outputs stay clean and copy can iterate without re-running scans:

- `Glossary[Kind]` — definitions of subject/resource Kinds (`ServiceAccount`, `Pod`, `Secret`, `Deployment`, ...) with `Title` / `Short` / `Long` / `DocURL`.
- `Techniques[ActionSlug]` — attacker-technique explainers keyed by chain-hop `Action` (`impersonate`, `read_secrets`, `pod_host_escape`, ...) with `Title` / `Plain` / `Mitre` / `AttackerSteps`.
- `Categories[CategoryName]` — impact-lane copy for the Attack Graph (`privilege_escalation`, `lateral_movement`, ...).

`GlossaryKeyForSubject` / `GlossaryKeyForResource` / `TechniqueKeyForFinding` (all in `glossary.go`) resolve a `Finding` to keys. Both the interactive Attack Graph (`attack_graph.go` → `GraphPayload`) and the static Findings tab (`education_render.go` → `findingEducationHTML`) consume them.

The static **"How an attacker abuses this"** section is one combined `.scenario` wrapper that holds, in order: a `Background` block of glossary cards (Subject / Resource / Technique definitions), the `AttackScenario` narrative (`<ol class="attack-narrative">`), and the `EscalationPath` chain cards (`<ol class="attack-chain">`). The Background block suppresses its Technique entry when the chain renders technique copy per-hop, to avoid duplication. There is no separate "Observed attack chain" section anymore.

When you add a rule that targets a new resource/subject Kind, or a new privesc Action slug, also add the corresponding `Glossary` / `Techniques` entry — otherwise the Background block silently drops that aspect.

## Conventions worth preserving

- Package doc comments at the top of each `package foo` file describe the package's role; new files should follow the same pattern.
- Cobra subcommands live one-per-file in `internal/cli/` and are wired from `root.go`.
- Test files sit alongside the code (`foo.go` ↔ `foo_test.go`); table-driven tests are the norm.
- `testdata/snapshots/minimal-risky.json` and `testdata/manifests/risky-resource.yaml` are reusable fixtures; reach for them before fabricating new ones.

## Module/dependency notes

Module path is `github.com/0hardik1/kubesplaining` and `go.mod` requires Go 1.26. Core deps: `spf13/cobra` for the CLI, `k8s.io/{api,apimachinery,client-go}` v0.36.x for cluster types and access. There is no separate `go-yaml` direct dep — `gopkg.in/yaml.v3` is used for the exclusions file loader.
