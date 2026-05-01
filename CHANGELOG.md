# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). v1.0.x patch releases use auto-generated commit-grouped notes (driven by the [Conventional Commits](https://www.conventionalcommits.org/) prefix on each commit); only minor/major releases carry a hand-curated narrative section here.

## [Unreleased]

## [1.0.0] - 2026-04-30

First public release.

Kubesplaining is a Kubernetes security assessment CLI inspired by Salesforce's [Cloudsplaining](https://github.com/salesforce/cloudsplaining). It reads a live cluster (or a previously captured snapshot) and analyzes it against a library of techniques, emitting a prioritized list of findings as HTML, JSON, CSV, or SARIF.

The differentiator is **graph-based privilege-escalation path detection**: BFS from every non-system RBAC subject to five escalation sinks (cluster-admin, system:masters, node-escape, kube-system-secrets, token-mint), with the full hop chain attached to every finding. See the [hosted example report](https://0hardik1.github.io/kubesplaining/) for what the output actually looks like.

### Added

- **41 stable rule IDs across 7 analyzer modules.** Catalog with severity, detection logic, and remediation lives in [`docs/findings.md`](docs/findings.md). Rule IDs are a public surface — they are stable across releases and referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.
  - **rbac** (10) — wildcards, impersonate, bind/escalate, secret reads, pod create, nodes/proxy, token create, overbroad cluster-admin bindings.
  - **podsec** (13) — privileged containers, host namespaces (PID/network/IPC), hostPath mounts, container sockets, runAsRoot, mutable image tags, default-SA usage.
  - **network** (5) — namespaces missing NetworkPolicy, broad-internet egress, unselected workloads, unrestricted ingress.
  - **admission** (3) — webhooks with `failurePolicy: Ignore`, objectSelector bypass surface, sensitive-namespace exemptions.
  - **secrets** (4) — legacy SA token secrets, credential-like ConfigMap keys, CoreDNS tampering risk, kube-system Opaque secrets.
  - **serviceaccount** (4) — privileged SAs, default-SA RBAC, DaemonSet token blast-radius, workload-mounted SA risk correlation.
  - **privesc** (5 sinks) — multi-hop BFS to cluster-admin / system:masters / node-escape / kube-system-secrets / token-mint with chain-length severity attenuation.

- **Cluster-wide attack-path analysis.** `internal/analyzer/privesc/` builds a directed graph of RBAC subjects + sinks + pod-escape edges, BFS's from every non-`system:*` subject up to `--max-privesc-depth` (default 5), and emits one finding per (source, sink) pair with the full hop chain as `EscalationPath`.

- **Offline snapshot mode.** `kubesplaining download` captures a `snapshot.json` from a live cluster; `kubesplaining scan --input-file snapshot.json` analyzes it with no further cluster access. Useful for jumphost workflows, audits, and diffing cluster state over time.

- **`scan-resource` for ad-hoc manifest checks.** Run analyzers against a single YAML/JSON manifest without any cluster connection — handy for shift-left in `kubectl apply` review flows.

- **Four output formats.** HTML (self-contained, executive summary + per-module sections + attack graph + glossary), JSON (raw `[]Finding` for programmatic consumption), CSV (triage spreadsheets), SARIF (GitHub code scanning, IDE integration).

- **Composite scoring.** `score = base × exploitability × blast_radius + chain_modifier`, with the engine bumping non-privesc findings whose subject sits on a privesc chain. Cross-module dedupe on `(RuleID, Subject, Resource)` keeps the highest score and merges tags.

- **Exclusions presets.** `--exclusions-preset {standard|minimal|none}` filters built-in Kubernetes plumbing (kube-system / `system:*` / `kubeadm:*`) by default so actionable findings aren't buried under control-plane noise. Layer custom YAML rules with `--exclusions-file`.

- **CI mode.** `--ci-mode` with `--ci-max-critical` / `--ci-max-high` exits non-zero when the finding count exceeds the budget — pair with the SARIF output and `github/codeql-action/upload-sarif` to gate PRs.

- **Pre-built binaries and container image.** Linux/macOS amd64+arm64 and Windows amd64 archives on every release, plus a multi-arch image at `ghcr.io/0hardik1/kubesplaining:v1.0.0`.

### Documentation

- Comprehensive [README](README.md) with install paths, quickstart, comparison table vs. kube-bench / kubescape / KubiScan / rbac-tool.
- Full rule catalog and roadmap in [`docs/findings.md`](docs/findings.md) and [`PLAN.md`](PLAN.md).
- Live demo report at <https://0hardik1.github.io/kubesplaining/> regenerated on every push to `main`.

### Security

- Read-only access is sufficient for the full analysis. No admission webhook registration, no CRD install, no agent pods.
- Secrets are collected as `SecretMetadata` only — raw secret values are never read. ConfigMap data is redacted by the collector (keys preserved, values blanked) so analyzers can pattern-match credential-like key names without ever storing the payloads.
- Forbidden/Unauthorized list errors are downgraded to `CollectionWarnings` rather than aborting — locked-down clusters still produce a useful partial-snapshot report.
- Vulnerability disclosure: GitHub Private Vulnerability Reporting only. See [SECURITY.md](SECURITY.md).

[Unreleased]: https://github.com/0hardik1/kubesplaining/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/0hardik1/kubesplaining/releases/tag/v1.0.0
