# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). v1.0.x patch releases use auto-generated commit-grouped notes (driven by the [Conventional Commits](https://www.conventionalcommits.org/) prefix on each commit); only minor/major releases carry a hand-curated narrative section here.

## [Unreleased]

### Added

- **Deep escalation chains.** The privesc graph now expresses multi-hop paths that were previously invisible. `namespace_admin` is no longer a dead-end sink: reaching it now continues into every ServiceAccount co-located in that namespace (`colocated_sa_token_theft`), which is what turns a namespace-bounded grant into a cluster-wide path when that namespace also hosts a privileged controller. Node escape continues into control-plane PKI theft (`control_plane_pki_theft` to `system:masters`, `static_pod_admission_bypass` to token mint), gated on the snapshot actually containing a control-plane node with no `NoSchedule` taint, so worker-only clusters are unaffected. Non-built-in ServiceAccounts in `kube-system` are now traversable as chain intermediates while still never being seeded as path-search sources.

- **`KUBE-CONFUSED-DEPUTY-001`.** Flags a subject that cannot escalate directly but can write a custom resource that a privileged operator then reconciles on its behalf. Catalog covers Flux, Argo CD, Argo Workflows, cert-manager, external-secrets, Velero, Tekton, and prometheus-operator `ServiceMonitor` (the `bearerTokenFile` token-exfiltration vector, GHSA-cxh2-4639-vmc5). Detection is RBAC-only and requires the operator's controller ServiceAccount to exist in the cluster, so a stray grant on an uninstalled CRD produces nothing.

### Changed

- **Escalation paths are now scored by their weakest hop rather than their length.** Each graph edge carries a difficulty rating, and a path's score is attenuated by the sum of its hops' difficulties instead of a flat penalty per hop. Severity now downgrades when a chain contains a genuinely hard step (one needing attacker-controlled infrastructure or a timing window), not merely because the chain is long. Previously a five-hop chain of trivial RBAC grants was ranked below a two-hop chain that required a race condition. `EscalationEdge` and `EscalationHop` gained a `difficulty` field, visible in JSON output.

## [1.2.0] - 2026-07-15

This release takes kubesplaining's privilege-escalation graph across the cloud boundary and sharpens the RBAC matching engine. The headline additions are a first-class EKS cloud-provider module (IRSA admin-role detection, aws-auth IAM-to-RBAC mapping, and IMDS pivot edges) so an escalation chain can now cross from a Kubernetes ServiceAccount into an AWS IAM role; completion of the 17-entry `KUBE-PRIVESC` technique taxonomy with a dedicated Escalation Paths report tab; structured remediation hints across all eight analyzer modules; and `(apiGroup, resource, verb)`-aware RBAC matching that honors `resourceNames` to cut false positives across the rbac, secrets, serviceaccount, and privesc modules.

### Added

- **EKS cloud-provider module (`internal/analyzer/cloud`, `cloud/eks`).** The first cloud-aware analyzer. It reads EKS-specific state and extends the privesc graph past the cluster edge:
  - **IRSA (IAM Roles for Service Accounts).** `KUBE-CLOUD-IRSA-ADMIN-ROLE-001` flags a ServiceAccount annotated to assume an admin-equivalent IAM role; `KUBE-CLOUD-IRSA-MISSING-001` flags an IRSA annotation pointing at a role that cannot be resolved. A `ServiceAccount → IAM role` graph edge (`irsa_assume_role`) feeds the BFS so the assume-role step surfaces as a `KUBE-PRIVESC-PATH-AWS-IAM-ROLE` chain.
  - **aws-auth ConfigMap mapping.** The `kube-system/aws-auth` IAM-to-RBAC map is parsed to name the offending principals: `KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001` (an IAM principal mapped straight to `system:masters`), `KUBE-CLOUD-AWSAUTH-OVERBROAD-001` (mapped to a group bound to an admin-equivalent ClusterRole), and `KUBE-CLOUD-AWSAUTH-PARSE-ERROR-001` (malformed map). `external IAM principal → system:masters / cluster-admin` edges wire these into the graph.
  - **IMDS pivot.** `KUBE-CLOUD-IMDS-PIVOT-001` detects a pod that can reach the node instance-metadata endpoint (`169.254.169.254`) to steal the node IAM role. `KUBE-CLOUD-PROVIDER-UNKNOWN-001` records when the provider could not be identified.
  - External IAM nodes are modeled as terminal sinks with controlled traversal, so a chain can enter AWS without laundering back through the control plane.

- **Completed `KUBE-PRIVESC` technique taxonomy (7 new IDs) + Escalation Paths report tab.** Adds `KUBE-PRIVESC-002` (create pods into a namespace whose Pod Security Admission does not block privileged pods), `-004` (create/get on `pods/exec` or `pods/attach`), `-006` (get-only on secrets, split out of `-005` which is now list/watch), `-007` (create + get on secrets: mint a legacy token Secret pointed at a privileged SA, then read the token), `-013` (update/patch on `pods/ephemeralcontainers`), `-015` (create on `pods/portforward`), and `-016` (delete pods + node status write / delete: evict and reschedule onto an attacker node). New graph edges (`-002`, `-007`, `-013`, `-016`) feed the BFS so these surface as `KUBE-PRIVESC-PATH-*` chains. The HTML report gains a CSS-tab-gated **Escalation paths** tab listing every `KUBE-PRIVESC-PATH-*` chain, grouped by sink and sorted by danger.

- **Structured remediation hints across every analyzer.** All eight modules (podsec, rbac, privesc, network, admission, secrets+configmap, serviceaccount, containersec) now attach a `RemediationHint` to each finding with one or more of: a `kubectl patch` payload (strategic-merge / merge / JSON), a Kyverno `ClusterPolicy`, a Gatekeeper `ConstraintTemplate` + `Constraint`, or a unified RBAC diff. JSON/SARIF expose the whole struct; HTML renders a per-finding "Structured remediation" section with collapsible `<details>` blocks per surface.

- **`--remediation-patches` opt-in flag.** Added to `scan`, `scan-resource`, and `report`. Off by default. Pass the flag to populate the hint on each emitted finding; the same flag controls render-time inclusion in `report` so a JSON saved with hints renders cleanly with or without them.

- **Live EKS demo walkthrough.** [`docs/eks-demo.md`](docs/eks-demo.md) walks a cross-namespace privesc chain that pivots into AWS via IRSA, end to end, against a real EKS cluster.

### Changed

- **RBAC matching is now `(apiGroup, resource, verb)`-aware and honors `resourceNames`.** A new shared matcher (`internal/permissions/matcher.go`) requires the API group, resource, and verb to all line up (wildcards on each axis), so a custom resource that reuses a core name (e.g. `secrets.example.com`) no longer trips the core-`secrets` checks. `resourceNames` is now modeled on the effective rule: a name-scoped grant cannot authorize collection verbs (list / watch / deletecollection, create on a top-level resource), so it no longer fires the broad "read / enumerate / create the whole resource type" checks. Name-scoped RBAC findings gain a `scope:resource-names` tag and attenuated blast radius, ranking below unrestricted grants of the same permission instead of vanishing. The rbac, serviceaccount, and privesc analyzers (and the SA remediation matcher) all route through this one matcher.

- **Chain amplification (`correlate`) is now causal.** Each `EscalationHop` carries the technique of the edge that enabled it, and the correlation pass amplifies a finding only when its own `(subject, rule)` is an actual edge of an escalation chain, rather than bumping every finding that merely shares a subject with a privesc path.

- **BREAKING (in 0.x): RemediationHint emission is now opt-in.** Earlier builds attached hints unconditionally for the podsec, rbac, and privesc modules. They are now gated behind `--remediation-patches` for consistency with the five new module wirings. To restore prior behavior pass `--remediation-patches` on `scan` / `scan-resource` / `report`.

### Fixed

- External IAM nodes are terminal sinks with proper traversal, so cloud identities cannot be used as intermediate hops to launder a path.
- `hostNetwork` IMDS reachability, custom wildcard-ClusterRole detection, and Fargate `ProviderID` parsing corrected in the cloud module.
- Per-subject capability cards in the Least Privilege tab restyled for consistent sizing.

### Documentation

- EKS demo (`docs/eks-demo.md`), cloud findings catalog entries in [`docs/findings.md`](docs/findings.md), and a privilege-escalation methodology-gap research note.

### Dependencies

- `github.com/google/cel-go` 0.28.1 → 0.29.2, the `k8s.io` library group, `golang.org/x/text`, and several CI action bumps (checkout, cache, codeql-action, upload-artifact).

## [1.1.0] - 2026-05-16

This release expands kubesplaining from a detection tool into a delta-gated, remediation-aware assessment platform. The headline additions are: an audit-log-driven least-privilege analyzer (the AWS IAM Access Advisor analog for Kubernetes RBAC), a snapshot-diff `diff` command and `scan --baseline` flag so CI fails only on *new* findings, CEL-based `--custom-rules` for org-specific detections, Kyverno and Gatekeeper policy generators that turn findings into enforceable admission rules, and a new `containersec` analyzer module covering resource limits, probes, lifecycle hooks, and image pinning. A composite GitHub Action (`action.yml`) wraps the SARIF scan flow so you can wire kubesplaining into a workflow without authoring `docker run` invocations by hand.

### Added

- **`diff` command + `scan --baseline`** for CI delta gates. `kubesplaining diff old.json new.json` reports only new findings between two snapshots; `scan --baseline previous-findings.json` runs an analysis and fails the build only on findings that did not exist in the baseline. Pairs with `--ci-mode` so PR pipelines stop drifting on legacy findings nobody plans to fix today.

- **`--custom-rules` for CEL-based detections.** New `internal/analyzer/cel` module evaluates user-supplied CEL expressions against the snapshot, producing findings the same way built-in rules do. Ship a `.cel.yaml` rule next to your manifests; `kubesplaining scan --custom-rules ./rules/` picks them up. Example rules live in `examples/custom-rules/` (`no-default-namespace.cel.yaml`, `disallow-large-replica-counts.cel.yaml`).

- **`leastprivilege` analyzer module (audit-log driven).** Opt in via `--audit-log <path>` (kube-apiserver JSON-lines, or EKS CloudWatch export via `--audit-source eks`). The module compares RBAC granted to each ServiceAccount against verbs actually exercised in the audit window and flags the delta: `KUBE-RBAC-UNUSED-ROLE-001`, `KUBE-RBAC-UNUSED-RULE-001`, `KUBE-RBAC-UNUSED-VERB-001`, `KUBE-RBAC-WILDCARD-USED-PARTIAL-001`. A focused mode (`--least-privilege-only`) hides every other tab and lands on the Least Privilege view. See [`docs/audit-logs.md`](docs/audit-logs.md) for setup on kubeadm / kind / EKS.

- **`containersec` analyzer module.** New rules for resource limits absent, probes missing, lifecycle hook risk, and mutable image tags. Lives alongside `podsec` and shares its evidence schema.

- **`compliance` framework tags + Compliance tab.** Findings now carry CIS Kubernetes Benchmark and NSA Kubernetes Hardening Guidance control IDs where applicable; the HTML report adds a Compliance tab grouped by framework so auditors can pivot the findings list onto their existing control matrix.

- **Remediation generators (one library per policy engine).**
  - `internal/remediation/kubectl-patch`: kubectl-patch payloads for podsec rules (drop `privileged`, fix host namespaces, etc.).
  - `internal/remediation/kyverno`: Kyverno ClusterPolicy YAML for the same rule set, so you can paste the output into your policy bundle.
  - `internal/remediation/gatekeeper`: OPA Gatekeeper ConstraintTemplate + Constraint pairs.
  - `internal/remediation/rbac`: kubectl-patch and minimal-binding-diff generators for RBAC findings (smallest set of binding edits needed to remove a privesc edge).
  Each generator is invoked from the per-finding card in the HTML report; the JSON output exposes the generated payload under `properties.remediation`.

- **New analyzer rules across existing modules.**
  - `podsec`: `KUBE-PODSEC-CAPS-001` (dangerous Linux capabilities), readOnly-root-filesystem hardening, seccomp profile assessment, `procMount` overrides, PV-based hostPath bypass detection, Pod Security Admission namespace label assessment.
  - `secrets`: stale secret detection, cross-namespace secret access, TLS certificate expiry, ConfigMap credential heuristics.
  - `network`: cross-namespace traffic map, IMDS-endpoint egress detection (`169.254.169.254`).
  - `privesc`: CSR approval primitive (`KUBE-PRIVESC-011`) and the corresponding graph edges. A subject with `certificatesigningrequests/approval` can mint a high-privilege client cert; the analyzer now traces that to cluster-admin where applicable.
  - `rbac`: stale-binding detection (dangling `roleRef`, missing ServiceAccount subjects) under the new `KUBE-RBAC-STALE-*` rule family.

- **GitHub Action wrapper (`action.yml`).** Composite Action that pulls the pinned GHCR image and runs a scan against a live cluster (base64-encoded kubeconfig) or a snapshot JSON, with optional SARIF upload to GitHub code scanning. Drop into a workflow without hand-authoring the `docker run` form. Smoke-tested by `.github/workflows/action-smoke.yml`.

- **Report enhancements.**
  - Hero panel at the top of the HTML report highlights critical attack chains so the most actionable findings surface first.
  - Top-5-fixes panel groups remediation candidates by subject and resource so an operator sees the smallest set of changes that closes the most chains.
  - Per-subject capability cards in the Least Privilege tab spell out what a ServiceAccount can actually do.
  - Per-finding scoring tooltip explains how the composite score (`base × exploitability × blast_radius + chain_modifier`) was assembled.
  - Findings list capped to top 20 with category-balanced truncation so the report stays scannable; the full set remains in `findings.json`.
  - Per-subject finding groups and Least Privilege tables collapse by default for a calmer first view.

### Fixed

- `leastprivilege` no longer emits zero-event findings when the audit log contains no events for a subject; the module is a no-op in that case.
- Static-export HTML now gates JS-only interactivity copy (collapse/expand hints) so it does not appear when JavaScript is disabled.
- Font sizing inside Least Privilege finding cards normalized.
- Duplicate PersistentVolume entry removed from the glossary.
- GitHub Action container now runs as the host UID to avoid permission-denied writes when mounting `${{ github.workspace }}`.
- Action smoke test builds the image locally and skips the pull step when the image is already present.
- `errcheck` warning silenced on the stderr truncation-notice write path.

### Changed

- The e2e fixture is now split into per-feature manifest files (`testdata/e2e/vulnerable/00-baseline.yaml` through `14-csr.yaml`) with matching `.expect` / `.rollout` expectation files, replacing the single `testdata/e2e/vulnerable.yaml`. `scripts/kind-e2e.sh` rolls up each fixture, waits for its rollout, and asserts the rule IDs from the per-file expectation list.

### Documentation

- README rewritten for adoption: hero paragraph names the multi-hop-RBAC-graph differentiator, copy-pasteable from-clone install snippet, vs-alternatives table positioning against kubescape / trivy / polaris, and inspiration credits for [Kinnaird McQuade](https://www.linkedin.com/in/kmcquade3/) at BeyondTrust Phantom Labs and [Ramesh Ramani](https://www.linkedin.com/in/rameshdotramani/) (who inspired the least-privilege mode).
- New `docs/audit-logs.md` covers enabling audit logging on self-managed / kubeadm, kind, and EKS clusters and exporting from CloudWatch.
- CLAUDE.md and README spell out CI gates not exercised by `make lint` (repo-wide golangci-lint, PR title length, repo-wide `go vet`).
- README documents when the `leastprivilege` module fires (with a behavior matrix across `scan`, `--audit-log`, `--least-privilege-only`, and `make scan-lp`).

### CI / Build

- Multi-stage Dockerfile (`Dockerfile.goreleaser`) for smaller release images.
- Release tag pattern in `.github/workflows/release.yml` tightened to match `v*.*.*` only.
- `example-report.yml` Pages workflow publishes the uncapped report so the Least Privilege tab is populated on the hosted demo.
- Dependabot bumps: `actions/setup-go` 5→6, `docker/setup-qemu-action` 3→4.

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

[Unreleased]: https://github.com/0hardik1/kubesplaining/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/0hardik1/kubesplaining/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/0hardik1/kubesplaining/releases/tag/v1.1.0
[1.0.0]: https://github.com/0hardik1/kubesplaining/releases/tag/v1.0.0
