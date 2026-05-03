# Kubesplaining

[![Latest release](https://img.shields.io/github/v/release/0hardik1/kubesplaining?include_prereleases&sort=semver)](https://github.com/0hardik1/kubesplaining/releases)
[![License](https://img.shields.io/github/license/0hardik1/kubesplaining)](LICENSE)
[![CI](https://github.com/0hardik1/kubesplaining/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/0hardik1/kubesplaining/actions/workflows/lint.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/0hardik1/kubesplaining)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/0hardik1/kubesplaining)](https://goreportcard.com/report/github.com/0hardik1/kubesplaining)

A Kubernetes security assessment CLI that maps every RBAC subject's privilege-escalation paths to cluster-admin, host root, and kube-system secrets, then renders the chains as a risk-prioritized HTML / JSON / CSV / SARIF report.

* [Live example report](https://0hardik1.github.io/kubesplaining/)

> <video src="https://github.com/user-attachments/assets/b32aa71e-4220-437d-8676-2a58a466a5e1" controls width="100%"></video>

Inspired by [Kinnaird McQuade](https://www.linkedin.com/in/kmcquade3/) at [BeyondTrust Phantom Labs](https://www.linkedin.com/company/beyondtrust-phantom-labs/) and his [Cloudsplaining](https://github.com/salesforce/cloudsplaining), which does the same job for AWS IAM. Kubesplaining reads a live cluster or a previously captured snapshot, analyzes it against a library of techniques, and produces a prioritized list of findings: explanation, not just detection.

## Why kubesplaining

Most Kubernetes scanners stop at "this resource is misconfigured." Kubesplaining answers a different question: **how would an attacker actually move through your cluster?** Given the RBAC bindings and pods you already have, it walks the escalation graph from every non-system subject and tells you which can reach `cluster-admin`, host root, or `kube-system` secrets, with the full hop chain attached.

It focuses on the ground attackers actually exploit:

- **Privilege escalation paths**: graph-based chains of "subject A can become subject B can reach sink X" via BFS to four sinks (`cluster-admin`, `system:masters`, `node-escape`, `kube-system-secrets`).
- **Overly permissive RBAC**: wildcards, impersonation, bind/escalate, secret reads, pod creation, token mint.
- **Pod-escape surface area**: privileged containers, host namespaces, sensitive hostPath mounts, container socket mounts.
- **Network isolation gaps**: namespaces with no NetworkPolicy, policies that allow broad internet egress.
- **Admission-control bypass**: webhooks that fail open, objectSelector bypasses, exempt sensitive namespaces.
- **Secrets and service-account hygiene**: legacy token secrets, credentials in ConfigMaps, default-SA mounting, DaemonSet token blast-radius.

Every finding names the technique, shows the evidence, and includes remediation.

**Use cases:**

- **Pentest / red-team engagements**: the escalation paths *are* the attack plan.
- **Security review before a new binding**: see if it closes the graph from someone untrusted to a sink.
- **Continuous assurance in CI**: `--ci-mode` with severity budgets fails the pipeline when high-severity findings cross a threshold.
- **Post-incident replay**: capture the snapshot, analyze offline, explain how the actor could have moved.

## Quickstart

After installing (see [Installation](#installation) below), point Kubesplaining at your current `kubectl` context:

```bash
kubesplaining scan                          # writes ./kubesplaining-report/
open kubesplaining-report/report.html       # macOS; xdg-open on Linux
```

Already cloned the repo? `make scan` builds the binary (Hermit auto-downloads the pinned Go toolchain) and runs it against your current `kubectl` context in one step — no separate install needed. Pass extra flags via `ARGS`, e.g. `make scan ARGS="--severity-threshold high --only-modules privesc"`.

For air-gapped or audit workflows, capture a snapshot first and analyze it offline:

```bash
kubesplaining download --output-file snapshot.json
kubesplaining scan --input-file snapshot.json
```

For one-off manifest checks without cluster access:

```bash
kubesplaining scan-resource --input-file deployment.yaml
```

## Installation

Pick the path that fits. All three produce the same `kubesplaining` binary.

### Go install

```bash
go install github.com/0hardik1/kubesplaining/cmd/kubesplaining@latest
```

### Pre-built binary

Grab the archive matching your OS / arch from the [Releases page](https://github.com/0hardik1/kubesplaining/releases/latest), extract, and put `kubesplaining` on your `PATH`. Each release ships:

- `kubesplaining_<version>_Linux_x86_64.tar.gz` / `Linux_arm64.tar.gz`
- `kubesplaining_<version>_Darwin_x86_64.tar.gz` / `Darwin_arm64.tar.gz`
- `kubesplaining_<version>_Windows_x86_64.zip`
- `kubesplaining_<version>_checksums.txt` (SHA-256)

Verify the checksum, then move the binary into place:

```bash
shasum -a 256 -c kubesplaining_<version>_checksums.txt
sudo install kubesplaining /usr/local/bin/
```

### Homebrew

Coming as a post-release fast-follow: `brew install 0hardik1/tap/kubesplaining` will be wired up shortly after v1.0.0.

## What it checks

41 stable rule IDs across 7 modules today, plus the privilege-escalation graph that chains them. Full per-rule severity, detection logic, and remediation: [docs/findings.md](docs/findings.md).

| Module | Rules | Focus |
| --- | --- | --- |
| **rbac** | 10 | wildcard / impersonate / bind-escalate / secret-read / pod-create / nodes-proxy / token-create |
| **podsec** | 13 | privileged, host namespaces, hostPath, container sockets, runAsRoot, mutable tags |
| **network** | 5 | namespaces missing NetworkPolicy, broad-internet egress, unselected workloads |
| **admission** | 3 | failurePolicy: Ignore, objectSelector bypass, sensitive-namespace exemptions |
| **secrets** | 4 | legacy SA token secrets, credential-like ConfigMap keys, CoreDNS tampering |
| **serviceaccount** | 4 | privileged SAs, default-SA RBAC, DaemonSet token blast-radius |
| **privesc** | 4 sinks | graph chains to cluster-admin / system:masters / node-escape / kube-system-secrets |

Every finding is tagged with a `RiskCategory` (`privilege_escalation`, `data_exfiltration`, `lateral_movement`, `infrastructure_modification`, `defense_evasion`) so the HTML report can group by impact lane.

Rule IDs are a **public surface**: they are stable across releases and referenced from `findings.json`, the SARIF output, and the e2e assertions in `scripts/kind-e2e.sh`.

## How it works

Four-stage pipeline:

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Connection   │ →  │  Collection   │ →  │   Analysis    │ →  │    Report     │
│  kubeconfig   │    │ snapshot.json │    │  7 modules ∥  │    │  html/json/   │
│ / in-cluster  │    │ RBAC+workload │    │  findings[]   │    │   csv/sarif   │
└───────────────┘    └───────────────┘    └───────────────┘    └───────────────┘
```

The boundary that matters most: the **collector is the only thing that talks to the Kubernetes API**; analyzers consume a `Snapshot` and never make network calls. That's what makes `download` → `scan --input-file` work for offline analysis. Read-only access is sufficient: no admission webhooks, no agents, no CRDs installed.

For the per-stage walkthrough, the privesc graph mechanics, the data model, and the scoring formula: [docs/architecture.md](docs/architecture.md).

## Sample finding

What the output actually looks like. Each rule produces a `Finding` with stable `RuleID`, severity, evidence, and remediation; the privesc rules additionally carry an `EscalationPath` array.

<details>
<summary><strong>KUBE-PRIVESC-PATH-CLUSTER-ADMIN</strong>: service account reaches cluster-admin in 2 hops</summary>

```json
{
  "id": "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:foo:builder-bot",
  "rule_id": "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
  "severity": "CRITICAL",
  "score": 9.3,
  "category": "privilege_escalation",
  "subject": { "kind": "ServiceAccount", "namespace": "foo", "name": "builder-bot" },
  "title": "ServiceAccount foo/builder-bot can reach cluster-admin equivalent in 2 hop(s)",
  "escalation_path": [
    {
      "from_subject": "ServiceAccount/foo/builder-bot",
      "to_subject":   "ServiceAccount/kube-system/replicaset-controller",
      "action":       "pod_create",
      "permission":   "create on pods",
      "gains":        "run a pod that mounts the kube-system replicaset-controller token"
    },
    {
      "from_subject": "ServiceAccount/kube-system/replicaset-controller",
      "to_subject":   "ClusterRole/cluster-admin",
      "action":       "wildcard_holder",
      "permission":   "*/*/*",
      "gains":        "this SA already holds cluster-admin equivalence"
    }
  ],
  "remediation": "Drop `create pods` from foo/builder-bot's role, OR move that workload off kube-system."
}
```

The HTML report renders this as a hop-by-hop card with technique explainers per edge; the SARIF output keeps the chain in the `properties.escalationPath` field for IDE integration.

</details>

<details>
<summary><strong>KUBE-ESCAPE-001</strong>: privileged container with hostPath mount</summary>

```json
{
  "id": "KUBE-ESCAPE-001:default:debug-shell",
  "rule_id": "KUBE-ESCAPE-001",
  "severity": "CRITICAL",
  "score": 9.5,
  "category": "privilege_escalation",
  "resource": { "kind": "Pod", "namespace": "default", "name": "debug-shell" },
  "title": "Privileged container in default/debug-shell",
  "evidence": {
    "container": "debug",
    "securityContext": { "privileged": true },
    "volumeMounts": [{ "name": "host-root", "mountPath": "/host", "hostPath": "/" }]
  },
  "remediation": "Drop `privileged: true`; replace hostPath `/` with the specific files via ConfigMap / Secret / CSI."
}
```

</details>

<details>
<summary><strong>KUBE-RBAC-OVERBROAD-001</strong>: group bound directly to cluster-admin</summary>

```json
{
  "id": "KUBE-RBAC-OVERBROAD-001::ops-team-admin",
  "rule_id": "KUBE-RBAC-OVERBROAD-001",
  "severity": "CRITICAL",
  "score": 9.0,
  "category": "privilege_escalation",
  "subject": { "kind": "Group", "name": "ops-team" },
  "title": "Group ops-team is bound to cluster-admin",
  "evidence": {
    "clusterRoleBinding": "ops-team-admin",
    "roleRef": "cluster-admin"
  },
  "remediation": "Replace cluster-admin with a least-privilege role scoped to what ops-team actually needs."
}
```

</details>

For the full rule catalog (severity, detection, remediation per rule): [docs/findings.md](docs/findings.md).

## Offline analysis

The collector and the analyzer are decoupled: the snapshot is a plain JSON file. Capture once, analyze repeatedly, in environments where credentials shouldn't sit on the analyst's machine:

```bash
# On a jumphost with cluster credentials:
kubesplaining download --output-file snapshot.json

# Move snapshot.json to your laptop / audit machine, then:
kubesplaining scan --input-file snapshot.json
```

Useful for:

- **Audit trails**: the snapshot is the evidence; reruns produce identical findings.
- **Air-gapped review**: analyze a production cluster without bringing kubeconfig off the jumphost.
- **Manifest scans**: `kubesplaining scan-resource --input-file deployment.yaml` runs the same analyzers against a single YAML, no cluster needed.

## CI integration

The SARIF output integrates with [GitHub code scanning](https://docs.github.com/en/code-security/code-scanning) so findings appear as PR annotations. Until the dedicated GitHub Action ships (post-release fast-follow), the `docker run` form works directly:

```yaml
# .github/workflows/kubesplaining.yml
name: Kubesplaining
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v6
      - name: Scan manifests
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/work" -w /work \
            ghcr.io/0hardik1/kubesplaining:latest \
            scan-resource --input-file manifests/ --output-format sarif \
            --output-dir /work/kubesplaining-report
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kubesplaining-report/results.sarif
```

Or fail the build on findings over budget with `--ci-mode`:

```bash
kubesplaining scan --ci-mode --ci-max-critical 0 --ci-max-high 0
```

`--ci-mode` exits non-zero when the count of critical / high findings crosses the configured thresholds; combine with `--severity-threshold` to scope what counts.

## Exclusions

`scan`, `scan-resource`, and `report` **auto-apply the `standard` exclusions preset by default**, so findings about built-in Kubernetes plumbing are suppressed up front. That covers kube-system / kube-public / kube-node-lease namespaces, kube-controller-manager service accounts (`clusterrole-aggregation-controller`, `generic-garbage-collector`, …), `system:*` users / groups / roles, and `kubeadm:*` groups and bootstrap roles. None of it is something an operator can change without breaking their cluster, so showing it as risk just buries the things that are actionable.

Pick a different baseline with `--exclusions-preset`:

| Preset | Behavior |
| --- | --- |
| `standard` (default) | Auto-applied. Filters kube-system / system:* / kubeadm:* noise. |
| `minimal` | Filters only `kube-public`, `kube-node-lease`, and `system:*`. |
| `none` (alias `strict`) | No built-in filtering: every finding surfaces, including control-plane noise. |

Layer custom rules on top with `--exclusions-file path.yml`. The user file is **merged** with the preset, so you keep the defaults and add your own suppressions (specific service accounts, expected workloads, custom rule-ID patterns). Generate a starter file:

```bash
kubesplaining create-exclusions-file --preset standard --output-file exclusions.yml
```

See [docs/exclusions.md](docs/exclusions.md) for the full YAML schema (Global / RBAC / PodSecurity / NetworkPolicy sections, all matchers support shell-style globs).

To audit what the defaults are hiding, re-run with `--exclusions-preset=none` and diff.

## Cheatsheet

### Commands

| Command | Purpose |
| --- | --- |
| `kubesplaining scan` | Analyze (live or `--input-file`) and write reports. |
| `kubesplaining download` | Capture a `snapshot.json` from a live cluster. Read-only. |
| `kubesplaining scan-resource` | Scan a single resource manifest for quick checks. |
| `kubesplaining report` | Re-render reports from an existing findings JSON. |
| `kubesplaining create-exclusions-file` | Emit a starter exclusions YAML. |
| `kubesplaining version` | Print build info. |

### Frequently used flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--severity-threshold` | `low` | Hide findings below this severity (`critical` / `high` / `medium` / `low` / `info`). |
| `--output-format` | `html,json` | Comma-separated list: `html`, `json`, `csv`, `sarif`. |
| `--output-dir` | `./kubesplaining-report` | Where reports are written. |
| `--only-modules` / `--skip-modules` | — | Scope analyzers (`rbac`, `podsec`, `network`, `admission`, `secrets`, `serviceaccount`, `privesc`). |
| `--max-privesc-depth` | `5` | BFS depth cap for the escalation graph. |
| `--ci-mode` | off | Exit non-zero when over thresholds. |
| `--ci-max-critical` / `--ci-max-high` | `0` / `0` | Max findings allowed at each severity in CI mode. |
| `--exclusions-preset` | `standard` | `standard` / `minimal` / `none`. |
| `--exclusions-file` | — | User-supplied YAML, merged on top of the preset. |
| `--input-file` | — | Use a snapshot JSON instead of live collection. |
| `--namespaces` / `--exclude-namespaces` | — | Filter live collection by namespace. |
| `--parallelism` | `10` | Max parallel API requests during live collection. |

### Output formats

| Format | Use case |
| --- | --- |
| HTML | Human review; self-contained, works offline, includes per-finding educational copy |
| JSON | Programmatic consumption, snapshot diffing |
| CSV | Triage spreadsheets |
| SARIF | GitHub code scanning, IDE integration |

## FAQ

**Why is `system:masters` flagged in some clusters but not others?**
The privesc analyzer skips `system:*` subjects as *traversable intermediates* (so paths don't launder through the control plane) but it *does* report `system:*` as a sink-reach target if you can impersonate or otherwise escalate into it. If the analyzer doesn't see anyone with that capability, the rule stays silent.

**How accurate are the privesc paths?**
Each hop is validated against the snapshot's RBAC and pod state. The analyzer doesn't speculate. False positives come from chains that are *structurally* possible but operationally suppressed (e.g. an SA bound to a role that's never actually used). Severity is attenuated by chain length (hops ≥ 3 drop one bucket); use `--max-privesc-depth` to limit BFS aggressiveness.

**Can I run this against my prod cluster?**
Yes. Read-only access is sufficient. No webhooks, CRDs, agents, or pods are installed. Forbidden listings are downgraded to warnings, not fatal, so locked-down clusters still produce useful output.

**Why no admission webhook?**
Out of scope. The intent is *assessment*, not enforcement. If you want enforcement, generate Kyverno / Gatekeeper policies from the findings and hand them off to your policy engine.

**Why are findings excluded by default?**
The `standard` preset suppresses control-plane noise (kube-system, system:*, kubeadm:*) that an operator can't change without breaking their cluster. Re-run with `--exclusions-preset=none` to see everything.

## Where to go next

- **Full rule catalog** (implemented + planned): [docs/findings.md](docs/findings.md)
- **Architecture deep-dive** (per-stage walkthrough, scoring, data model): [docs/architecture.md](docs/architecture.md)
- **Exclusions YAML schema** (presets, sections, glob semantics): [docs/exclusions.md](docs/exclusions.md)
- **Roadmap & status**: [PLAN.md](PLAN.md)
- **Releases & changelog**: [CHANGELOG.md](CHANGELOG.md) / [GitHub Releases](https://github.com/0hardik1/kubesplaining/releases)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security disclosure**: [SECURITY.md](SECURITY.md) (GitHub Private Vulnerability Reporting only)
- **License**: [Apache-2.0](LICENSE)
- **End-to-end verification**: `make e2e` provisions a local kind cluster with intentionally risky manifests in `testdata/` and asserts expected findings
