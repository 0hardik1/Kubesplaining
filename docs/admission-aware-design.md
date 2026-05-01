# Admission-Aware Pod-Security Findings — Roadmap

**Status:** Phase 1 shipped. Phase 2 / 3 / 4 are deferred future work, captured below so the next iteration can resume without re-deriving the design.

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Pod Security Admission (PSA) namespace-label awareness — `suppress`/`attenuate`/`off` modes | **Shipped** |
| 2 | Collect VAP / Kyverno / Gatekeeper CRDs and emit `KUBE-ADMISSION-NO-POLICY-ENGINE-001` posture finding when none is present | Deferred |
| 3 | Evaluate `ValidatingAdmissionPolicy` CEL expressions offline via `cel-go` | Deferred |
| 4 | Operator attestation flow for Kyverno / Gatekeeper / custom webhooks (effects we cannot statically determine) | Deferred |

## Context

Kubesplaining's pod-security analyzer (`internal/analyzer/podsec/`) emits 13 host-level rule IDs (`KUBE-ESCAPE-001..008`, `KUBE-HOSTPATH-001`, `KUBE-CONTAINERD-SOCKET-001`, `KUBE-PODSEC-APE-001`, `KUBE-PODSEC-ROOT-001`, etc.) by inspecting pod specs in isolation. It never asks "would this pod actually have been admitted to this cluster?"

In real prod environments, the answer is often **no** — Pod Security Admission, ValidatingAdmissionPolicy (v1 CEL), Kyverno, or Gatekeeper would reject these specs at admission time. The pod is in the snapshot only because it was already running before the policy was applied, or because the policy is in `audit`/`warn` mode rather than `enforce`. Either way, today's report flags it as CRITICAL with no acknowledgement that a defense is already in place.

For large clusters this means hundreds of host-level findings that look like emergencies but are already mitigated. Operators tune out the report ("it flags everything"), and the genuine risk — workloads that would slip past admission — gets buried in noise.

The fix is to make the analyzer admission-aware: read what's already in the snapshot (PSA labels, webhook configs) plus collect what's missing (VAP, Kyverno, Gatekeeper), reason about what each control would block, and act on that.

By default the tool **suppresses** findings that the namespace's PSA `enforce` label would reject — large clusters need aggressive noise reduction, and that noise is the dominant signal-to-noise problem in the report today. Two invariants keep suppression honest: the report header always shows a count of suppressed findings (with per-namespace breakdown) so the hidden risk is auditable, and `audit`/`warn`-mode labels never trigger suppression because they do not actually block creates or updates. Users who want every residual risk to stay in the report can opt into `--admission-mode=attenuate`, which downweights but keeps the finding visible.

---

## Phase 1 — PSA awareness (shipped)

Phase 1 was the cheapest and most accurate phase: PSA is fully declarative, the labels are already in `Snapshot.Resources.Namespaces[*].Labels`, and the rules each enforcement level blocks are stable and documented.

### What landed

- **`internal/analyzer/admission/mitigation/psa.go`** owns the `check:` tag → enforcement-level lookup table:

  | podsec `check:` tag | Blocked by `restricted` | Blocked by `baseline` | Blocked by `privileged` |
  |---|---|---|---|
  | `privileged` | yes | yes | no |
  | `hostPath` (any) | yes | yes | no |
  | `hostNetwork` / `hostPID` / `hostIPC` | yes | yes | no |
  | `allowPrivilegeEscalation` | yes | no | no |
  | `runAsRoot` | yes | no | no |
  | `defaultServiceAccount` | no | no | no |
  | `imageTag` (`:latest`) | no | no | no |

- **`internal/analyzer/admission_mitigation.go`** holds the `applyAdmissionMitigations` engine stage. It runs **before** `correlate` so chain amplification builds on already-attenuated scores. For each `module:pod_security` finding:
  1. Resolve the finding's namespace.
  2. Look up `Snapshot.Resources.Namespaces[ns].Labels["pod-security.kubernetes.io/enforce|audit|warn"]`.
  3. Cross-reference the finding's `check:` tag with `mitigation.WouldPSABlock`.
  4. Apply the configured `--admission-mode`:
     - `suppress` (default) — drop the finding from the slice; bump the `models.AdmissionSummary.SuppressedByNamespace[ns][ruleID]` counter.
     - `attenuate` — drop severity by exactly one bucket via `models.Severity.Down()`, snap score to the new bucket's floor via `scoring.MinScoreForSeverity`, append `admission:mitigated-psa-<level>`.
     - `off` — no-op.
  5. Audit/warn-mode labels never suppress or attenuate; they only contribute `admission:audit-psa-<level>` / `admission:warn-psa-<level>` tags.

- **`internal/models/admission.go`** defines `AdmissionSummary`. `Engine.Analyze` now returns `AnalyzeResult{Findings, Admission}` so the CLI can surface counts without a second pass over the slice.

- **CLI flag `--admission-mode={off|attenuate|suppress}`** on `scan`, default `suppress`. `scan-resource` pins `off` (no namespace context to evaluate against). Invalid values reject with a clear error.

- **Report integration**:
  - `report.WriteWithAdmission` writes a sidecar `admission-summary.json` next to `scan-metadata.json` so `kubesplaining report --input-file=findings.json` re-reads it and re-renders the HTML banner.
  - `internal/report/assets/report.html.tmpl` renders an `.admission-banner` block with suppression / attenuation counts and a per-namespace details list.
  - SARIF: `runs[0].properties.admission` carries the same `AdmissionSummary` for IDE/CI consumers.

- **Verification**: unit tests cover every (check × enforce-level × mode) combination in `internal/analyzer/admission/mitigation/psa_test.go` and the full engine stage in `internal/analyzer/admission_mitigation_test.go`. The kind e2e (`scripts/kind-e2e.sh` + `testdata/e2e/vulnerable.yaml`) adds a `psa-suppressed` namespace, applies the `enforce=restricted` label after the deployment rolls out (so the privileged pod is already running — PSA only checks at create/update time), and asserts both default-suppress and explicit `--admission-mode=attenuate` flows.

### Default-mode rationale

The default is `--admission-mode=suppress`. Two invariants keep this safe:

- **Suppression is always counted in the report header.** Operators never lose visibility into how much risk the report is hiding — they just don't have to scroll through it as individual findings.
- **Audit/warn-mode is never suppressed.** PSA `audit` and `warn` log violations but do not block creates or updates. A pod with `privileged: true` in a namespace labeled `pod-security.kubernetes.io/audit=restricted` (no `enforce`) is a genuine, present-day risk, and the finding stays at full severity with an `admission:audit-psa-restricted` tag explaining what's missing.

For risk-conservative environments (compliance audits, "every residual risk must remain in the report"), `--admission-mode=attenuate` is the documented escape hatch. For maximum compatibility, `--admission-mode=off` reproduces the pre-Phase-1 behavior.

CI guidance documented alongside the flag: pair `--admission-mode=suppress` with `--baseline=previous-scan.json` so policy removal surfaces as new findings on the next scan. This is the regression-detection story that makes suppression defensible.

---

## Phase 2 — Policy-engine detection (deferred)

Phase 1 covers the most common case but misses clusters that rely on Kyverno, Gatekeeper, or VAP without using PSA labels (still very common). The cheapest improvement is to **collect** the relevant CRDs and emit two kinds of signal:

1. **Posture finding when none are present**: `KUBE-ADMISSION-NO-POLICY-ENGINE-001`, MEDIUM, "cluster has no Pod Security Admission labels and no detected policy engine; pod-security findings cannot be admission-mitigated." This is itself useful — it tells operators their cluster is one mistake away from accepting a privileged pod.
2. **Per-finding tag when policies *are* present but not evaluated**: append `admission:policy-engine-detected:<kyverno|gatekeeper|vap>` to host-level findings without changing the score. The HTML report shows "A policy engine is configured in this cluster but kubesplaining did not evaluate its rules. Consider running the same scan with `--admission-mode=evaluate-vap` (Phase 3) for ValidatingAdmissionPolicy support, or manually verify."

### Files to modify

- `internal/models/snapshot.go` — extend `SnapshotResources` with `ValidatingAdmissionPolicies`, `ValidatingAdmissionPolicyBindings`, `KyvernoPolicies`, `GatekeeperConstraints`. Use `unstructured.Unstructured` for the latter two so we don't take a CRD-typed dependency on each engine.
- `internal/collector/collector.go` — add the four list operations under the existing parallel-listing pattern. Downgrade NotFound errors (CRDs not installed) to `CollectionWarnings`, never failures — the same convention the collector uses everywhere else.
- `internal/analyzer/admission/analyzer.go` — add the new `KUBE-ADMISSION-NO-POLICY-ENGINE-001` posture rule.
- `internal/analyzer/admission/mitigation/detection.go` — new file, the `policy-engine-detected` tag application pass that runs alongside `applyAdmissionMitigations`.
- `docs/findings.md` — document the new rule and tag.

### Resume notes

- Phase 1's `applyAdmissionMitigations` already takes the snapshot, so adding a parallel `applyPolicyEnginePresenceTags` stage (or extending the existing one) is the natural insertion point.
- Kyverno's `kyverno.io` API group and Gatekeeper's `constraints.gatekeeper.sh` group are stable enough to hard-code; the resource list is what `kubectl api-resources` shows them as.
- Auth: list permissions on these CRDs are typically read-only via the standard scanner role. Document the new RBAC requirement in `docs/architecture.md` ("Access requirements" section).
- E2E: kind clusters can install Kyverno via Helm in <30s, but it adds non-trivial CI time. Consider a separate e2e job rather than extending the default one.

---

## Phase 3 — Real VAP evaluation (deferred)

This is the only phase that adds a meaningful runtime dependency (`github.com/google/cel-go`). It's also the phase with the highest user value because VAP is the K8s-native, GA, declarative way to express admission rules — and CEL is evaluable offline.

Compile each `ValidatingAdmissionPolicy`'s `validations[*].expression` with cel-go, evaluate it against each pod in the snapshot (with the pod's namespace honoring `ValidatingAdmissionPolicyBinding.spec.matchResources` + `paramRef`), and treat a `false` result the same way Phase 1 treats a PSA block. Skip Kyverno/Gatekeeper here — Kyverno's matching is tractable but its mutation/Jinja semantics are not 1:1 reproducible offline, and Gatekeeper requires the OPA Rego runtime. The honest UX is: "VAP is fully evaluated; for Kyverno/Gatekeeper kubesplaining tells you they exist but defers to operator attestation (Phase 4) for what they block."

The `--admission-mode` flag should reserve `evaluate-vap` as a documented future value but reject it for now with "not yet implemented." Rejecting the unknown-but-reserved value (rather than silently treating it as one of the existing modes) gives users a clear "you're ahead of the implementation" signal.

### Resume notes

- `cel-go` is roughly a 200KB dependency; not free but acceptable for the value.
- VAP introduces variable bindings (`paramKind` / `paramRef`) — the simplest first cut is to evaluate policies that don't use parameters and emit an `admission:vap-not-evaluated:<reason>` tag for those that do.
- Test fixtures: the K8s docs ship example VAPs that block `privileged: true` and `hostPath` mounts. Use those as the unit-test corpus.

---

## Phase 4 — Operator-attested admission effect (deferred)

Phase 1–3 cover what kubesplaining can determine *statically* from the snapshot. The remaining gap is real: **Kyverno** with templated rules and **Gatekeeper** Rego constraints have policy semantics we can't faithfully reproduce offline without bundling each engine's runtime. Custom `ValidatingWebhookConfiguration` bodies are opaque code in operator-owned services; the snapshot only sees the configuration metadata, not the policy logic.

For these, the most reliable signal is **the operator's claim** about what the cluster's controls actually block. This phase introduces a structured way to capture that claim, cross-check it against reality, and consume it during scoring.

### `kubesplaining attest-admission` subcommand

Verb-noun matches the existing `create-exclusions-file` convention at `internal/cli/create_exclusions.go`.

- Takes `--input-file` (snapshot) or live cluster (same connection logic as `scan`).
- Reuses Phase 2 collection to detect Kyverno / Gatekeeper / VAP / webhook controls.
- For each detected engine, prompts **per `check:` tag in the host-security family** (≈10 prompts per engine, not per-namespace): "Does Kyverno block `privileged` containers cluster-wide? [y/n/audit/skip]". `y` = enforce, `audit` = log-only, `n`/`skip` = no attestation.
- Writes a `policy-attestation.yaml` artifact with: cluster identity (`Snapshot.Metadata.ClusterName` or kubeconfig context), per-engine list of attested check tags + mode, the policy resource UIDs and resourceVersions observed at attestation time, the attesting operator's identity (`git config user.email` fallback `$USER`), and an ISO-8601 timestamp.

### `scan` integration

- New flag `--policy-attestation=path.yaml` — explicit, never auto-loaded. CI-safe by default; non-interactive runs see no behavioral change unless the flag is passed.
- When loaded, attested check tags drive findings the same way Phase 1 handles PSA blocks (suppress under `suppress` mode, downweight under `attenuate`), tagged with `admission:attested-<engine>` (e.g. `admission:attested-kyverno`, `admission:attested-gatekeeper`, `admission:attested-webhook`).
- **Staleness check**: if the attestation's policy UIDs no longer exist in the current snapshot, or resourceVersions diverge by more than a configurable threshold, treat the attestation as **stale** and skip it (with a CollectionWarning). Forces re-attestation when policies change.
- **Contradiction detection** — the safety net: for every workload finding that an attestation says should be blocked, kubesplaining cross-checks the workload's `creationTimestamp` against the policy's `creationTimestamp`. If the workload was created **after** the policy and still has the offending spec, emit a new CRITICAL finding `KUBE-ADMISSION-ATTESTATION-CONTRADICTED-001` and **do not** attenuate the original finding. Either the policy doesn't actually do what the operator thinks, or there's an exemption the attestation didn't capture — both deserve a loud signal.

### Why a separate file, not `exclusions.yaml`

Exclusions are workload-scoped assertions ("this finding doesn't apply to this pod"); attestations are policy-scoped assertions ("this control class is in force cluster-wide"). Different audit semantics, different durability requirements (attestations expire on policy resourceVersion drift; exclusions don't). Forcing them into one schema would muddle both.

### Why PSA stays auto-detect-only (even after Phase 4)

PSA labels are *in* the snapshot. Asking the operator "do you have PSA?" when we can read `Namespaces[ns].Labels["pod-security.kubernetes.io/enforce"]` directly is worse than redundant — operators answer "yes" without checking actual labels, and the report under-flags namespaces that lack the label. Phase 4 only covers controls we can't statically determine.

### Resume notes

- TTY detection lives at `internal/cli/output.go`. Any Phase 4 prompt path must check it and fall through to a `--non-interactive` no-op when stdin isn't a TTY.
- The CLI already has `git config user.email` reading; reuse that for attestation signing.
- The attestation schema should embed the kubesplaining version that wrote it so future versions can detect schema drift.

---

## Decisions recorded during Phase 1

- **Scope of initial PR**: Phase 1 only (PSA auto-detect + suppression/attenuation). Phase 2 (VAP/Kyverno/Gatekeeper CRD collection + posture finding), Phase 3 (VAP CEL evaluation), and Phase 4 (operator attestation) are documented as future work but explicitly out of scope.
- **Default mode**: `--admission-mode=suppress`. Aggressively reduces noise for large clusters. Safety invariants: the suppression count is always shown in the report header, audit/warn-mode findings are never suppressed, and CI guidance documents pairing with `--baseline` for drift detection.
- **Attenuation rule**: drop severity by exactly one bucket via `Severity.Down()`, then snap score to the floor of the new bucket via `scoring.MinScoreForSeverity`. The original "× 0.2 multiplier" idea was discarded because it pushed Critical findings into Info, which the default `--severity-threshold=low` filter then dropped — making attenuate indistinguishable from suppress for high-severity findings.
- **Mitigation encoding**: tags-only on `Finding.Tags` for v1. No `Finding` schema change. The structured `Mitigations []Mitigation` slice can be added later as an additive JSON field without breaking existing consumers.
- **Phase 4 (operator attestation)**: documented as a deferred phase in this doc so the path forward is visible, but not built. Revisit once Phase 1 has shipped and we observe whether Kyverno/Gatekeeper-heavy users complain.
