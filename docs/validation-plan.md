# Validation Plan

**Status:** proposal. Nothing in the harness sections is implemented yet.

**Landed since this was written**, and it changes two sections below. A review pass
against the tree found three soundness defects and one doc drift, and all four were
fixed rather than documented:

1. `modify_role_binding` and `bind_or_escalate` were each emitted from a single RBAC
   verb, so the tool predicted routes the API server's escalation-prevention check
   refuses. Both are now conjunctions built in a per-subject pass
   (`privesc/graph.go:addRBACWriteEdges`): a binding write needs `bind`, and
   `escalate` needs write access to a role. **This removes the pre-registered false
   positive R2-C1 and §4 were built on.**
2. `impersonate users` reached `cluster_admin` unconditionally. It now emits one edge
   per User subject a binding actually names. Measured on the e2e kind cluster: the
   only `User` subjects present are `system:*`, and the admin identity rides on the
   *group* `kubeadm:cluster-admins`, so on a stock cluster this grant reaches no
   privileged user at all. `impersonate groups` stays unconditional, correctly.
3. `permissions.Aggregate` read `clusterRole.Rules` only, so an aggregated ClusterRole
   registered as granting nothing on any manifest-sourced snapshot. It now expands
   `aggregationRule` when `.rules` is empty and trusts `.rules` when the aggregation
   controller has already filled it. `nonResourceURLs` is carried instead of dropped.
   **This was a silent false negative in the §7 prevalence corpus**, which is rendered
   manifests by construction.
4. `privesc-research.md` rated Services, ValidatingAdmissionPolicies and CSRs as Tier B
   ("not collected yet") when all three were collected. Corrected, and
   `internal/models/collector_coverage_test.go` now fails the build when the Tier B
   list names a type `models.SnapshotResources` already carries.
**Purpose:** replace the sentence *"survived a 2-of-3 plausibility vote"* in
[`privesc-research.md`](privesc-research.md) with evidence a program committee will accept.

That phrase appears in the "How this was produced" header and again as the title of section L.
It is the single most damaging sentence in the document. It says the technique catalog was
validated by language models agreeing with each other. No security venue will accept that, and a
reviewer who reads it will discount every other claim in the paper, including the ones that are
independently correct.

This plan replaces it with a three-tier evidence ladder, a mechanical success oracle, and one
reproducible test case per taxonomy cell. It is written to be executable by a solo author, and it
is explicit about which parts are not fundable and what the honest weaker claim is in those cells.

---

## 0. What is already here, and what is missing

Two harnesses exist and both are good. Neither validates what the paper claims.

| Harness | What it proves | What it cannot prove |
| --- | --- | --- |
| `internal/corpus/` | Precision and recall of **finding IDs** against labeled snapshots. Gates default to 1.0, so any drift fails. `TestScore` pins the math independently of any fixture. | Nothing about paths. `Case.Run` collects only `f.ID` (`corpus.go:200-205`): severity, score, tags, `escalation_path`, hop count, and difficulty are all invisible to the gate. |
| `scripts/kind-e2e.sh` | Six assertion classes against a live kind cluster, including set-equality rulesets and ordered hop-subsequence chain shapes. | That the tool **fires**. Not that the **attack works**. Nothing in the repo ever authenticates as an attacker identity and attempts an escalation. |

The gap in one sentence: **every existing gate asks whether the analyzer agrees with a fixture the
analyzer's author wrote.** That is a regression test, which is what it was built to be. It is not
evidence that a technique is real.

There is one prototype of the missing tier already in the tree. `scripts/eks-demo/poc.sh:130` mints
a ServiceAccount token, binds it to a kubeconfig context, and runs commands as that identity. It is
a human-paced teaching script that deliberately swallows non-zero exits (`poc.sh:102`), so it proves
nothing mechanically, but the identity-assumption pattern is exactly right and should be
generalized rather than reinvented.

**Two CI facts worth fixing before any of this starts**, because they are free provenance:

1. `make e2e` ran **only** in `example-report.yml`, which triggers on `push: [main]` and
   `workflow_dispatch`, with **no `pull_request` trigger**. The entire six-class e2e was a
   post-merge side effect of publishing the docs report, so a PR could break every assertion and
   merge green.
2. `kind-e2e.sh` used `jq` without a `require_cmd jq` preflight.

**Both landed in `ci: gate pull requests on make e2e and preflight jq` (#130), before this plan was
written.** `.github/workflows/e2e.yml` now triggers on `pull_request`, and `kind-e2e.sh:41` requires
`jq`. The provenance argument holds and needs no further work: the artifact's CI history already
shows the existing gates live on pull requests, which pre-empts "how do we know your goldens were
enforced?" at zero cost.

That this section shipped describing both as outstanding is itself a data point for §9's
prose-versus-tree threat: it is the same drift class, inside the document proposing the fix for it.

---

## 1. The evidence ladder

Every claim in the paper carries a label. Labels are enforced by `internal/validation/schema_test.go`,
which runs on every PR without Docker.

### E1: executed and mechanically observed

An unprivileged attacker identity, a ServiceAccount token or client certificate minted for the
fixture's starting subject and **never the harness kubeconfig**, performed the escalation against a
live kube-apiserver, and a per-run random canary marker reachable only at the target sink appeared
in the probe's output.

- **Artifact:** `testdata/validation/<CELL>/{case.json,fixture.yaml,control.patch,probe.sh}`, a
  `results.jsonl` line with `verdict=ESCALATED`, `marker_observed=true`, the `walk[]` array, and the
  canary id, plus the paired control line.
- **Permitted language:** unhedged past tense. "We executed", "the route was walked", "reaching
  `<sink>` in N hops". Always append the configuration scope: "on kind v1.35, single-node profile".

### E2: differential authorization oracle

**This tier was rewritten after review.** As originally drafted, E2 asked the apiserver
`can-i create certificates --as=tenant` about a tuple the author's own fixture explicitly grants,
got `yes`, and recorded it. That is a tautology check on the author's YAML dressed as independent
adjudication. It would catch none of the modeling errors it claimed to catch.

E2 is now a **differential test of `permissions.Aggregate` against the Kubernetes authorizer**:

> For each fixture, enumerate the cross product of (subject × verb × group/resource/subresource ×
> namespace) implied by its rules, then mutate it: wildcards in each position, `resourceNames`-scoped
> rules, aggregated ClusterRoles with `aggregationRule` labels (which `permissions.Aggregate` now
> expands, so this mutation is adjudicable rather than trivially disagreeing), subresources, and
> prefixed verbs. For
> every tuple, POST a SubjectAccessReview to the live apiserver **and** independently ask
> `permissions.Aggregate`. Record every disagreement.

This produces a number no comparator can produce: *"our RBAC evaluator agrees with the Kubernetes
authorizer on N of M adjudicated tuples; the disagreements are X."* It directly answers the
circularity objection at the permission layer, it reuses the cluster and token-minting the harness
already needs, and it costs roughly 0.5 to 1.0 person-week.

- **Artifact:** `case.json` with `evidence_label: E2`, a non-empty `blocked_reason`, and an `sar[]`
  array of the literal adjudicated tuples; a `results.jsonl` line with `verdict=AUTHORIZED`.
- **Permitted language:** "The API server authorizes `<identity>` to `<verb> <resource>`; the
  remaining step (`<named residual>`) was not executed here." Permitted verbs: "is authorized to",
  "is permitted to", "holds the grant". **Never** "can escalate to".

### E3: inherited from a named source

Feasibility rests entirely on an external citable authority: a CVE record with a vendor advisory, an
upstream KEP or design doc, a cloud provider's documented trust model, or a published proof of
concept with a named author and date. Nothing about the crossing was executed here.

- **Artifact:** `case.json` with `citations[]` of `{source, url, accessed, what_it_establishes}`.
- **Permitted language:** "As reported by `<citation>`, ...", "per CVE-XXXX-YYYYY, whose affected
  band includes the observed version". Every E3 sentence carries its citation in the same sentence
  or the one immediately following.

### Three rules that make the ladder load-bearing

1. **Segregated denominators.** Every aggregate number is computed over exactly one label. The
   headline is E1 only. An E1+E2 figure may appear as a clearly secondary number with both
   denominators printed. **E3 never enters a denominator.** The taxonomy count is itself a
   denominator: never write "we studied 30 techniques" without the immediate split.
2. **Non-promotion.** A label can be **downgraded** by the harness (a `DEGRADED` run rewrites the
   cell's effective label downward) but **never upgraded** without an execution record. This is the
   honest version of "labels are assigned by the harness": the harness can demote, the author
   declares, and the declaration is checked against evidence.
3. **Generated tables.** `paper/tables/` is regenerated in CI with a diff check. A committed table
   that differs from the regenerated one fails the build.

---

## 2. The success oracle

### Canary scheme

At cluster bootstrap, `scripts/attack/canary-mint.sh` generates **one 32-hex random marker per sink
per run**, never committed and never reused, and plants them **out of band** using admin credentials
or `docker exec` into the kind node. A probe cannot pass by hard-coding, and a stale cluster cannot
pass with old markers.

| Sink | Canary |
| --- | --- |
| `cluster_admin_equivalent` | Secret `ksp-canary/canary-cluster-admin`. The namespace has no Role, RoleBinding, or namespace-scoped grant of any kind, so the only RBAC shape that reads it is a cluster-scoped wildcard or an explicit cluster-wide `get secrets`. |
| `system_masters` | **Its own distinct Secret**, plus `kubectl auth whoami` reporting `system:masters` in `.status.userInfo.groups`. |
| `kube_system_secrets` | Secret `kube-system/ksp-canary-kubesystem`. |
| `namespace_admin:<NS>` | Two-part: read Secret `<NS>/ksp-canary-ns` **and** create RoleBinding `<NS>/ksp-canary-proof`. Namespace-admin is a write authority; a read-only oracle over-credits it. |
| `node_escape` | Two files via `docker exec`: `/var/lib/ksp-canary/node-fs.marker` (0644, "host filesystem reach") and `node-root.marker` (0600 root:root, "root on the host"). Each cell declares which tier it needs, because a PSA-restricted route yields filesystem reach as a non-root UID and must not be credited with host root. |
| `token_mint` | The minted token reads a Secret granted only to the impersonated SA, and `auth whoami` under it reports that SA. |
| control-plane PKI | `/etc/kubernetes/pki/ksp-canary-cp.marker` (0600 root:root). Probes read **this marker instead of real key material**, proving the same access without any probe handling `ca.key` or `sa.key`. |
| `traffic_intercept` | No shipped sink, but still needs an oracle. The **victim** emits the marker: a victim pod POSTs its marker to the address it believes is trusted, and the attacker's listener logs it. |
| `aws_iam_role` | No kind-reproducible canary exists. E2 or E3 by construction. |

> **Fix applied from review.** The original draft gave `cluster_admin_equivalent` and
> `system_masters` the *same* canary, so any route landing on a `system:masters`-bound identity
> satisfied both and the endpoint metric's `sink_key` half was untested for exactly the two sinks
> most likely to be conflated. One distinct Secret per sink enum. This costs about an hour.

**SUCCESS** is the runner performing a literal string match of the probe's stdout against a value
the probe never had access to before the attack. Not a zero exit. Not "created". Not the absence of
errors.

**Observation channel.** The attack channel is the unprivileged identity. The observation channel is
privileged: the harness reads the attacker pod's logs with admin credentials. This is a deliberate
modeling choice and the paper must state it. We demonstrate **arrival at the sink, not egress of the
data**. Running a C2 listener in CI adds fragility without adding evidence.

### Failed attack versus broken test

Every probe sources `scripts/attack/lib.sh` and obeys a strict exit contract:

| Code | Verdict | Meaning |
| --- | --- | --- |
| 0 | `ESCALATED` | Marker observed. |
| 1 | `DENIED` | A declared denial signature matched **and** all preflight passed. |
| 3 | `BROKEN` | Anything else. |
| 4 | `DEGRADED` | A declared precondition is absent. Rewrites the label downward, does not fail the build. |

`DENIED` is reachable **only** through a whitelist of signatures the probe declares up front:
`reason=Forbidden` or HTTP 403; an admission rejection naming the rejecting policy or webhook; an
RBAC escalation-prevention error; `EACCES`/`EPERM`/`ENOENT` on the specific canary path. Every other
failure is `BROKEN`, including connection refused, i/o timeout, context deadline exceeded,
`ImagePullBackOff`, `CrashLoopBackOff`, YAML parse errors, a missing binary, and an empty log.

> **Fix applied from review.** Two draft signatures were timeouts in costume:
> `pvc-unbound-deadline` ("stays Pending past 60s") and `csr-pending-deadline`. A slow scheduler or a
> briefly unhealthy approver manufactures a false `DENIED`, which is precisely the failure the
> contract exists to prevent. **Every deadline-based signature must now be paired with a positive
> assertion of the blocking state**: for the PVC, `.status.phase == Pending` AND no PV with a
> matching `claimRef` AND no pending provisioning event AND the storage controller pods `Running`.
> Both cells additionally run a mandatory doubled-timeout sensitivity re-run.

**Five preflight gates run before every attack. Any failure exits `BROKEN`, never `DENIED`:**

- **P1 fixture present.** Every object in `case.json:fixture_objects[]` resolves via `kubectl get`.
- **P2 canary intact.** The harness re-reads the canary and confirms it matches `canaries.json`.
- **P3 identity mintable.** Token creation succeeds and `auth whoami` returns the expected username.
- **P4 RBAC propagated.** Retry to 30s against a positive-control authorization check.
- **P5 non-triviality.** The attacker identity **cannot already** read the canary before the attack.
  This is what makes the transition attributable to the technique rather than to the fixture.

---

## 3. Path-level scoring

The corpus scores findings. The paper's contribution is **paths**.

**Normalization.** Ground truth is an executed path `G`, reconstructed from the probe's `walk[]`: an
ordered list of `(from_identity, action, to_identity)` triples terminating in an observed marker.
Prediction is a `models.EscalationPath` from `findings.json`, normalized to
`(source_key, sink_key, action_seq)`.

> **Blocker found in review.** None of `.source`, `.target`, `.target_namespace`, or `.target_id`
> currently reaches `findings.json`. `internal/models/escalation.go` says so in the `TargetID` doc
> comment: only `Hops`/`AlternateHops` are serialized. **A serialized `escalation_target` block must
> be added to `models.Finding` and pinned in the ruleset golden**, about half a day, and noted as a
> public-surface addition per `CLAUDE.md`. The scorer as drafted was specified against fields that do
> not exist, which is itself evidence the plan needed a code-checking pass rather than a plausibility
> vote.

**Deduplication before scoring.** Collapse predicted paths by `(source_key, sink_key)`, keeping all
action sequences as variants of one claim. A tool emitting a primary and an alternate route to the
same endpoint is making **one** claim about reachability; counting the alternate as a second
prediction would penalize exactly the capability this paper argues for.

**Endpoint match (primary).** `P` matches `G` iff `source_key` and `sink_key` both match. This is the
right primary metric because the operational claim is "this identity can reach this sink", and an
operator acts on it regardless of which equivalent route was printed.

**Hop match (secondary, always reported alongside, never instead).** `P` hop-matches iff it
endpoint-matches **and** either action sequence is an ordered subsequence of the other. Two-way
containment is deliberate: one-way containment misclassifies the shorter-path case. Ordered
subsequence, not contiguous, matching the existing `*.chain` semantics.

| | Definition |
| --- | --- |
| **TP** | An executed `G` with at least one endpoint-matching deduplicated prediction. Many-to-one: variants yield one TP and no extra FPs. |
| **FN** | An executed `G` with no endpoint-matching prediction. **The most valuable number in the paper**, because the executed set is authored from external technique catalogs, not from tool output. |
| **FP** | A predicted path whose endpoint pair was **attempted** and returned `DENIED` (not `BROKEN`, not unattempted). A prediction with no probe is `UNADJUDICATED` and is not an FP. |

**Shorter prediction than executed.** If `P` endpoint-matches and its action sequence is a *proper*
subsequence of `G`'s, classify as TP with flag `shorter_prediction` and enqueue a confirmation probe
attempting exactly the tool's shorter route. If it escalates, substitute it into ground truth and
record the edit. Note the honest limit: this measures probe-authoring efficiency, not tool insight,
unless the shorter route uses an edge the author demonstrably did not know about.

### Reporting precision honestly

> **Fix applied from review, and the most important one.** The draft's sample output line showed
> `cov=0.31`. The real coverage is **one to three percent**: roughly 20 to 40 adjudicated endpoint
> pairs from the E1 cells plus 50 stratified adjudications, against thousands of predicted paths over
> the chart corpus. Publishing `precision=0.94` at 2% coverage is worse than publishing no precision
> at all, and a reviewer computes that ratio in thirty seconds.

Three binding rules:

1. Always print coverage as an **absolute pair count** beside the fraction:
   `precision 0.94 (34 of 1,812 predicted endpoint pairs adjudicated)`.
2. **Pre-registered floor:** below 10% coverage, report **no point estimate**. Report a Wilson
   interval and the raw counts only, and state in the methodology that this floor was committed to
   before running.
3. Move disagreement adjudication out of the comparator workstream (the last one, and the first
   casualty of any schedule cut) into the same week as the E1 cells. Contested endpoint pairs are
   the cheapest coverage available and exactly the pairs a reviewer cares about.

---

## 4. The per-cell matrix

Thirty cells across the 7 × 6 grid. Full specifications, with fixture contents, literal attacker
command sequences, success oracles, and negative controls, live in the machine-readable
`testdata/validation/<CELL>/case.json`. Summary:

| Cell | Label | Env | Technique | Detection expectation |
| --- | --- | --- | --- | --- |
| R1-C1 | E1 | kind | `create pods` in a namespace hosting a more privileged SA | **Present:** `KUBE-PRIVESC-001` + path to that SA |
| R1-C2 | E1 | kind | Argo Workflows `spec.serviceAccountName`, no pods verb | **Known FN** |
| R2-C1 | E1 | kind | `create rolebindings` + `bind` on a privileged ClusterRole | **Present.** Its control (binding write, no `bind`) is now correctly silent; see §4 |
| R2-C2 | E1 | kind | Flux Kustomization steers cluster-admin kustomize-controller | **Present:** `KUBE-CONFUSED-DEPUTY-001`, hop-1 `operator_reconcile` |
| R2-C3 | E1 | kind | MutatingAdmissionPolicy covering another tenant | **Covered (capability):** write on `mutatingadmissionpolicies`+`…bindings` now fires `KUBE-PRIVESC-019` + a `mutating_policy_inject` edge to `node_escape`. The finding is on the write capability, not on which tenant a specific policy's matchConstraints target. |
| R2-C4 | E1 | kind | `spec.externalIPs` pointed at a victim ClusterIP | **Known FN**, double-blocked: no `traffic_intercept` sink exists |
| R2-C5 | E1 | kind-multinode | Node-shared tenant token theft from `/var/lib/kubelet` | **Known FN:** `node_escape` has exactly two outbound edges |
| R3-C1 | E1 | kind | Attacker-minted hostPath PV defeats PSA in a Restricted namespace | **Known FN** |
| R3-C2 | E1 | kind | Flux applies a privileged hostPath DaemonSet | **Present:** path to `node_escape` via `operator_reconcile` |
| R3-C3 | E1 | kind | Mutating policy injects a privileged sidecar into every future pod | **Covered:** `KUBE-PRIVESC-019` (write on both `mutatingadmissionpolicies` and `…bindings`) + a `mutating_policy_inject` graph edge to `node_escape` |
| R3-C5 | E1 config / E3 version | kind | Privileged hostPath pod (executed) + kernel CVE band (inherited) | **Present** for the configuration half only |
| R3-C6 | E1 | kind-multinode | Bootstrap token to `system:node:<name>` via auto-approver | **Known FN:** no `TargetNodeIdentity` sink |
| R4-C1 | E1 | kind | Self-approve a CSR, `CN=` an SA, authenticate as it | **Present:** `KUBE-PRIVESC-011` |
| R4-C2 | E2 | kind | cert-manager CA ClusterIssuer in the apiserver's `--client-ca-file` | **Present:** deputy edge; issuance not executed |
| R4-C3 | E1 | kind | Static pod dropped into `/etc/kubernetes/manifests` | **Present:** `pod_host_escape` then `static_pod_admission_bypass` |
| R4-C4 | E1 | kind | APIService aggregation to an attacker Service | **Known FN**, double-blocked: APIServices are not collected |
| R4-C6 | E2 | kind | Append an attacker CA to `extension-apiserver-authentication` | **Known FN** |
| R5-C1 | E2 | kind | Pod-create to an IRSA-annotated SA, then `AssumeRoleWithWebIdentity` | **Present** for the in-cluster prefix; IAM half not executed |
| R5-C2 | E2 | kind | ExternalSecret via a cluster-scoped `ClusterSecretStore` | **Present:** composed deputy path |
| R5-C3 | E1 | kind | Admission policy **adds** `eks.amazonaws.com/role-arn` to an SA | **Known FN**, and uniquely a *taxonomy* blind spot as well |
| R5-C4 | E1 intercept / E3 yield | kind | `externalIPs: [169.254.169.254]` hijacks IMDS cluster-wide | **Present:** `KUBE-CLOUD-IMDS-PIVOT-001` reachability half |
| R5-C6 | E3 | offline | GKE/Azure Workload Identity annotations, structural twin of IRSA | AWS arm present, GCP/Azure arms **known FN** |
| R6-C2 | E1 | kind | Write the OCI artifact a Flux `OCIRepository` already tracks | **Known FN**, structural |
| R6-C6 | E3 | offline | `aws-auth` `system:masters` reachable from an IRSA SA | **Present.** The cell where section O2's correction is confirmed |
| R7-C1 | E1 | kind | `patch deployments` on an operator to inherit its SA token | **Sharpest code-versus-doc result**, asserted as an asymmetry *within one fixture* |
| R7-C2 | E1 | kind | Home-grown controller outside the ten-entry catalog | **Known FN**, collector-shaped: CRDs are not collected |
| R7-C3 | E1 | kind | Flip `failurePolicy` Fail to Ignore to neuter the policy engine | **Known FN**: de-hardening is modeled nowhere |
| R7-C4 | E1 | kind | Validating webhook with off-cluster `clientConfig.url` taps Secret CREATE | **Known FN** |
| R7-C5 | E1 reachability / E3 RCE | kind | Unauthenticated vulnerable in-cluster service, no NetworkPolicy | **Known FN**: no image-version-to-CVE join |
| R7-C6 | E2 | kind | Patch the image-trust verification key | **Known FN** |

**Distribution: 20 E1, 3 split, 5 E2, 2 E3.** Nineteen of the thirty are known false negatives. That
is the headline result and it should be stated as one: *the taxonomy is mostly a map of what this
tool, and by extension this tool class, does not see.*

### Known false negatives must be machine-emitted

> **Fix applied from review, and the one that most changes a reviewer's disposition.** As drafted,
> every `.knownfn` justification was a code-reading claim: "no `runTask` for `apiextensions.k8s.io`",
> "`node_escape` has exactly two outbound edges". The reviewer reproduced most of them by grep in
> under ten minutes, and that is the point. **The 2-of-3 plausibility vote had been replaced by a
> 1-of-1 author-grep vote.**

One runner rule, about 0.2 person-week:

> A `.knownfn` line may exist **only** when `results.jsonl` contains an `ESCALATED` attack record for
> that cell **and** the path scorer found no endpoint-matching prediction for the executed
> `(source, sink)` pair. `schema_test.go` fails the build on any `.knownfn` entry with no backing
> execution record, and the runner **emits new lines automatically** when an executed crossing has no
> prediction.

For cells that cannot execute, the entry is not a `.knownfn` at all. It is a tool-behavior A/B on an
offline snapshot, which is mechanically checkable. This converts every false-negative claim from
"the author read the code" to "the attack ran and the tool was silent".

Add, in the same spirit, a **machine-derived `observed_status`** per cell, computed by running the
analyzer, with `schema_test` failing on disagreement with the hand-written status and
`shipped_rule_ids`. This, not generated tables, is what would have caught the A5b/O2 error, and it is
what will catch the next one.

### The false-positive class now has no pre-registered member

This section previously rested on one hypothesis: that `modify_role_binding` fired on
create/update/patch of rolebindings **with no check** on `bind` or `escalate`, so the tool would
predict routes the apiserver's escalation-prevention check refuses. That was true, and it has been
fixed (see the header). The honest consequence is that **the paper no longer has a false positive it
knows about in advance**, and billing an outcome determinable by reading five lines of source as a
discovery was the weaker half of the claim anyway.

What is left is stronger, because it is not author-selected:

1. **Runner rule (0.2 wk), now the entire FP program:** every control subject is also a prediction
   source, and any predicted path from a control subject is an **automatically adjudicated FP**.
   Thirty control fixtures become a systematic FP oracle whose yield nobody knows in advance. R2-C1's
   control (a binding write with no `bind`) is the first member and is currently silent, which is a
   passing negative control rather than a finding. Report the count honestly even if it is zero: a
   pre-registered oracle that found nothing is a result, an unreported one is not.
2. **Static prevalence (0.3 wk, entirely offline), repointed:** measure across the chart corpus how
   many charts grant a binding write **without** `bind`, i.e. how many identities a tool modeling
   this edge unconditionally would report as reaching cluster-admin in error. This is now a
   measurement of the tool *class* rather than a confession about this tool, it upper-bounds the FP
   volume the conjunction gate removes at N of several hundred, and it is still a genuinely novel
   number. It also needs the aggregation fix above to be correct, since a chart's aggregated
   ClusterRoles otherwise read as empty.

---

## 5. The blind subset

> **Fix applied from review.** The draft declared the blind subset undroppable and funded it with
> zero line items. At the stated per-cell rate, 25 to 35 blind techniques is 7.5 to 10.5 person-weeks,
> which would have taken the total from 24 to 35 and the MVP from 12 to 22. Either the totals were
> wrong by 40% or the single most important anti-circularity control was aspirational.

Cut to **8 to 10 techniques, budgeted explicitly at 3.0 person-weeks**, drawn only from KubeHound's
published edge list, which is already enumerated and already E1-shaped so triage cost is near zero.

**Ritual:** author them in a branch, commit the probe files and `case.json` **before the tool is ever
run against them**, and cite that commit hash in the paper. Report blind recall over n=10 with an
exact binomial interval.

*"Blind recall was 6 of 10 versus 13 of 14 on author-designed cells"* is a publishable,
self-damaging, credibility-buying result. A small honest blind number with an auditable timestamp is
worth more to a committee than a promised 35 that never materializes.

---

## 6. Harness changes

New, all globbed with no registration step, modeled on `corpus.LoadCases`:

```
testdata/validation/<CELL>/{case.json,fixture.yaml,control.patch,probe.sh}
scripts/attack/{lib.sh,canary-mint.sh,run-validation.sh}
scripts/kind-profiles/{single,multinode,operators}.yaml     # node images pinned by digest
internal/validation/{case.go,pathscore.go,pathscore_test.go,schema_test.go}
internal/bench/{convert/,mappings/,runner.go}
.github/workflows/validation.yml                            # WITH a pull_request trigger
```

Reused verbatim where they fit: `.expect`, `.deny`, and `.chain` keep their existing grammars and
parsers for the detection side of each cell. `.knownfn` is a new single-column family with the same
grammar as `.deny` and the same `collect_rules` parser, checked with identical absence logic but
reported as "known gap, still absent (N entries)" plus a non-vacuity guard.

**Controls ship as patches, not files.** `control.patch` applied to `fixture.yaml`, with a
`control_delta[]` whitelist enforced by `schema_test`, replaces the draft's independent
`control.yaml`. The draft conceded "there is no automated check that a control differs in exactly one
dimension; that remains a human review obligation", which for a solo author is a restatement of the
risk rather than a mitigation. A five-line diff is auditable; two independently authored YAML files
are not.

**Corpus extension:** add optional `expected_paths[]` and `expected_tags{}` label dimensions to
`corpus.Case` (`corpus.go:42-76`) and extend `Run`'s projection past `f.ID` (`:200-206`) so severity,
tags, and escalation paths enter the gate.

---

## 7. Prevalence dataset

Precedent for what an accepted paper's N looks like: CCS 2023 measured 51 of 153 CNCF applications;
*Inside Job* measured 634 misconfigurations across 287 applications.

| Source | Achievable N | Claim it supports |
| --- | --- | --- |
| **Artifact Hub Helm charts** (primary) | ~700-850 charts that declare RBAC, from ~1,200-1,500 pulled, after 8-12% render failures and the ~60% that ship any RBAC | "Of N charts that ship RBAC and render with default values, X% grant at least one identity a route to `<sink>` under a default single-tenant install." |
| **OLM / OperatorHub bundles** | Every bundle's ClusterServiceVersion carries `clusterPermissions`; best fit for the deputy cells | Operator-install prevalence, matching the NDSS 2026 "over 14% of Operators" framing |
| **CNCF project default installs** | Small, hand-triaged | Qualitative, named, high-credibility examples |

Effort: 3-5 days to build the harvester, 1-2 days wall-clock to run, 2-3 days of failure triage.

**The mandatory hedge.** Rendered manifests are single-tenant and lack auto-created default
ServiceAccounts, the cluster's own `system:*` bindings, node labels, and admission configuration.
The only supportable phrasing is *"reported as potentially affected by kubesplaining"*, and only
within the tool's own worldview. Unhedged language is reserved for the adjudicated sample.

**Exclusions warning.** The `standard` preset is auto-applied and `exclusions.Apply` drops findings
*before* output, therefore before any measurement. `corpus.Case.Run` already uses
`--exclusions-preset none`. If the paper's numbers are produced that way but operators run the
default, the paper measures a configuration nobody uses. Report both, or state the choice explicitly.

---

## 8. Baseline comparison

Comparators worth a head-to-head, from the prior-art sweep: **KubeHound** (Datadog, 26 published
attack edges), **rbac-police** (Unit 42), **KubiScan**, **Krane**, **IceKube** (WithSecure),
**kube-chainsaw**, **rbac-tool**, **kubectl-who-can**, plus **EPScan**, which appears to be the
closest academic instrument.

Two scoreboards, because a naive one is unfair in both directions:

1. **Composition experiment.** Give every tool the same cluster. Measure which *composed* routes each
   surfaces. This is fair by construction because it does not depend on output vocabulary.
2. **Explanation scoreboard.** For the routes both find, compare what each tells an operator: hop
   attribution, whether the recommended fix actually closes the route, alternate-route awareness.

Publish the per-tool mapping files (`bench/mappings/<tool>.yaml`) that translate each tool's output
vocabulary into the canonical `(subject_key, sink_class)` space, and publish the
**conversion-fidelity report** alongside. Offer maintainers a pre-review. The comparison has a
converter and an endpoint vocabulary the author wrote, and an infrastructure-asymmetry column
belongs in the table.

---

## 9. Threats to validity

Beyond the standard set, these are the ones a reviewer will find if the paper does not name them
first:

1. **Fixture authorship.** Fixtures, controls, `.expect` lists, the 7 × 6 grid, which cells are
   populated, and the sink vocabulary all have one author. **Only the execution verdict is
   independent.** The correct sentence is: *the oracle is independent of the tool; the population is
   not.* The blind subset and the differential oracle are the only two real mitigations.
2. **Endpoint match is nearly unfalsifiable** given `bfsToSinks` (`pathfinder.go:139-145`) keeps only
   the first arrival per sink, so the tool emits at most one route per `(source, sink)` by
   construction. Report exact-sequence-equality alongside the containment metric and promote hop
   attribution to a headline figure. Publishing a low attribution number is a strength.
3. **The scoring model is untested.** Thirty cells and not one touches the difficulty attenuation
   (`easy` 0.15, `moderate` 0.4, `hard` 0.9, one bucket dropped for any `hard` hop) that the repo
   treats as a differentiator. Near-free fix: `results.jsonl` already records `duration_ms`; add
   per-hop wall-clock, precondition count, and `DEGRADED` rate, then correlate against declared
   difficulty. A null result is still publishable.
4. **Environment monoculture.** Everything runs on kind. Either budget one cell across three node
   images or state plainly that the version matrix is not funded.
5. **Hop attribution is knowingly unpinned** in at least one place: `cut-resilient.chain`'s own
   comment concedes the asserted action is `wildcard_permission` rather than `bound_to_cluster_admin`
   purely because of edge insertion order in `BuildGraph`. One cell should pin this deliberately.
6. **externalIPs on kind is assumed, not verified.** R2-C4 and R5-C4 both depend on kube-proxy
   programming `spec.externalIPs`. Proxy mode, kindnet's handling of a foreign ClusterIP, and the
   nftables backend recent releases default to all bear on it, and several distributions deny
   externalIPs outright by admission.
7. **Prose claims about the tree go stale.** Twice, found in one review pass.
   `privesc-research.md` rated three object types as uncollected after the collector had gained all
   three, mis-sequencing the roadmap behind collector work that had already shipped; and §0 of *this
   document* listed two CI gaps that #130 had already closed. Both are the same failure: a claim
   about the tree, written once, never re-checked. The mitigation is mechanical and cheap:
   `internal/models/collector_coverage_test.go` reflects over `models.SnapshotResources` and fails
   the build when the Tier B list names a type already collected. Every other prose-versus-tree claim
   in either document is still unchecked, and the `observed_status` proposal in §4 is the general
   form of this fix.
8. **Taxonomy completeness is asserted by its author.** Crosswalk MITRE ATT&CK for Containers,
   KubeHound's 26 edges, and Peirates' action menu against the grid, and require every external
   technique to land in a cell or force a new one.
9. **The observation channel is privileged.** A probe that never escalated but whose log happens to
   contain the marker would pass. P2 verifies the canary is intact; it does not verify the marker was
   not otherwise reachable.
10. **Ethics.** R7-C5 ships a manifest pinning a known-RCE image by digest plus a reachability prober.
   Gate it behind an opt-in `make` target that refuses without `CONFIRM=1`.

---

## 10. Effort, schedule, and venues

| | Workstream | Weeks |
| --- | --- | --- |
| W1 | Evidence ladder, case schema, `internal/validation`, table tooling | 2.0 |
| W2 | Oracle infrastructure: canary mint, three-state contract, orchestrator, kind profiles | 1.5 |
| W3 | 14 cheap E1 cells, no operator installs | 4.0 |
| **W3b** | **Blind subset, 8-10 techniques from KubeHound's edge list** | **3.0** |
| W4 | Operator tier: Argo Workflows, Flux, local OCI registry, plus three E2 adjudications | 2.5 |
| W5 | Admission and webhook tier, including the TLS tap and pinned-vulnerable ingress-nginx | 2.0 |
| W6 | Offline and detection-only cells, corpus label extension | 1.0 |
| W7 | Dataset: harvesters, N≈1,000 run, 50-case stratified adjudication | 4.0 |
| W8 | Baselines: converters, mappings, both scoreboards, maintainer pre-review | 3.0 |
| W9 | CI wiring, artifact packaging, Zenodo DOIs, `CITATION.cff`, artifact appendix | 1.5 |
| W10 | Writing, generated tables, threats, taxonomy corrections | 2.5 |
| **W11** | **Differential SAR-versus-`permissions.Aggregate` oracle** | **1.0** |
| | **Total** | **≈28** |

**Minimum viable subset: W1, W2, W3, W3b, W6, W9, W10, W11 ≈ 17 person-weeks.** That drops the
operator and admission tiers, the prevalence corpus, and the baselines, and keeps the ladder, the
oracle, the executed cells, the blind subset, and the differential test. It is a smaller paper but
not a weaker one.

**Schedule arithmetic, stated honestly.** Today is 3 August 2026. A solo author with a job sustains
roughly half-time, so 17 person-weeks is about 34 calendar weeks and 28 is about 56.

| Venue | Next deadline | Verdict |
| --- | --- | --- |
| NDSS '27 fall | 19 August 2026 | **Not reachable.** Sixteen days. |
| USENIX Sec '27 Cycle 1 | 25 August 2026 | **Not reachable.** Three weeks. |
| IEEE S&P '27 Cycle 2 | 17 November 2026 | **Not reachable at half-time**, even for the MVP. Reachable only at close to full-time. |
| **USENIX Sec '27 Cycle 2** | ~February 2027 | **The realistic first target** for the MVP. |
| **ACM CCS '27 Cycle A** | ~January 2027 | **Best topical fit**, and the only top-4 venue awarding **Artifacts Evaluated: Reusable**, the badge this repo is closest to earning. |
| ACSAC / RAID | annual, mid-2027 | **Highest acceptance probability per unit of effort.** The fallback, and RAID's CFP explicitly welcomes catalog-plus-tool-plus-measurement. |

**The multi-venue split**, which is the user's actual goal and is achievable without self-plagiarism:

- **The SoK / measurement paper** (taxonomy, detectability tiers, prevalence, baselines) goes to
  CCS or Oakland.
- **The technique catalog with per-technique live-cluster confirmation** goes to **USENIX WOOT**,
  which is the natural home for offensive technique work and has a separate cadence.
- **The tool and artifact** carry both, with a Zenodo concept DOI so citations accrue to one
  identifier across versions.

A useful negative result from the sweep: **no SoK specifically covering container or Kubernetes
privilege escalation was found at a top-4 venue in 2024-2026**, across five differently phrased
searches. That is an open niche, though absence of search evidence is not proof of absence.

---

## 11. Sentences the paper may not write

Enforce this list mechanically where possible and by review where not.

| Tempting | Why it is unsupported |
| --- | --- |
| "We executed all 30 techniques against a live API server." | Twenty are E1, and three of those are E1 only for a prefix or a precondition. |
| "kubesplaining achieves 94% precision on path prediction." | Computed over ~2% adjudication coverage. Unsupported at any coverage below the pre-registered 10% floor. |
| "We validate that our RBAC model agrees with the Kubernetes authorizer." | True **only** once the differential oracle (W11) is built. |
| "Our fixtures were validated independently of the tool." | Only the execution verdict is independent. |
| "We measure kubesplaining's false negatives." | Over techniques the author chose to probe, in a grid whose empty cells the author declared empty. |
| "X% of Helm charts contain a path to cluster-admin." | Only "reported as potentially affected", and only within the tool's worldview. |
| "kubesplaining outperforms KubeHound." | Different input formats, an author-written converter, an author-defined vocabulary. Only the composition experiment and the explanation scoreboard are fair by construction. |
| "The attacker reached cluster-admin." | The canary proves a specific Secret was read. The prose must inherit that hedge every time. |
| "No number in this paper is typed by hand." | Tables are generated from `case.json`, which is typed by hand. Only `observed_status`, the counts, and the `results.jsonl`-derived figures are machine-derived. |
| "kubesplaining found routes the analyst missed." | The `shorter_prediction` tally measures probe-authoring efficiency unless the shorter route uses an edge the author demonstrably did not know. |
| "Our remediation cuts the route in K% of cases." | n≈14 with single-digit cells. Report exact counts, never percentages, below ten. Drop "first" unless surveyed. |

---

## 12. Immediate next actions

0. **Done.** The three soundness fixes and the doc correction listed in the header have landed, with
   unit coverage for each gate, amended e2e fixtures (every RBAC-write fixture now carries the half
   that makes it genuinely exploitable), and the full six-class e2e green with both ruleset goldens
   unchanged at 76 rules.
1. ~~**Free provenance, a few hours.**~~ Already landed in #130; see §0.
2. **Delete the phrase.** Replace "survived a 2-of-3 plausibility vote" everywhere it appears in
   `privesc-research.md` with a forward reference to this plan and an explicit statement that the
   catalog is currently **unvalidated**. An honest placeholder beats a false credential.
3. **Serialize `escalation_target`** into `models.Finding` and pin it in the ruleset golden. The path
   scorer cannot be written until this exists.
4. **Build W11 first, not last.** The differential oracle is the cheapest headline number in the
   plan and the direct answer to the circularity objection.
