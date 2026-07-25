# Deep-chain privilege escalation: design

Date: 2026-07-24
Status: approved, pending implementation
Supersedes nothing. Builds on [`docs/privesc-research.md`](../../privesc-research.md) sections A1-A6 and N.

## Problem

The privesc graph produces almost no chains longer than two hops, and the ones it does
produce are accidental rather than modeled. An audit of the current tree confirmed that
`--max-privesc-depth` is not the constraint: building the graph over
`testdata/snapshots/minimal-risky.json` and `testdata/snapshots/leastprivilege-demo.json`
and running `FindPaths` at depth 5 and depth 10 gives byte-identical output.

Four structural properties bound chain length instead:

1. **Edge topology.** Only 5 of the 26 edge builders emit subject-to-subject edges
   (`pod_create_token_theft`, `pod_exec`, `ephemeral_container_inject`, `token_request`,
   namespace-scoped `impersonate_serviceaccount`). Every other builder lands directly on a
   terminal sink, so path length is `1 + (consecutive SA-hop edges)`. Every intermediate is
   drawn from `serviceAccountsByNamespace` / `podServiceAccountsByNamespace`
   (`graph.go:632-675`), so a chain can never route through a User or Group.
2. **`IsSystem` silently drops hops.** `pathfinder.go:128-130` skips any neighbor with
   `IsSystem`. Because a subject node is not a sink, reaching a kube-system controller SA
   yields no path *and* no onward traversal. This removes exactly the highest-value
   intermediates in a real cluster.
3. **Sinks are terminal.** `pathfinder.go:113-126` records a sink and stops, with external
   cloud-IAM nodes as the sole exception. This is gap A1 (`namespace_admin`, `IsSink` set at
   `graph.go:589`) and gap A2 (`node_escape`, `graph.go:47`) in force.
4. **Shortest-path-only per (source, sink).** The global visited prune
   (`pathfinder.go:105-108`) plus the one-path-per-pair dedupe (`pathfinder.go:43-47`) mean
   that once a subject has any 1-hop edge to a sink, every richer route to that same sink is
   invisible.

A secondary problem: scoring actively penalizes depth. `analyzer.go:179-191` subtracts 0.5
per hop and downgrades one severity bucket at 3+ hops, so unlocking deep chains would
surface them as MEDIUM or LOW regardless of how trivially exploitable each hop is.

Finally, no e2e assertion covers chain *shape*. The harness asserts rule-ID recall
(`*.expect`), rule-ID set equality (`*.ruleset`), and instance-level negatives (`*.deny`).
A regression that flattened every path to a single hop would pass all three.

## Goals

- Make 4-to-6 hop escalation chains expressible and correct, not accidental.
- Keep false positives in check: every new edge family is gated on a precondition that is
  observable in the snapshot.
- Score chains by how hard they are to walk, not by how long they are.
- Validate the graph shape in e2e, not just the rule-ID set.

## Non-goals

- Collector extensions (EndpointSlices, Ingresses, APIServices, CRDs, DRA objects). The
  confused-deputy family is deliberately RBAC-only for this iteration.
- GKE and AKS cloud identity parsing (gap A5(a)).
- The `resourceName`-aware impersonation rework (gap A6).
- The 2026 disclosure backlog (Copy Fail image-layer join, DRA verb prefixes, OCI image
  volumes, `gitRepo` volumes, ConstrainedImpersonation, `hostUsers` attenuation). These are
  recorded in the research doc follow-up section and sequenced after this work.

Correction to the research doc worth recording: gap **A5(b) is inaccurate as written**.
External AWS-IAM nodes already carry outbound return edges to `system_masters` and
`cluster_admin` (`cloud_edges.go:170,182`), and the pathfinder deliberately re-enqueues
external sinks (`pathfinder.go:117-125`). Only GKE/AKS parsing, gap A5(a), is genuinely open.

## Design

### 1. Traversable sinks

`models.EscalationNode` gains `Traversable bool`. `bfsToSinks` replaces its
`if !neighbor.IsExternal { continue }` special case with `if !neighbor.Traversable { continue }`,
and external cloud nodes simply set `Traversable: true`. A node may now be both a sink
(the finding still fires) and an intermediate (BFS keeps walking). This is the enabling
change for sections 3 and 4; on its own it alters no output.

### 2. Split `IsSystem` into `IsSystem` and `IsControlPlane`

`isSystemSubject` (`graph.go:614-622`) currently returns true for two unrelated conditions
and the single resulting flag does two jobs: it blocks BFS *sources* and blocks *intermediate
hops*.

- `IsSystem` narrows to the name-prefix `system:` test. Still blocked in both roles, because
  laundering a chain through the control plane's own built-in identities is a modeling
  artifact rather than an attack.
- `IsControlPlane` is new: a non-`system:` ServiceAccount in `kube-system`, `kube-public`, or
  `kube-node-lease`. **Traversable as an intermediate, still never seeded as a BFS source.**

A control-plane SA is only reachable when some subject genuinely holds an edge into it
(pod-create in that namespace, exec into its pods, impersonate it, mint its token), each of
which is already an independent finding. So this widens chains without inventing reachability.

### 3. `namespace_admin` becomes traversable

Namespace-admin over namespace X implies the ability to steal any ServiceAccount token
living in X: create a pod as that SA, exec into its pods, or read its token Secret.

`ensureNamespaceAdminSink` keeps `IsSink: true` (the `KUBE-PRIVESC-PATH-NAMESPACE-ADMIN`
finding is unchanged) and gains `Traversable: true`. A new builder emits
`colocated_sa_token_theft` edges from `sink:namespace_admin:X` to every ServiceAccount node
whose namespace is X. Combined with section 2, `kube-system` is the high-value instance.

### 4. `node_escape` continues into control-plane PKI

Node root on a control-plane node yields `/etc/kubernetes/pki/ca.key` (offline `system:masters`
client-cert forgery) and `sa.key` (forge a token for any ServiceAccount), plus a writable
`/etc/kubernetes/manifests` that runs static pods bypassing all admission control.

Emitting this unconditionally would be a serious false positive on worker-only clusters, so
it is gated on an observable precondition: the snapshot contains at least one node labeled
`node-role.kubernetes.io/control-plane` whose taints do not include a `NoSchedule` entry for
that role. When the gate passes, `sink:node_escape` is marked `Traversable` and gains:

- `control_plane_pki_theft` to `sink:system_masters`
- `static_pod_admission_bypass` to `sink:token_mint`

The gate is satisfied by a default single-node `kind` cluster, which is what `make e2e`
creates, so e2e exercises the path rather than merely compiling it.

### 5. Confused-deputy edge family

New rule ID `KUBE-CONFUSED-DEPUTY-001`, applied as a **technique overlay**: `findingFromPath`
overrides the path's rule ID when the first hop's action is `operator_reconcile`. This matches
the decision already taken for roadmap item 6b and avoids inventing a new `EscalationTarget`.

Trigger is RBAC-only. A subject holding `create`, `update`, or `patch` on a catalogued
operator custom resource gets an `operator_reconcile` bridge edge to that operator's
controller ServiceAccount. The reconciling controller then supplies its own outbound edges,
which is where the escalation actually lands.

Precision gate: **the edge is emitted only when the controller ServiceAccount exists as a node
in the graph**, meaning the operator is genuinely installed in this cluster. An uninstalled
operator produces nothing, even if a stray Role grants verbs on its CRD.

Initial catalog, keyed by (apiGroup, resource) to (controller namespace, controller SA name):

| API group | Resource | Controller SA |
| --- | --- | --- |
| `kustomize.toolkit.fluxcd.io` | `kustomizations` | `flux-system/kustomize-controller` |
| `helm.toolkit.fluxcd.io` | `helmreleases` | `flux-system/helm-controller` |
| `source.toolkit.fluxcd.io` | `gitrepositories`, `ocirepositories` | `flux-system/source-controller` |
| `argoproj.io` | `applications`, `applicationsets` | `argocd/argocd-application-controller` |
| `argoproj.io` | `workflows` | `argo/argo-workflow-controller` |
| `cert-manager.io` | `certificates` | `cert-manager/cert-manager` |
| `external-secrets.io` | `externalsecrets` | `external-secrets/external-secrets` |
| `velero.io` | `restores` | `velero/velero` |
| `tekton.dev` | `pipelineruns` | `tekton-pipelines/tekton-pipelines-controller` |
| `monitoring.coreos.com` | `servicemonitors` | `monitoring/prometheus-operator` |

The `servicemonitors` entry covers GHSA-cxh2-4639-vmc5 (`bearerTokenFile` service-account
token exfiltration), disclosed after the research doc was written.

Namespace-scoped grants bridge only when the CR is namespaced, which every catalog entry is.
Cluster-scoped grants bridge unconditionally.

### 6. Scoring by weakest hop

`models.EscalationEdge` gains `Difficulty` (`easy`, `moderate`, `hard`). Path scoring in
`targetScoring` replaces raw length attenuation:

- penalty = sum of per-hop difficulty costs (`easy` 0.15, `moderate` 0.4, `hard` 0.9)
- severity downgrades one bucket when the chain **contains at least one `hard` hop**, rather
  than when it exceeds two hops
- score still clamps to `[1, 10]`

Rationale: a five-hop chain of ordinary RBAC grants is more dangerous than a two-hop chain
that needs a race window, and the current model ranks them backwards. Length still influences
the result through the summed penalty, but as a consequence of difficulty rather than as the
primary signal.

Difficulty assignment for existing edges (full table lives with the code):

- `easy`: direct RBAC grants that need nothing else (`wildcard_permission`,
  `bound_to_cluster_admin`, `modify_role_binding`, `bind_or_escalate`, `impersonate*`,
  `read_secrets`, `token_request`, `mint_arbitrary_token`, `secret_mint_token`, `csr_approve`,
  `operator_reconcile`, `colocated_sa_token_theft`)
- `moderate`: needs a workload to exist or be created (`pod_create_token_theft`, `pod_exec`,
  `ephemeral_container_inject`, `pod_create_privileged_escape`, `pod_host_escape`,
  `nodes_proxy`, `irsa_assume_role`, `aws_auth_admin`, `control_plane_pki_theft`,
  `static_pod_admission_bypass`)
- `hard`: needs attacker-controlled infrastructure or timing (`node_drain_migrate`,
  `imds_node_role_pivot`)

### 7. Report copy

Each new action slug needs a `Techniques[slug]` entry in `internal/report/glossary.go` and,
where a rule ID maps to it, a case in `TechniqueKeyForFinding`. Per `CLAUDE.md`, omitting
these silently drops the technique card from the Background block. New slugs:
`colocated_sa_token_theft`, `control_plane_pki_theft`, `static_pod_admission_bypass`,
`operator_reconcile`.

### 8. e2e validation

**New assertion type.** `scripts/kind-e2e.sh` gains a `*.chain` handler asserting chain shape,
which nothing covers today. Format, one assertion per non-comment line:

```
<finding-id-prefix> <min-hop-count> <ordered,comma,separated,technique,actions>
```

The check reads `.tmp/e2e-report-full/findings.json`, locates the finding, and fails if it is
absent, if `hop_count` is below the minimum, or if the ordered hop actions do not contain the
expected sequence as a subsequence.

**New fixture shard** `testdata/e2e/vulnerable/17-privesc-deep-chains.yaml`, following the
existing convention of a fresh `NN-` prefix and a dedicated namespace. It constructs:

- A confused-deputy chain: tenant SA with `create kustomizations.kustomize.toolkit.fluxcd.io`,
  a `flux-system` namespace, a `kustomize-controller` SA bound to a powerful ClusterRole.
  RBAC rules may reference resources whose CRD is not installed, so this needs no Flux
  install.
- A namespace-admin traversal chain: a subject reaching `namespace_admin:X` where X hosts an
  SA that itself reaches a cluster sink.
- A control-plane continuation chain, exercised by the single-node kind control-plane node.

**Gate maintenance.** Sections 2 through 5 all add findings, so both `full-scan.ruleset` and
`minimal-scan.ruleset` goldens must be regenerated per the documented `jq` recipe, and the
`internal/corpus` precision/recall cases re-checked for newly introduced false positives.
That is precisely what those gates exist to catch.

## Testing

- Table-driven unit tests alongside each change: `graph_test.go` for the new edge builders and
  the `IsControlPlane` split, `pathfinder_test.go` for traversable-sink BFS behavior,
  `analyzer_test.go` for the difficulty-based scoring.
- A unit test asserting a synthetic 5-hop chain is found end to end, so deep-chain support is
  covered without depending on Docker.
- `make test`, `make lint`, `./bin/golangci-lint run ./...`, `make corpus`, `make e2e`.

## Risks

- **kube-system traversal floods output.** Mitigated by requiring a real inbound edge, and
  caught by the `.ruleset` set-equality gate plus corpus scoring.
- **Confused-deputy over-fires.** Mitigated by the controller-SA-exists precondition. If it
  still over-fires, the fallback recorded in the roadmap is to collect real CRDs and CRs and
  additionally require the CR spec to be attacker-steerable.
- **Scoring change moves existing severities.** Intended. e2e asserts rule IDs and finding-ID
  prefixes rather than severities, so gates will not spuriously break, but the corpus
  comparison should be reviewed by hand once.
