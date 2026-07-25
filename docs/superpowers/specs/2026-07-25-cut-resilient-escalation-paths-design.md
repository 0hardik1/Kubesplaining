# Cut-resilient escalation paths: design

Date: 2026-07-25
Status: approved, pending implementation
Builds on [`docs/privesc-research.md`](../../privesc-research.md) section O3 and the deep-chain
work in [`2026-07-24-privesc-deep-chains-design.md`](2026-07-24-privesc-deep-chains-design.md).

## Problem

A `KUBE-PRIVESC-PATH-*` finding answers one question: can this subject reach this sink? It does
not answer the question an operator asks next, which is whether the fix we printed alongside it
actually closes the route.

Today the answer is frequently no, for two independent reasons.

**The path search hides every alternate route.** `bfsToSinks` prunes on a per-source `visited`
map (`pathfinder.go:111`): once a node is reached at depth *d*, any later arrival at depth `>= d`
is discarded. One chain per node, ever. So once a subject has any 1-hop edge to a sink, every
other route to that same sink is invisible. This is section O3 of the research doc. The
correction that section needs: the three mechanisms it names are not three independent
contributors. The `visited` prune alone enforces the property. The shorter-chain guard at
`pathfinder.go:120` and the one-path-per-pair `seen` map at `pathfinder.go:45` are both
unreachable in the current shape, as is the hop-count tiebreak in the sort at `pathfinder.go:76`.
All three were written in anticipation of exactly this change.

This is also why the deep-chain work in a472d90 under-delivers. It added namespace-admin
traversal, control-plane continuation, and confused-deputy edges, all of which create *richer
routes* to sinks that subjects can often already reach in one hop. The pathfinder discards them.

**The remediation hint cuts an arbitrary binding.** `ForPrivescPath` (`remediation/rbac.go:357`)
reads `finding.EscalationPath[0]` and calls `findBindingForSubject`, which returns the first
`(Cluster)RoleBinding` whose subject list contains the subject. Its own doc comment
(`rbac.go:424-433`) records the choice not to disambiguate: "the first match is good enough for
the hint." It is not. A subject in three bindings where only the third grants `impersonate` gets
told to edit the first, which closes nothing. This is a latent correctness bug in shipped output,
independent of O3, and the provenance this design adds is what makes it fixable.

## Goals

- Make a privesc path finding state whether the remediation it carries actually closes the route.
- Fix `ForPrivescPath` to cut the binding that enabled the first hop rather than the first
  binding it finds.
- Surface the surviving route when one exists. This addresses O3's shortest-path limit for the
  remediation case, with an objective selection rule rather than a judgment about which chain
  teaches more. Note that a surviving route is not always a *longer* one: see section 3.
- Add no new rule IDs and move neither e2e ruleset golden.

## Non-goals

- The k-visit BFS generalization (find richer routes regardless of remediation). Deferred; see
  "Deferred" below for why this design does not foreclose it.
- Any change to scoring or severity. Discussed and explicitly rejected in section 6.
- Rendering alternates in the interactive attack graph.
- Recursive resilience (an alternate to the alternate, or cutting more than the first hop).
- GKE/AKS cloud identity, the PodSpec Tier-A rules, and the 2026 disclosure backlog. Unchanged
  from the deep-chain spec's non-goals.

## Design

### 1. Edge provenance

`models.EscalationEdge` gains three fields:

```go
// SourceBinding, SourceRole, and BindingNamespace record which (Cluster)RoleBinding
// and (Cluster)Role granted the RBAC rule that justified this edge, so remediation
// can cut the binding that actually enabled the hop and path search can model what
// removing that binding would do. All three are empty for synthetic edges (pod
// escape, token mint, cloud identity, the node-escape continuation) that do not
// trace back to a binding. An empty BindingNamespace on a populated SourceBinding
// implies a ClusterRoleBinding, matching how permissions.Aggregate builds the rule.
SourceBinding    string `json:"source_binding,omitempty"`
SourceRole       string `json:"source_role,omitempty"`
BindingNamespace string `json:"binding_namespace,omitempty"`
```

`permissions.EffectiveRule` already carries `SourceRole`, `SourceBinding`, and `Namespace`
(`aggregate.go:15-27`), and `addEdgesForRule` already receives the rule (`graph.go:169`). So
every RBAC-derived edge has provenance in scope at construction. Implementation is a local
closure at the top of `addEdgesForRule` that stamps the three fields and delegates to `addEdge`,
so each of the roughly twenty literal call sites inside that function changes by one identifier.

Edges built outside `addEdgesForRule` keep empty provenance by construction: the pod-escape
edges (`graph.go:491,515,566`), the node-escape continuation (`graph.go:691,697`), the
namespace-admin token-theft fan-out (`graph.go:428`, which emanates from a sink node rather
than a subject), and the cloud-identity edges in `cloud_edges.go`.

`models.EscalationHop` (`finding.go:297`) gains the same three fields, copied through in
`buildPath` (`pathfinder.go:146`) so they survive into the finding, JSON, and report.

### 2. Cutting the right binding

With provenance on hop 1, `ForPrivescPath` uses `EscalationPath[0].SourceBinding` and
`BindingNamespace` to locate the binding, and falls back to today's `findBindingForSubject`
scan only when provenance is empty (synthetic-rooted chains, which is precisely the case the
existing fallback comment describes).

This is a behavior change to shipped remediation output. It is a fix, but it will move
`RBACDiff` and `Patch.Command` strings for any finding where the first-match binding was not the
granting one, so remediation golden tests need re-baselining and the change belongs in the
commit message.

### 3. The cut-resilient pass

A **cut-set** is every outbound edge from the source node carrying a given
`(SourceBinding, BindingNamespace)` pair. That models what removing the subject from that
binding actually does: it revokes every capability the binding conferred on that subject, and
nothing else. Edges from other nodes are unaffected, because a binding removal only touches the
subject named in it.

Per source subject:

1. Collect the distinct cut-sets implied by the first hops of that source's emitted paths.
   Typically one or two, not one per path.
2. For each cut-set, re-run `bfsToSinks` once with those edges banned.
3. For each emitted path P, look up the run for P's *own* first-hop cut-set, and take that
   run's chain to P's sink as P's alternate.

Step 3 matters because one banned run reports every sink still reachable, not just the sink of
the path that motivated it. A source with a path to `cluster_admin` via binding A and a path to
`node_escape` via binding B gets two runs, and each path reads only its own run. Reading run A's
`node_escape` result would answer a question nobody asked, since cutting A was never the proposed
fix for the `node_escape` path.

Paths whose first hop has no provenance skip the pass entirely, since there is no binding to
model cutting.

`bfsToSinks` changes only by accepting an optional banned-edge predicate. The traversal, the
`visited` prune, the traversable-sink handling, and the `IsSystem` skip are all untouched, so
the primary path for every existing finding is bit-identical to today.

Cost is one extra BFS per distinct first-hop binding per source, which is a small constant
multiple of today's work. It does not have the combinatorial hazard of per-branch visited sets:
with the namespace-admin fan-out (`graph.go:415-436`) and the cluster-scoped pod-create fan-out
(`graph.go:833-843`), out-degree is O(ServiceAccount count), so naive all-simple-paths
enumeration to depth 5 would be O(N^4). `MaxDepth` bounds that exponent but not its base. This
design never enumerates simple paths, so the hazard does not arise.

**Same-length alternates are expected and are the most valuable case.** `addEdge`
(`graph.go:824-831`) appends unconditionally with no dedupe, so two bindings granting the same
capability produce two parallel edges with distinct provenance. Banning binding A's edges leaves
binding B's, and the BFS rediscovers the sink at the same hop count. The resulting finding says
"removing this subject from binding A changes nothing, binding B grants the same thing," which
is a stronger statement than a longer detour. An alternate is therefore *not necessarily
longer*; it is necessarily *not via the cut binding*.

### 4. Finding shape

`models.Finding` gains one field:

```go
// AlternateEscalationPath is a route to the same sink that survives the binding cut
// this finding's RemediationHint recommends. Non-empty means the printed fix is not
// sufficient on its own. Empty (the common case) means either that no such route
// exists or that the chain is synthetic-rooted and no binding cut was modeled.
AlternateEscalationPath []EscalationHop `json:"alternate_escalation_path,omitempty"`
```

A second **finding** is the wrong shape. `dedupeKey` is `(RuleID, SubjectKey, ResourceKey)`
(`correlate.go:161-174`), and privesc paths to non-namespace sinks carry a nil `Resource`. A
second finding for the same (source, sink) would collide and be swallowed at
`correlate.go:150-153` with only a tag merge surviving. Making it survive would require a
synthetic Resource, a new rule ID (churning both ruleset goldens and `docs/findings.md`), or an
exemption in `dedupeKey`. All three are worse than an additive field.

Findings with an alternate also carry the tag `privesc:survives-first-cut`, giving the report,
the exclusions matcher, and CI consumers a handle that does not require parsing the chain.

Because the field is `omitempty` and no rule ID changes, every finding without an alternate
serializes byte-identically to today across JSON, SARIF, and CSV.

### 5. Report

- `renderEscalationPath` (`evidence_render.go:216`) gains a variant parameter so the same
  renderer produces both chains with different framing copy.
- The alternate renders inside a collapsed disclosure beneath the primary chain, in both the
  Findings tab (`education_render.go`) and the Escalation paths tab
  (`privesc_paths_section.go`). Copy leads with the operational point ("this route survives the
  fix above") rather than with chain length.
- `PrivescPathCard` (`types.go`) gains alternate hop fields. Card sorting stays keyed on the
  primary chain, so tab ordering is unchanged.
- The interactive attack graph (`attack_graph.go:456`) ignores alternates this slot.
- `TechniqueKeyForFinding` (`glossary.go:564`) keys off `EscalationPath[0]` and is deliberately
  left reading the primary, so the Background block keeps describing the main route.

### 6. Scoring: no change

Score keeps modeling exploitability through summed hop difficulty (`analyzer.go:154-175`).
Remediation resilience is a different axis: an alternate route makes a finding harder to *fix*,
not easier to *exploit*. Folding it into the score would shift every consumer's `--ci-max-critical`
and `--ci-max-high` gates and force regeneration of the corpus labels, in exchange for conflating
two things the report is better off stating separately. The tag and the report treatment carry
the signal.

Revisit once there is real output to look at. If the alternate turns out to fire on a large
fraction of paths, a scoring axis becomes more defensible than it is today.

### 7. Housekeeping in the files being touched

- Delete the three dead guards this design supersedes or activates, rather than leaving them
  ambiguous: the `seen` map at `pathfinder.go:45`, the shorter-chain guard at
  `pathfinder.go:120`, and the hop-count tiebreak at `pathfinder.go:76`. Whichever remain
  unreachable after the change should go, with the sort tiebreak kept only if alternates make
  it live.
- `scripts/kind-e2e.sh:361,375` selects a finding with `| first`. As the finding set grows this
  can silently retarget a different finding and keep passing. Replace with an explicit
  `.id ==` match. In scope because this design edits those same assertions.

## Testing

**Unit.** `pathfinder_test.go:11-37` currently asserts `len(paths) != 2` and will need updating.
New cases: a graph where the source reaches a sink via two distinct bindings (expect a
same-length alternate); one where the only alternate is longer (expect the longer chain); one
where no alternate exists (expect an empty field); one with a synthetic-rooted first hop (expect
the pass to be skipped, not to crash). Provenance stamping gets a test in the graph builder
asserting that RBAC edges carry a binding and synthetic edges do not.

`remediation/rbac` needs a test that a subject in multiple bindings gets the *granting* binding
cut, which is the regression test for the bug in section 2.

**E2E.** No fixture in the tree has the required shape: both `testdata/snapshots/minimal-risky.json`
and the e2e cluster produce only routes where the shortest is the only one. A new
`testdata/e2e/vulnerable/` shard is a prerequisite, not a follow-up. It needs a subject bound
into a sink two ways (the parallel-binding case is the cheapest to express and the most
instructive to read). Per the repo's fixture constraint, its pods must actually reach Running on
kind, so idle sleep containers as in the existing shards.

The `.chain` assertion format gains an optional column selecting primary or alternate, so the
alternate's shape is pinned and not merely its existence.

**Invariants to assert explicitly.** Neither `full-scan.ruleset` nor `minimal-scan.ruleset`
should move, since no rule ID is added or removed. If either moves, something fired that should
not have. The corpus (`make corpus`) keys on instance-level finding IDs, which this design does
not change, so it should be inert.

## Risks

- **The alternate over-reports if the cut-set is wrong.** Banning only edges attributable to the
  named binding is the correct model for a subject-removal edit. It would be wrong for a
  different remediation (deleting the Role, editing its rules), so the report copy must say which
  fix the alternate is relative to rather than implying the path is unfixable.
- **Behavior change in remediation output.** Section 2 moves `RBACDiff` strings for findings
  whose first-match binding was not the granting one. Correct, but visible, and golden tests
  need re-baselining.
- **Cost.** One extra BFS per distinct first-hop binding per source. Bounded and small, but it
  is on the scan hot path and worth confirming against the largest available snapshot rather
  than assuming.

## Deferred

The k-visit BFS (approach A during design) remains open and this work does not foreclose it. If
it lands later, `AlternateEscalationPath` is the field it would populate, with a different
selection rule choosing what goes in it. The research doc's O3 entry should be updated to record
that the shortest-path limit is now partially addressed for the remediation case, and that the
general "richer route regardless of remediation" case is what remains.
