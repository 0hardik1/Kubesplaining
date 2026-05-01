# Exclusions YAML Schema

Exclusions mute findings before they surface in reports. The CLI builds the active exclusion config from two sources: a built-in **preset** chosen with `--exclusions-preset` (default `standard`), and an optional **user file** passed with `--exclusions-file`. The user file is *merged on top* of the preset — your rules layer onto the defaults, they do not replace them.

This doc is the schema reference. For the operator-level overview (when to use which preset, how to audit defaults), see the [README's Exclusions section](../README.md#exclusions).

## Top-level shape

```yaml
global:           # cross-module rules — apply to every analyzer's findings
  ...
rbac:             # only checked against findings tagged module:rbac
  ...
pod_security:     # only checked against findings tagged module:pod_security
  ...
network_policy:   # only checked against findings tagged module:network_policy
  ...
```

All four sections are optional, and within each section every field is optional. Set only what you need; missing fields silently match nothing.

Module-scoped sections (`rbac`, `pod_security`, `network_policy`) only run against findings emitted by their own analyzer, identified by a `module:<name>` tag on the finding. Putting a `pod_security:` rule will not accidentally suppress an RBAC finding, and vice versa.

## Pattern matching

String fields described as "glob" use Go's [`path.Match`](https://pkg.go.dev/path#Match) semantics:

| Pattern | Meaning |
| --- | --- |
| `*` | Matches any run of characters except `/`. |
| `?` | Matches exactly one character. |
| `[abc]` / `[a-z]` | Matches one character from the set / range. |

Patterns also fall back to exact-string equality, so a literal value like `cluster-admin` matches only `cluster-admin`. Empty patterns never match anything.

A few worked examples:

- `kube-*` matches `kube-system`, `kube-public`, `kube-node-lease`.
- `system:*` matches `system:masters`, `system:authenticated`.
- `prod-?` matches `prod-1` but not `prod-12`.

Fields described as "exact" (notably `kind` on subject/workload exclusions and `check` on check exclusions) compare with `==`.

## `global` — cross-module exclusions

| Key | Type | Matches |
| --- | --- | --- |
| `exclude_namespaces` | `[]string` (glob) | The finding's namespace, or the namespace of its Subject or Resource. |
| `exclude_service_accounts` | `[]string` (glob) | When the Subject is a `ServiceAccount`: the bare name, `ns:name`, or `ns/name`. |
| `exclude_cluster_roles` | `[]string` (glob) | When the Resource is an `RBACRule`: the role name. |
| `exclude_finding_ids` | `[]string` (glob) | Both the shared `RuleID` (e.g. `KUBE-PRIVESC-001`) and the per-instance `ID` (`RULE:ns:name`). |
| `exclude_subjects` | `[]SubjectExclusion` | Any finding whose Subject matches every set field on the entry. |

`SubjectExclusion` has these fields:

| Key | Type | Notes |
| --- | --- | --- |
| `kind` | `string` (exact) | `User`, `Group`, or `ServiceAccount`. Empty = match any kind. |
| `name` | `string` (glob) | Empty = match any name. |
| `namespace` | `string` (glob) | Empty = match any namespace. |
| `reason` | `string` | Surfaced as the exclusion reason in logs/audit output. |

## `rbac` — RBAC-module exclusions

Only checked against findings tagged `module:rbac` (everything emitted by the RBAC analyzer).

| Key | Type | Matches |
| --- | --- | --- |
| `exclude_subjects` | `[]SubjectExclusion` | Same shape as `global.exclude_subjects`. |

The module-scoped form is useful when you want to silence an SA in RBAC findings only, while still seeing it flagged by, say, the privesc graph.

## `pod_security` — Pod Security module exclusions

Only checked against findings tagged `module:pod_security`.

| Key | Type | Matches |
| --- | --- | --- |
| `exclude_workloads` | `[]WorkloadExclusion` | A specific workload by Kind + name + namespace. |
| `exclude_checks` | `[]CheckExclusion` | A specific control (e.g. `hostNetwork`, or a `KUBE-PODSEC-*` rule ID), optionally scoped to a namespace. |

`WorkloadExclusion`:

| Key | Type | Notes |
| --- | --- | --- |
| `kind` | `string` (exact) | `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `Job`, `CronJob`. Empty = any kind. |
| `name` | `string` (glob) | Empty = match any name. |
| `name_pattern` | `string` (glob) | Equivalent to `name` (both go through the glob matcher). Either field works; `name_pattern` reads more naturally when you're using wildcards. |
| `namespace` | `string` (glob) | Empty = match any namespace. |
| `reason` | `string` | Surfaced as the exclusion reason. |

`CheckExclusion`:

| Key | Type | Notes |
| --- | --- | --- |
| `check` | `string` (exact) | Either the full `RuleID` (e.g. `KUBE-PODSEC-APE-001`) or the value following `check:` in the finding's tag list (e.g. `hostNetwork` matches the `check:hostNetwork` tag). |
| `namespace` | `string` (glob) | Limits the exclusion to findings in the matching namespace. Empty = any namespace. |
| `reason` | `string` | Surfaced as the exclusion reason. |

## `network_policy` — Network module exclusions

Only checked against findings tagged `module:network_policy`.

| Key | Type | Matches |
| --- | --- | --- |
| `exclude_namespaces` | `[]string` (glob) | The finding's namespace, or the namespace of its Subject or Resource. |

## Order of evaluation

A finding is checked against sections in this order: `global` → `rbac` → `pod_security` → `network_policy`. The first matching entry wins, the finding is dropped from the output, and the matching reason is recorded — either the entry's `reason` field, or a generic label such as `matched global.exclude_namespaces` when no reason is set.

## Presets and merging

`--exclusions-preset` selects the built-in baseline:

| Preset | What it suppresses |
| --- | --- |
| `standard` (default) | Namespaces `kube-system` / `kube-public` / `kube-node-lease` / `gatekeeper-system`; service accounts `system:*` and `kube-system:*`; cluster roles and subjects matching `system:*` / `kubeadm:*`; a `hostNetwork` check exclusion in `kube-system`. |
| `minimal` | Just `kube-public` / `kube-node-lease` namespaces, `system:*` service accounts, `system:*` cluster roles. |
| `none` (alias `strict`) | Empty config — every finding surfaces, including control-plane noise. |

When `--exclusions-file` is also passed, the user file is merged on top: string slices are concatenated and deduped (preserving preset entries), struct slices are concatenated as-is. The merged config is what the analyzer sees — there is no per-rule precedence between preset and user file beyond ordering.

To start a user file from a preset, use `create-exclusions-file`:

```bash
kubesplaining create-exclusions-file --preset standard --output-file exclusions.yml

# Pre-populate any kube-* / *-system namespaces discovered in a snapshot:
kubesplaining create-exclusions-file --preset standard \
  --from-snapshot snapshot.json --output-file exclusions.yml
```

## Complete example

```yaml
global:
  exclude_namespaces:
    - kube-system
    - kube-public
    - prometheus
  exclude_service_accounts:
    - system:*
    - argocd:argocd-application-controller
  exclude_cluster_roles:
    - system:*
    - kubeadm:*
  exclude_finding_ids:
    - KUBE-PRIVESC-005    # secret reads accepted in this cluster, see ticket-1234
  exclude_subjects:
    - kind: Group
      name: system:*
      reason: Built-in Kubernetes group

rbac:
  exclude_subjects:
    - kind: ServiceAccount
      name: cert-manager
      namespace: cert-manager
      reason: Vendor SA, reviewed Q1 2026

pod_security:
  exclude_workloads:
    - kind: DaemonSet
      name_pattern: node-exporter-*
      namespace: monitoring
      reason: Prometheus node exporter, hostPath required
  exclude_checks:
    - check: hostNetwork
      namespace: kube-system
      reason: System networking components require host networking

network_policy:
  exclude_namespaces:
    - kube-system
    - kube-public
    - kube-node-lease
```

## Where to look in the code

- [`internal/exclusions/config.go`](../internal/exclusions/config.go) — struct definitions and the built-in presets.
- [`internal/exclusions/matcher.go`](../internal/exclusions/matcher.go) — match rules, glob semantics, evaluation order.
- [`internal/cli/exclusions_helper.go`](../internal/cli/exclusions_helper.go) — how `--exclusions-preset` and `--exclusions-file` are combined.
