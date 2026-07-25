# Privilege-Escalation Methodology Gap Research

Research reference cataloguing Kubernetes privilege-escalation methodologies that
**kubesplaining does not model today** — new RBAC/API primitives, confused-deputy
paths through privileged controllers, admission-layer abuse, MITM vectors, node/PKI
escapes, storage escapes, multi-cloud identity, and long multi-hop chains the
current BFS cannot surface. It also proposes how each maps onto the existing
`privesc` graph (`internal/analyzer/privesc/`): the new sinks, edge types, and rule
IDs that would let the tool detect them.

This is a **planning/roadmap document**, not shipped detection. Nothing here is
emitted by the analyzer yet. See [`findings.md`](findings.md) for what *is*
implemented and [`PLAN.md`](../PLAN.md) for status.

> **Scope & intent.** kubesplaining is a defensive posture assessor. Everything
> below is framed as *"what an offline snapshot could flag so an operator fixes it
> first"* — detection signals and remediation, not exploitation tooling. Each entry
> names the RBAC triple or spec field a rule would key on.

## How this was produced

A multi-agent research sweep (12 technique families → per-technique adversarial
verification → long-chain design → novel-vector plausibility voting → completeness
critic) surfaced 84 candidate techniques; 57 verified as genuine gaps and 21 as
partial-coverage, plus 20 long chains and 15 novel vectors that survived a 2-of-3
plausibility vote. This document is the deduplicated, code-cross-referenced
synthesis. Every mechanism was checked against `graph.go` / `cloud_edges.go` /
`snapshot.go` to confirm it is actually unmodeled, and against Kubernetes docs /
CVEs for technical correctness.

## How to read this — detectability tiers

A "detectable" gap must be inferable from a `models.Snapshot` **offline** (RBAC via
`permissions.Aggregate` + collected object specs; no live API). Each entry is tagged:

| Tier | Meaning | Implementable today? |
| --- | --- | --- |
| **A** | Fires on data the collector **already** captures (RBAC grants, Pod/controller specs, Nodes, existing webhook configs, SecretMetadata, ConfigMap keys). | Yes — rule + graph edge only. |
| **B** | Needs a **new object type** added to the snapshot (Services, Endpoints/EndpointSlices, Ingresses, APIServices, CSIDrivers, VAP/bindings, PriorityClasses, operator CRs, CSRs). Node runtime/kernel version strings are *already present* but unparsed. | Yes — collector extension + rule. |
| **C** | Precondition lives **outside the cluster** (cloud IAM policies, apiserver `--client-ca-file` trust, feature-gate state). Detection is **origin-only**: name the pivot, flag intent, cannot confirm the completed edge. | Partial — same fidelity as the shipped EKS IRSA edge. |

## Baseline recap — what is already modeled

So gaps are unambiguous. The `privesc` graph has **7 sinks** — `cluster_admin`,
`system_masters`, `node_escape`, `kube_system_secrets`, `token_mint`, per-namespace
`namespace_admin`, external `aws_iam_role` — and edges from `KUBE-PRIVESC-001…017`
(pod-create/exec/ephemeral/portforward, secrets read/mint, impersonate, bind/escalate,
rolebinding-write, CSR+approval, nodes/proxy, token-request, node-drain, wildcard),
the pod-escape edges (privileged/hostPID/hostNet/hostIPC/sensitive-hostPath/dangerous-caps/
procMount/APE/PV-hostPath), and the EKS cloud edges (IRSA, aws-auth, IMDS-pivot). System
subjects are skipped as intermediate hops. **Everything below is outside that set.**

---

## A. Structural gaps in the graph model (highest leverage)

These are not individual rules — they are shape limits in `BuildGraph` / `FindPaths`
that make whole *classes* of chain invisible. Fixing them unlocks many Section K chains
at once.

### A1. `namespace_admin` is a dead-end sink, never chained onward
`ensureNamespaceAdminSink` sets `IsSink: true`, and `FindPaths` halts on any sink. So a
subject that reaches `namespace_admin:X` is never expanded further — even though namespace
admin over `X` implies **stealing any ServiceAccount token living in `X`** (create a pod as
that SA, exec into its pods, or read its token Secret). If `X` hosts a controller/operator SA
that is `ClusterRoleBinding`-bound to a powerful role (or `X` is `kube-system`), that two-hop
correlation reaches `cluster_admin`/`system_masters` and is currently silent.
**Fix:** make `namespace_admin:X` a *traversable intermediate* with `colocated_sa_token_theft`
edges to every SA whose namespace is `X`; let BFS continue from those SA nodes. (`kube-system`
is the extreme case: bootstrap-token Secrets + every control-plane SA.)

### A2. `node_escape` is terminal — no "and then" from node root
`addPodEscapeEdges` / `KUBE-PRIVESC-002/012/016` all terminate at `node_escape`, which has no
outbound edges. But node root on a **control-plane** node yields `/etc/kubernetes/pki/ca.key`
and `sa.key` (→ offline `system:masters` cert forgery and arbitrary SA-token forgery), and
writable `/etc/kubernetes/manifests` runs static/mirror pods bypassing *all* admission.
**Fix:** make `node_escape` a conditional intermediate with onward edges to `system_masters`
(control-plane PKI theft) and `token_mint` (SA signing-key theft), gated on a control-plane-node
heuristic (`node-role.kubernetes.io/control-plane` label/taint).

### A3. No confused-deputy edge type (CRD-write → privileged reconciler SA)
`addEdgesForRule` only maps built-in RBAC verbs. A grant of `create`/`patch` on an operator
CRD (`kustomizations.kustomize.toolkit.fluxcd.io`, `applications.argoproj.io`,
`workflows.argoproj.io`, `certificates.cert-manager.io`, `externalsecrets.external-secrets.io`,
`restores.velero.io`, Kyverno policies, Crossplane compositions, …) maps to **no sink**, even
though the reconciling controller SA is frequently `cluster-admin`. This is the single largest
missing edge *family* (Section C). **Fix:** a catalog-driven `operator_reconcile` bridge edge
`subject → controllerSA(K)`, gated on `permissions.Aggregate(controllerSA)` already reaching a
sink and on the CR spec being attacker-steerable.

### A4. No traffic-intercept / MITM sink
The graph has no sink for man-in-the-middle. Multiple *unpatched-by-design* primitives —
Service `externalIPs` (CVE-2020-8554), Endpoints/EndpointSlice repoint, CoreDNS Corefile
rewrite, malicious aggregated `APIService`, admission-webhook payload exfil — all yield
credential/token capture but have nowhere to terminate. **Fix:** add
`TargetTrafficIntercept` (lateral-movement lane) with soft onward edges to
`kube_system_secrets` / `token_mint` when a token-bearing flow is the intercept target.

### A5. Cloud edges are EKS-only and IAM nodes are terminal
`models.CloudIdentity` only defines AWS kinds; `cloud_edges.go` documents GKE/AKS as
"reserved". And the external `aws-iam` node has **no outbound edges** — so no chain crosses
back *into* the cluster (IAM → `eks:AssociateAccessPolicy` / GKE `roles/container.admin` /
AKS `listClusterAdminCredential` → cluster-admin). **Fix:** `TargetGCPServiceAccount` /
`TargetAzureManagedIdentity` sinks mirroring IRSA; and a **cloud-return edge table** so a
cloud-admin IAM node re-enters the cluster graph (Section J, chains C17–C20).

### A6. Impersonation ignores `resourceName` and non-core subresources
`KUBE-PRIVESC-008` maps `impersonate groups → system_masters` and `impersonate users →
cluster_admin` *generically*. It therefore both (a) mis-sinks `impersonate system:nodes` as
`system_masters` (a node identity is **not** cluster-admin — it's the Node authorizer's
per-node scope), and (b) never matches `impersonate` on `authentication.k8s.io/uids` or
`userextras/*` (authz-attribute spoofing). **Fix:** `resourceName`-aware impersonation with a
distinct `TargetNodeIdentity` sink and a conditional `authz_attribute_spoof` edge.

---

## B. New RBAC / API privesc primitives

Direct subject→sink edges keyed on an RBAC triple the graph does not match today. Unless noted,
these are **Tier A** (fire on current snapshot data).

| Proposed rule | Sev | RBAC signal (verb · resource · apiGroup) | Terminal gain / sink | Tier |
| --- | --- | --- | --- | --- |
| KUBE-PRIVESC-018 | CRITICAL | create/update/patch · `mutatingwebhookconfigurations` / `validatingwebhookconfigurations` · admissionregistration.k8s.io | Mutating → `cluster_admin` (+`node_escape` via injected privileged sidecar); Validating → `kube_system_secrets` (AdmissionReview exfil). *See §D1.* | A |
| KUBE-PRIVESC-019 | CRITICAL | create/update/patch · `mutatingadmissionpolicies`+`…bindings` (and VAP de-hardening) · admissionregistration.k8s.io | Webhookless CEL/JSONPatch injection → `node_escape`/`cluster_admin`. *§D2.* | A |
| KUBE-PRIVESC-020 | CRITICAL | create/update/patch · `apiservices` · apiregistration.k8s.io | Register aggregated API server → control-plane MITM/credential-forward (CVE-2022-3172) → `traffic_intercept`/`cluster_admin`. | A (edge) / B (flag existing) |
| KUBE-PRIVESC-021 | HIGH | create/update/patch · `endpoints` (core) / `endpointslices` (discovery.k8s.io) | Repoint a Service backend (esp. a webhook/aggregated-API backing Service) → `traffic_intercept`. CVE-2021-25737/25740. | A (grant) / B (target scoping) |
| KUBE-PRIVESC-022 | HIGH | create/update · `services` (core); update/patch · `services/status` | Set `spec.externalIPs` / `status.loadBalancer.ingress` → kube-proxy MITM of arbitrary IPs incl. IMDS/apiserver (CVE-2020-8554, unpatched-by-design) → `traffic_intercept`. | A (grant) / B (suppress if externalip-webhook present) |
| KUBE-PRIVESC-023 | MEDIUM | update/patch · `leases` · coordination.k8s.io (esp. `resourceNames` kube-controller-manager/-scheduler) | Overwrite `holderIdentity` → controller reconciliation DoS; conditional leader takeover only if attacker runs a matching replica. Weak `controller_hijack` sink. | A |
| KUBE-PRIVESC-024 | CRITICAL | `sign` / `approve` · `signers` · certificates.k8s.io (`resourceName kubernetes.io/kube-apiserver-client`) | Sign an arbitrary client cert `O=system:masters` directly, bypassing the approval controller — distinct from `-011`'s create+`/approval`. → `system_masters`. | A |
| KUBE-PRIVESC-025 | HIGH* | impersonate · `uids` / `userextras/*` · authentication.k8s.io | Forge `Impersonate-Uid`/`-Extra-*` → spoof authorizing attributes. *Conditional:* only escalates when a webhook/ABAC/authenticating-proxy authorizer keys on extras/uid (worthless on stock RBAC-only). → conditional `cluster_admin`. | A (grant) / C (impact) |
| KUBE-PRIVESC-026 | HIGH | create · `secrets` type `bootstrap.kubernetes.io/token` in kube-system (+ standing `system:node-bootstrapper` / nodeclient auto-approver bindings) | Mint a bootstrap token → `system:bootstrappers` → auto-approved nodeclient CSR → `system:node:<name>` identity. New `TargetNodeIdentity` sink (node-scoped, not cluster-admin). | A (all three signals in snapshot) |
| KUBE-PRIVESC-027 | CRITICAL | create · `persistentvolumes` (core, cluster) + create · `persistentvolumeclaims` + create · `pods`/controllers | Attacker-minted hostPath PV; PSA **cannot** follow PVC→PV → privileged host mount even in a Restricted namespace → `node_escape`. Distinct from `KUBE-PV-HOSTPATH-001` (which flags *existing* PVs). | A |
| KUBE-PRIVESC-028 | HIGH | create · `storageclasses` · storage.k8s.io | Steer a hostPath-capable dynamic provisioner (`pathPattern` traversal, local-path-provisioner CVE-2025-62878) → `node_escape`. PVC-time StorageClass ref is **not** permission-checked. | A (grant) / B (provisioner image + version) |
| KUBE-PRIVESC-029 | HIGH | get · `nodes/log` / `nodes/configz` / `nodes/stats` / `nodes/spec` (core) | Fine-grained kubelet subresources (GA 1.36), separate from `nodes/proxy`. `nodes/log` historically path-traverses to node files (tokens, `*.conf`, PKI). → `node_escape`/node cred disclosure. | A |
| KUBE-PRIVESC-030 | HIGH | create · `pods/binding` (core) + create · `pods` | Act as scheduler: write `spec.nodeName` directly, bypassing taints/affinity/gates → co-reside on a control-plane node → hostPath PKI → `system_masters`. | A (grant) / C (hostPath+control-plane join) |
| KUBE-PRIVESC-031 | HIGH | create · `pods`/controllers (any namespace with a valued Secret) | Mount **any** Secret in the namespace as `volumes[].secret` / `envFrom.secretRef` and read it at runtime — no `get/list secrets` verb needed. Canonical, unmodeled. → named `kube_system_secrets`/`token_mint`. | A |
| KUBE-PRIVESC-032 | CRITICAL | update/patch · existing privileged kube-system DaemonSet (kube-proxy, CNI, csi-node) | Higher blast-radius special case of `-003`: edit an *already* hostPath/hostNetwork DaemonSet image/command → attacker code on **every** node at once → cluster-wide `node_escape`. | A |
| KUBE-PRIVESC-033 | MEDIUM | create/update · `priorityclasses` (scheduling.k8s.io); create · `pods/eviction`; patch · `nodes` labels/taints | Scheduling-layer steering: `globalDefault` flip / preemption storm; evict a webhook backend to open a fail-open window; relabel a node to attract a privileged DaemonSet onto attacker hardware. Lateral → `token_mint`/`kube_system_secrets`. *Novel N12–N14.* | A (grant) / B (PriorityClass/PDB collection) |

\*Severity conditional on authorizer configuration.

---

## C. Confused-deputy via privileged controllers & operators

The most impactful missing *family* (structural gap A3). A subject with only
`create`/`patch` on an operator's CRD escalates **through** that operator's
high-privilege ServiceAccount. All are **Tier B** on the "which controller watches
which CRD" mapping (a shipped catalog constant), but the two halves are individually
snapshot-visible: the CRD-write grant (`permissions.Aggregate`) and the controller SA
reaching a sink (already computed for `KUBE-RBAC-OVERBROAD-001`).

Proposed prefix: **`KUBE-CONFUSED-DEPUTY-*`**, plus a generic meta-edge
`KUBE-CONFUSED-DEPUTY-001`.

| Operator | Attacker CRD-write grant | Deputy SA power abused | Gain | Notes / CVE |
| --- | --- | --- | --- | --- |
| **Flux** | create/patch `kustomizations` / `helmreleases` (kustomize/helm.toolkit.fluxcd.io) | kustomize/helm-controller (cluster-admin by default) applies attacker-authored manifests incl. a `ClusterRoleBinding` | `cluster_admin` | Works on patched Flux; `--default-service-account` is the only mitigation. GHSA-35rf-v2jv-gfg7. |
| **Argo CD** | create/patch `applications` / `appprojects` (argoproj.io), or app-in-any-namespace via `sourceNamespaces` | argocd-application-controller (cluster-admin) syncs privileged manifests | `cluster_admin` | Not CVE-dependent; CVE-2023-22736 is the enforcement-bypass widener. |
| **Argo Workflows / Tekton** | create `workflows`/`cronworkflows` (argoproj.io) / `pipelineruns`/`taskruns` (tekton.dev) | Controller builds executor pod as **attacker-named `spec.serviceAccountName`** — no `pods` verb needed | namespace-admin (any SA in ns) | Distinct from `KUBE-PRIVESC-001`: subject never holds `create pods`. Model as edge → every SA node in ns. |
| **cert-manager** | create `certificates` / `certificaterequests` (cert-manager.io) referencing a CA `ClusterIssuer` | certificate-controller holds the CA key; auto-approves in-tree issuer requests | `system_masters` (if CA is apiserver `--client-ca-file`) | Needs no CSR `/approval` half (contrast `-011`). Tier C on the apiserver-trust condition. |
| **external-secrets** | create `externalsecrets` / `clusterexternalsecrets` (external-secrets.io) → `ClusterSecretStore` | ESO controller's cloud creds fetch backend secrets into the attacker's namespace; `rbac.serviceAccountTokenCreate` mints SA tokens | cloud secret exfil; `token_mint` | ClusterSecretStore is the lever (referenceable cross-namespace). |
| **Kyverno** | create namespaced `policies` / `policyexceptions` (kyverno.io) with `apiCall`/`generate` | Policy `apiCall` runs as the Kyverno controller SA, unscoped | `cluster_admin` | GHSA-8p9x-46gm-qfx2; CVE-2024-48921 (PolicyException in any ns). |
| **Velero** | create `restores` (velero.io) / edit `backups` | velero server SA (cluster-admin) recreates arbitrary RBAC/workloads | `cluster_admin` | Requires influence over backup content. |
| **Crossplane / Cluster-API** | create/patch `Composition`/`Object`/managed-resource / `Machine` CRs | provider-controller holds cloud creds; reconciles into IAM roles, RoleBindings, infra | `cluster_admin` / cloud IAM | *Critic add.* Cloud-grade blast radius. |
| **OLM** | create `Subscription` / `OperatorGroup` | Installs an operator with attacker-chosen RBAC via the CSV | `cluster_admin` | *Critic add.* |
| **KubeVirt** | create `virtualmachines` / `virtualmachineinstances` (kubevirt.io) | virt-controller materializes a privileged virt-launcher pod, bypassing the requester's PSS | `node_escape` | *Novel N8.* Deputy-created pod escapes requester PodSecurity. |
| **Karpenter / autoscaler** | create/patch `ec2nodeclasses`/`nodepools`/`nodeclaims` | Provisions a node with attacker `userData` / AMI / instanceProfile | attacker node → SA-token harvest + cloud IAM | *Novel N9.* |
| **GitOps generic** (`KUBE-CONFUSED-DEPUTY-001`) | create/patch a catalogued CRD whose spec is attacker-steerable | any controller SA that already reaches a sink | that SA's sink | Meta-edge; tag each catalog entry with whether the CR spec actually *directs* the privileged action. |

---

## D. Admission-control abuse as a privesc primitive

kubesplaining audits *existing* weak webhooks (`KUBE-ADMISSION-001/003`) but never
models the **ability to create/patch** admission machinery as an edge. All Tier A on
the RBAC grant.

- **D1 · Create a webhook configuration (`KUBE-PRIVESC-018`).** `create` on
  `mutatingwebhookconfigurations` registers a cluster-wide tap on the API write path
  (after authn/authz, before persistence). A **mutating** webhook matching `pods CREATE`
  injects `privileged`/`hostPath`/a powerful SA mount/a sidecar into every future pod
  (incl. control-plane, unless namespace-excluded) → `node_escape`/`cluster_admin`; or
  rewrites incoming `RoleBinding`/pod objects. A **validating** webhook with
  `clientConfig.url` → attacker endpoint streams every matching AdmissionReview
  (Secret/ConfigMap `CREATE` bodies) out of band → `kube_system_secrets`. Precision:
  webhooks see the *request* object, so this taps Secrets *written through* admission,
  not a bulk read at rest; TokenRequest `.status.token` is populated post-admission so
  it is **not** captured. Cluster-scoped resource → must come from a ClusterRole.
- **D2 · MutatingAdmissionPolicy (`KUBE-PRIVESC-019`, *novel N1*).** The webhookless
  CEL/JSONPatch equivalent (`admissionregistration.k8s.io`, alpha v1.32) — no external
  TLS endpoint, mutation logic stored in etcd, executed in-process. `create` on
  `mutatingadmissionpolicies`+`…bindings` → same privileged-pod / token-mount injection,
  stealthier. Tier A on RBAC; feature-gate state is unknown offline (don't gate on it).
- **D3 · De-harden an existing policy engine.** `update`/`patch`/`delete` on
  `{mutating,validating}webhookconfigurations` or VAP/MAP `…policies`/`…bindings` flips
  `failurePolicy Fail→Ignore`, narrows `namespaceSelector`/`objectSelector` to exempt the
  attacker, empties `rules`, or deletes the config — neutering Kyverno/Gatekeeper/PSA-
  replacement enforcement so a previously-blocked privileged pod admits. Enabler edge →
  re-unlocks `node_escape`.
- **D4 · ParamRef / policy-as-data tampering (*novel N4/N15*).** A subject need not touch
  the policy or binding: writing the **param object** a VAP/MAP `paramRef` trusts (a
  ConfigMap/CRD) steers the CEL verdict, or `parameterNotFoundAction: Allow` + deleting the
  param fails it open. Correction verified: you **cannot** shadow a `Deny` binding with a new
  permissive one (bindings AND-combine / union `validationActions`) — only patching the
  existing binding's `paramRef` or param works. Tier B (needs VAP/bindings + paramRef
  collection).
- **D5 · CRD conversion webhook (*critic add*).** `create`/`patch` on
  `customresourcedefinitions` carrying `spec.conversion.strategy: Webhook` points the
  apiserver's per-read/write conversion call at an attacker Service — an admission-MITM-
  equivalent intercept the sweep's webhook rules miss.

---

## E. Ingress / network / MITM layer

| Ref | Vector | Signal | Gain | Tier |
| --- | --- | --- | --- | --- |
| KUBE-INGRESS-NGINX-001 | Ingress annotation injection → ingress-controller RCE → inherit its SA (cluster-wide `secrets` read for TLS) | create/patch `ingresses` (networking.k8s.io) + ingress-nginx controller pod present whose SA reads secrets cluster-wide | `kube_system_secrets` → `cluster_admin` | B |
| KUBE-INGRESS-NGINX-001 (unauth) | **IngressNightmare** CVE-2025-1974 (+1097/1098/24513/24514): POST a crafted AdmissionReview to the admission webhook over the pod network, `nginx -t` `dlopen`s a staged .so → **zero-RBAC** RCE | controller image tag `< v1.11.5` / `1.12.0`; ingress-nginx `ValidatingWebhookConfiguration` present; no NetworkPolicy fronting the webhook port | `kube_system_secrets`/`cluster_admin` | B (version+webhook) / C (true reachability) |
| KUBE-CONFIGMAP-COREDNS-WRITE-001 | Write `kube-system/coredns` Corefile → `forward`/`rewrite`/`template` in-cluster names to attacker IP → DNS MITM | update/patch `configmaps` in kube-system (`resourceNames [coredns]`) | `traffic_intercept` → credential/token theft | A |
| KUBE-INGRESS-GATEWAY-001/002 | Gateway API: attach `HTTPRoute` to a shared listener (`allowedRoutes.from: All`), or over-broad `ReferenceGrant` exposing cross-ns Secrets | create/update `httproutes`/`gateways`/`referencegrants` (gateway.networking.k8s.io) | `traffic_intercept`; cross-ns TLS disclosure | A (grant) / B (listener/ReferenceGrant spec) |

(Service `externalIPs` and Endpoints/EndpointSlice hijack are the RBAC-primitive rows
`KUBE-PRIVESC-021/022` in §B; they also feed the `traffic_intercept` sink.)

---

## F. Node / kubelet / PKI escalation

- **Static-pod manifest drop (`KUBE-ESCAPE-STATICPOD-001`).** Writable hostPath to
  `/etc/kubernetes/manifests` runs arbitrary mirror pods with **zero admission** — distinct
  from generic `/etc` read. Pair with A2 to chain node-root → control-plane.
- **Control-plane PKI theft → offline forgery.** Readable `/etc/kubernetes/pki/ca.key`
  → forge `system:masters` client certs; **`sa.key`** (`--service-account-signing-key-file`)
  → forge tokens for **any** SA including kube-system controllers, no API call, no expiry
  (*critic #1*). **`front-proxy-ca.key`** → forge the requestheader cert, set
  `X-Remote-Group: system:masters` to any aggregated API (*critic #4*).
- **Bootstrap token → `system:node`** (`KUBE-PRIVESC-026`, §B). Node-authorizer scope, not
  cluster-admin — correctly a node-scoped `kube_system_secrets` read.
- **Signer `sign`/`approve`** (`KUBE-PRIVESC-024`, §B). The controller-side half of PKI,
  never modeled.
- **Impersonate `system:nodes`** (A6). → `TargetNodeIdentity`; second hop (which pods run
  where) needs a pod→node→SA join to emulate the Node authorizer.
- **Control-plane scheduling amplifier (`KUBE-ESCAPE-CONTROLPLANE-SCHED-001`, *critic #6*).**
  A PodSpec tolerating `node-role.kubernetes.io/control-plane:NoSchedule` or pinning
  `nodeName`/`nodeSelector` to a master turns a benign hostPath into control-plane PKI/etcd
  access. The pod-escape edge never inspects tolerations/nodeName.
- **Poison trust ConfigMaps (`KUBE-CONFIGMAP-TRUST-001`, *critic #13*).** Write
  `kube-system/extension-apiserver-authentication` (requestheader CA list),
  `kube-root-ca.crt`, or `kubelet-config`/`kubeadm-config` → add an attacker CA → forge
  `system:masters` to aggregated APIs.
- **Version-gated node CVEs.** `KUBE-VERSION-CVE-2025-4563` (NodeRestriction DRA bypass on
  apiserver 1.32.0–1.32.5 / 1.33.0–1.33.1, Low/informational).

## G. Storage / volume escapes

| Ref | Vector | Signal | Tier |
| --- | --- | --- | --- |
| KUBE-PRIVESC-027 | Attacker-minted hostPath PV + PVC + pod (PSA-blind, create-time) | create `persistentvolumes`+`persistentvolumeclaims`+`pods` | A |
| KUBE-PRIVESC-028 | StorageClass → hostPath provisioner (`pathPattern` traversal; local-path-provisioner CVE-2025-62878) | create `storageclasses` (+ provisioner image/version) | A/B |
| KUBE-ESCAPE-SUBPATH-001 | `subPath`/`subPathExpr` symlink-exchange bind-mounts host paths (CVE-2021-25741, CVE-2017-1002101) | `volumeMounts[].subPath` set, **not** readOnly, on a writable volume (emptyDir/PVC/hostPath) + kubelet version < patch | B (kubelet version join) |
| KUBE-ESCAPE-CSI-001 | CSI ephemeral inline volume / FlexVolume runs a root plugin, bypassing hostPath-keyed PSA | `volumes[].csi.driver` / `volumes[].flexVolume` on a pod spec (+ host-capable CSIDriver `Ephemeral`) | A (spec) / B (CSIDriver) |
| KUBE-STORAGE-SNAPSHOT-001 | Clone a secret/etcd-bearing PV via VolumeSnapshot, mount the copy (*critic #8*) | create `volumesnapshots`/`volumesnapshotcontents` (snapshot.storage.k8s.io) | B |
| KUBE-STORAGE-SSRF-001 | In-tree provisioner SSRF via StorageClass `resturl`/endpoint params (CVE-2020-8555 class) (*critic #9*) | create `storageclasses` with a risky in-tree provisioner + URL param | B |

## H. Pod-spec escape vectors not inspected

| Ref | Field | Effect | Tier |
| --- | --- | --- | --- |
| KUBE-ESCAPE-WINHOSTPROCESS-001 | `securityContext.windowsOptions.hostProcess: true` (+`runAsUserName: NT AUTHORITY\SYSTEM`) | Windows-node root — the Windows analog of `privileged`, entirely unscored today | A |
| KUBE-PODSEC-SELINUX-001 | `seLinuxOptions.type: spc_t`/`unconfined_t` (or user/role set) | Removes SELinux confinement on enforcing nodes (Baseline-forbidden). Amplifier. | A |
| KUBE-PODSEC-APPARMOR-001 | `appArmorProfile.type: Unconfined` (or legacy annotation) | Removes the default syscall barrier that blocks mount/`unshare` escapes (CVE-2022-0492). Companion to the covered seccomp-Unconfined check. Amplifier. | A |
| KUBE-PODSEC-HOSTPORT-001 | `containers[].ports[].hostPort` | Ingress path invisible to NetworkPolicy; squat a node-local/NodePort service. Lateral, not node-root. | A |
| KUBE-PODSEC-SYSCTL-001 | `securityContext.sysctls[]` non-namespaced (`kernel.msg*/shm*/sem`) | Signals a loosened node; DoS/resource primitive. Low. | A (signal) / C (payoff) |

## I. Runtime & kernel CVE flags (node version strings, already collected, unparsed)

`Node.Status.NodeInfo.{ContainerRuntimeVersion,KernelVersion,KubeletVersion,OSImage}`
are in every snapshot but no analyzer matches them to CVE bands. These **amplify** any
in-container code-exec source (pod-create, controller-create, compromised image) into
`node_escape` independent of securityContext.

- **KUBE-NODE-RUNTIME-CVE-001** — runc ≤1.1.11 CVE-2024-21626 (Leaky Vessels;
  containerd→runc version is a *proxy* — flag as heuristic), CVE-2019-5736 (`/proc/self/exe`),
  containerd <1.4.3/<1.3.9 CVE-2020-15257 (gate on a hostNetwork pod on that node).
- **KUBE-NODE-KERNEL-CVE-001** — CVE-2022-0847 Dirty Pipe (no cap/userns needed — flag
  unconditionally in-band), CVE-2022-0185 fsconfig & CVE-2022-0492 cgroup-v1 release_agent
  (both need unprivileged userns / AppArmor-unconfined — gate accordingly).
- **KUBE-VERSION-CVE-2022-3172** — aggregated-API SSRF/credential-forward, apiserver
  ≤1.25.0/1.24.0-4/… ; **KUBE-INGRESS-NGINX-001** version gate (§E).

## J. Cloud identity beyond EKS (+ the cloud-return edge)

Mirror the shipped IRSA edge for GKE/AKS, then close A5's return gap.

| Ref | Signal | Sink | Tier |
| --- | --- | --- | --- |
| KUBE-CLOUD-GKE-WI-001 | SA annotation `iam.gke.io/gcp-service-account` + a pod/controller referencing it | new `TargetGCPServiceAccount` (admin heuristic on `-compute@developer` / `Owner`/`Editor`) | A (origin) / C (GCP-side binding) |
| KUBE-CLOUD-AZWI-001 | SA annotation `azure.workload.identity/client-id` + pod label `azure.workload.identity/use: "true"` | new `TargetAzureManagedIdentity` | A (origin) / C (Entra federation) |
| KUBE-CLOUD-GKE-WI-SAMENESS-001 | create `namespaces`+`serviceaccounts`+`pods` → recreate a `NAMESPACE/KSA` tuple matching an existing WI binding ("identity sameness") | `TargetGCPServiceAccount` | A (grant) / C |
| KUBE-CLOUD-\*-RETURN-001 | cloud-admin IAM node re-enters the cluster: GKE `roles/container.admin`/`clusterAdmin` → `get-credentials`; AKS `Contributor`/AKS-Admin → `listClusterAdminCredential`; EKS `eks:AssociateAccessPolicy` (Access Entries) | `cluster_admin`/`system_masters` | C (IAM policy data out-of-snapshot) |

Also: GCP SA impersonation chains (`iam.serviceAccountTokenCreator`/`actAs`, cross-project
`GenerateAccessToken` hops) are origin-detectable only (C).

---

## K. Long escalation chains the current BFS cannot surface

These are the multi-hop paths the user specifically asked for — each combines primitives
above such that **no existing edge sequence connects source to sink**. Grouped;
representative chains shown with the exact structural reason the BFS misses them. All 20
are in the research dataset; the marquee ones:

### K1 — Confused-deputy laundered into node-root (real-world, 5 hops)
`tenant/dev-deployer` (no `pods` verb) `--create Kustomization→attacker OCI source-->`
`kustomize-controller` (cluster-admin) `--applies a privileged kube-system DaemonSet-->`
hostPath `/`+privileged `--escape-->` `node_escape` `--read /etc/kubernetes/admin.conf &
etcd on a control-plane node-->` `cluster_admin`.
**Missed because:** no confused-deputy edge (A3) *and* `node_escape` is terminal (A2) — two
independent misses stack.

### K2 — Double-controller laundering (realistic, 6 hops)
`ci/pipeline-submitter` (create `workflows`, no `pods`) `--Workflow spec.serviceAccountName=
gitops-deployer-->` executor pod runs as `gitops-deployer` `--steal token-->` `--create
Kustomization-->` `kustomize-controller` `--applies a ClusterRoleBinding→attacker-->`
`cluster_admin`.
**Missed because:** the CI-CRD SA-override edge is unmodeled (subject lacks `pods`, so
`-001/-004` never fire), *and* SA-token-theft transitivity isn't represented, *and* the Flux
confused-deputy edge is absent.

### K3 — Create mutating webhook → tap the write path → node-escape (real-world, 5–6 hops)
`create mutatingwebhookconfigurations` `--register wildcard webhook-->` apiserver POSTs every
AdmissionReview to attacker `--inject privileged/hostPath sidecar into a kube-system pod-->`
`node_escape` `--steal kubelet cert-->` `cluster_admin`.
**Missed because:** `addEdgesForRule` has no `admissionregistration.k8s.io` case (D1), and the
injected sidecar is synthesized at admission — invisible to a static pod scan.

### K4 — Namespace-admin → cluster-admin via a co-located controller (real-world, 4 hops)
`namespace_admin:apps` `--implies create Flux CR / steal any SA token in apps-->`
`flux-system` controller SA (or a co-located privileged SA) `--its cluster-scoped edges-->`
`cluster_admin`.
**Missed because:** `namespace_admin` is a terminal sink (A1) — BFS halts and never expands the
implied token-theft/CRD-create capability.

### K5 — Webhook-backend hijack via EndpointSlice (realistic, 5 hops)
`namespace_admin:security-system` (or an `endpointslices`-writer) `--repoint the selector-less
Service backing a MutatingWebhookConfiguration-->` apiserver→webhook traffic redirected `--forge
admit responses / capture AdmissionReview Secret bodies-->` `--inject privileged pod / forge
RoleBinding-->` `cluster_admin`.
**Missed because:** no `endpoints`/`endpointslices` edge (A4/§B-021), Services & EndpointSlices
aren't collected, and nothing correlates an endpoint-writer with an in-namespace webhook Service.

### K6 — Service externalIPs → kube-proxy MITM of apiserver/IMDS (real-world, 5 hops)
`create services` `--spec.externalIPs=[apiserver ClusterIP | 169.254.169.254]-->` kube-proxy
MITM on every node `--capture a privileged token / node IAM creds-->` `cluster_admin` (or
`aws-iam` on the IMDS variant). **Missed because:** no `services`/externalIPs edge and no MITM
sink (A4).

### K7 — Ingress annotation injection → controller-SA cluster secret read (real-world, 5 hops)
`create ingresses` `--malicious snippet / IngressNightmare-->` ingress-nginx RCE `--read the
controller SA token (cluster-wide `secrets`)-->` `kube_system_secrets` → `cluster_admin`.
**Missed because:** Ingresses aren't collected, `ingresses` is not a modeled verb, and no edge
links an ingress-writer to the controller SA's secret-read power.

### K8 — PKI chains to `system_masters` (realistic, 3–4 hops)
Three distinct, all unmodeled: **signer `sign`** on `kubernetes.io/kube-apiserver-client` →
directly write a signed `O=system:masters` cert (C14); **bootstrap-token** → `system:node` →
pod-token theft (C13); **static-pod drop** on a control-plane node → steal `ca.key` → offline
forgery (C15). **Missed because:** the CSR model only covers create+`/approval`; `signers`/`sign`
and the bootstrap/static-pod primitives have no edge; `node_escape` is terminal.

### K9 — Cloud round-trips (real-world/realistic, 4–5 hops)
GKE: pod → WI token → GSA `roles/container.admin` → `get-credentials` → `cluster_admin` (C17).
EKS: pod → IMDS node role → `sts:AssumeRole` → `eks:AssociateAccessPolicy` (Access Entry) →
`system_masters` (C18). AKS: pod → IMDS MI → `listClusterAdminCredential` → `cluster_admin`
(C19). Plus C20: Argo SA-override → IRSA → IAM self-escalate → write `aws-auth` → `system_masters`.
**Missed because:** GKE/AKS unmodeled (A5), external IAM nodes are terminal (no return edge), and
the CI-CRD SA-override entry edge is absent.

---

## L. Novel / speculative vectors (survived 2-of-3 plausibility voting)

Under-documented or forward-looking primitives most scanners — and most write-ups — miss.
Detectability and the load-bearing caveat are stated honestly.

| # | Vector | Novelty | Detect | Key caveat |
| --- | --- | --- | --- | --- |
| N1 | **MutatingAdmissionPolicy** webhookless etcd-native mutating tap (§D2) | undocumented-but-real | full (RBAC) | feature-gate state unknown offline |
| N2 | `pods/ephemeralcontainers` inject into a **running** privileged pod (steal its token/PID) | undocumented-but-real | full | needs a high-value running pod in scope (`-013` covers the verb but not this framing) |
| N3 | **ClusterTrustBundle / PodCertificate** trust-anchor poisoning → mTLS peer impersonation | undocumented-but-real | full (grant) | workload must project the bundle; signer-scoped needs `attest` |
| N4/N15 | **VAP paramRef / policy-as-data** tampering (write the param, not the policy) | undocumented-but-real | partial | policy must actually derive its verdict from mutable params |
| N5/N7 | **DRA** `ResourceClaim`/`DeviceClass`/`adminAccess` → driver CDI host injection | speculative | partial | hinges on a driver that maps unsanitised claim config to CDI mounts/hooks |
| N6 | **Controller-token laundering**: `update` a privileged controller's Deployment (or create a pod as its SA in-ns) → inherit its token | undocumented-but-real | full | SA token must be auto-mounted; SA genuinely high-value |
| N8 | **KubeVirt** VMI as a PodSecurity-bypass deputy → privileged virt-launcher | undocumented-but-real | partial | KubeVirt installed with controller-SA PSA exemption |
| N9 | **Karpenter** NodeClaim `userData`/AMI/instanceProfile injection → attacker node | undocumented-but-real | partial | cloud IAM out-of-snapshot |
| N10 | **Image-policy trust-root** tampering (sigstore/Kyverno-verifyImages) → supply-chain bypass | speculative | partial | orthogonal to PSA — still needs a separate privileged-pod control to node-escape |
| N11 | **`pods/binding`** scheduler bypass onto a tainted control-plane node → PKI theft (§B-030) | undocumented-but-real | partial | control-plane co-residency unconditional; hostPath+root needs no PSA |
| N12 | **Evict-the-webhook-backend race**: `pods/eviction` + `failurePolicy: Ignore` fail-open window | speculative | partial | only bypasses the fail-open webhook's own controls, **not** the RBAC authorizer |
| N13 | **PriorityClass `globalDefault` flip** + preemption steering | undocumented-but-real | partial | caps at 1e9; can't preempt system-critical infra |
| N14 | **Node label/taint patch** → attract a privileged DaemonSet onto an attacker node | undocumented-but-real | partial | attacker must control the destination kubelet to harvest the relocated token |

---

## M. Additional gaps flagged by the completeness critic

Beyond the 57 verified above, the critic surfaced 13 under-covered classes; the ones not
already folded into A–L:

- **OpenShift SecurityContextConstraints** — `use` on `scc/privileged` (etc.) is the
  RBAC-inferable analog of PSA-bypass → `node_escape`. Entire authorization model absent
  (`KUBE-OPENSHIFT-SCC-001`).
- **Legacy PSP `use`** — first-class graph edge `use podsecuritypolicies/<permissive>` →
  `node_escape`, not just a docs footnote.
- **`get pods/log`** (scrape logged tokens) and **`pods/proxy`/`services/proxy`** (reach
  dashboards/IMDS bypassing NetworkPolicy) — RBAC-inferable recon-to-cred verbs
  (`KUBE-PRIVESC-RECON-001`).
- **CRD conversion webhook** (D5), **SA signing-key / front-proxy CA theft** (§F),
  **VolumeSnapshot clone-mount** & **provisioner SSRF** (§G), **Crossplane/OLM/Rancher-Fleet**
  catalog entries (§C), **trust-ConfigMap poisoning** (§F) — captured above.

---

## N. Proposed new sinks, edge types & rule-ID allocation (summary)

### New sinks
| Sink | Represents | Fed by |
| --- | --- | --- |
| `TargetTrafficIntercept` | MITM / credential capture in transit | externalIPs, endpoints/slices, coredns, APIService, webhook exfil, ClusterTrustBundle |
| `TargetNodeIdentity` | `system:node:<name>` (Node-authorizer scope) | bootstrap token, impersonate system:nodes |
| `TargetGCPServiceAccount` / `TargetAzureManagedIdentity` | bound cloud identity | GKE WI / AKS WI annotations |
| `TargetAdmissionBypass` | policy-engine de-hardening (enabler) | webhook/VAP patch, paramRef tamper, evict-backend race |

### Structural changes (unlock the most chains)
1. Make `namespace_admin` **traversable** (A1) → K4, K7 tail.
2. Make `node_escape` a conditional **intermediate** with control-plane onward edges (A2) → K1, K8.
3. Add the **confused-deputy** edge family + operator catalog (A3, §C) → K1, K2, K4.
4. Add the **traffic_intercept** sink (A4) → K5, K6.
5. Give external cloud-IAM nodes **outbound return edges** + GKE/AKS parsers (A5) → K9.
6. `resourceName`-aware **impersonation** with a node-identity sink (A6) → K8.

### Rule-ID allocation
New `KUBE-PRIVESC-018…033` (§B), `KUBE-CONFUSED-DEPUTY-*` (§C), `KUBE-ESCAPE-{WINHOSTPROCESS,
SUBPATH,CSI,STATICPOD,CONTROLPLANE-SCHED}-001`, `KUBE-PODSEC-{SELINUX,APPARMOR,HOSTPORT,SYSCTL}-001`,
`KUBE-NODE-{RUNTIME,KERNEL}-CVE-001`, `KUBE-INGRESS-{NGINX,GATEWAY}-001`, `KUBE-CLOUD-{GKE-WI,
AZWI,*-RETURN}-001`, `KUBE-CONFIGMAP-{COREDNS-WRITE,TRUST}-001`, `KUBE-PKI-{SAKEY,FRONTPROXY}-001`,
`KUBE-STORAGE-{SNAPSHOT,SSRF}-001`, `KUBE-CRD-CONVERSION-WEBHOOK-001`, `KUBE-OPENSHIFT-SCC-001`.
(The research agents collapsed many onto a placeholder `KUBE-PRIVESC-018`; the numbering above
is the deconflicted allocation.)

### Suggested implementation order (impact × cost)
1. **Tier-A RBAC edges on current data** — `-018` (webhooks), `-019` (MAP), `-024` (signer sign),
   `-026` (bootstrap token), `-027` (create-PV hostPath), `-031` (secret-mount read), `-032`
   (DaemonSet hijack), impersonate-subresources (`-025`), `KUBE-ESCAPE-WINHOSTPROCESS-001`.
   Highest value, zero collector work.
2. **Structural unlocks** — A1 (namespace_admin traversable) and A3 (confused-deputy catalog);
   biggest chain coverage per change.
3. **Collector extensions (Tier B)** — Services + Endpoints/EndpointSlices (→ `-021/-022`, K5/K6),
   Ingresses (K7), APIServices (`-020`), VAP/bindings+paramRef (D4), node version parsing (§I).
4. **Cloud (A5)** — GKE/AKS parsers + return-edge tables (K9); Tier-C fidelity, but parity with
   the shipped EKS edge.

---

## Appendix — method & provenance

- **Coverage baseline** cross-referenced against `internal/analyzer/privesc/{graph.go,
  analyzer.go,cloud_edges.go}`, `internal/models/escalation.go`, and `docs/findings.md`.
- **Grounding** (representative): Kubernetes RBAC good-practices & admission docs; Datadog
  Security Labs (KubeHound, unpatchable-CVEs, IngressNightmare); Palo Alto Unit42
  (CVE-2020-8554, CVE-2022-0492, modern-k8s-threats); BishopFox pod-privesc; Wiz / ProjectDiscovery
  IngressNightmare; rhinosecuritylabs (kubelet TLS bootstrap); GKE/AKS Workload Identity docs;
  cert-manager, Flux (GHSA-35rf-v2jv-gfg7), Argo CD (GHSA-2f5v-8r3f-8pww), Kyverno
  (GHSA-8p9x-46gm-qfx2), external-secrets, Velero security docs; CVE-2024-21626 (Leaky Vessels),
  CVE-2022-0847 (Dirty Pipe), CVE-2021-25741/25737/25740, CVE-2022-3172, CVE-2025-1974,
  CVE-2025-62878, CVE-2023-5528, CVE-2025-4563.
- Every mechanism was adversarially verified for technical correctness and offline-detectability;
  corrections (e.g. webhooks tap request objects not secrets-at-rest; VAP bindings AND-combine so
  you cannot shadow a Deny; `system:node` ≠ cluster-admin; containerd→runc version is a proxy) are
  reflected inline.

---

## O. Follow-up: implemented items, corrections, and disclosures since 2026-07-12

Added 2026-07-24 after re-auditing this document against the tree.

### O1. Implemented from this document

Landed on the deep-chain work (see `docs/superpowers/specs/2026-07-24-privesc-deep-chains-design.md`):

- **A1** — `namespace_admin` is now traversable, with `colocated_sa_token_theft` edges to every
  ServiceAccount in the namespace.
- **A2** — `node_escape` now continues to `system_masters` (`control_plane_pki_theft`) and
  `token_mint` (`static_pod_admission_bypass`), gated on the snapshot containing a control-plane
  node with no `NoSchedule` taint for its role.
- **A3** — confused-deputy edge family shipped as `KUBE-CONFUSED-DEPUTY-001`, catalog-driven and
  RBAC-only, in `internal/analyzer/privesc/deputy.go`. Precision gate: the controller
  ServiceAccount must exist in the snapshot.
- **Structural, not in the original A-list** — `IsSystem` was doing double duty as both a
  source-block and an intermediate-hop-block. Split into `IsSystem` (name prefix `system:`,
  blocked both ways) and `IsControlPlane` (non-built-in kube-system SA: traversable as an
  intermediate, never seeded as a source).
- **Scoring** — replaced the flat "0.5 per hop, downgrade at 3+ hops" attenuation with a per-edge
  `Difficulty` rating summed across the chain. Length alone no longer downgrades severity; a
  chain containing a `hard` hop does.

### O2. Correction to A5(b)

**A5(b) is inaccurate as written, and was already inaccurate when this document was published.**
External AWS-IAM nodes DO carry outbound return edges to `system_masters` and `cluster_admin`
(`cloud_edges.go:170,182`), and the pathfinder deliberately continues traversal through external
sinks. Only **A5(a)** (GKE / AKS unmodeled) is genuinely open.

### O3. A fifth structural limit, now addressed for the remediation case

Sections A1-A6 miss one: **path search records only the shortest chain per (source, sink) pair.**
Correction to the claim originally made here: three mechanisms did not jointly enforce this. Only
the global `visited` prune does. The other two named in the original text, a shorter-chain guard
and a one-path-per-pair `seen` map, were unreachable once the `visited` prune existed and have
been deleted by the cut-resilient work (see
[`2026-07-25-cut-resilient-escalation-paths-design.md`](superpowers/specs/2026-07-25-cut-resilient-escalation-paths-design.md)).

That work addresses the limit for the remediation case: a second BFS pass re-runs the search per
source with the binding behind the first hop banned, and a richer route that survives surfaces as
`alternate_escalation_path` on the finding, plus the tag `privesc:survives-first-cut`.
`--max-privesc-depth` still bounds both searches, so an alternate that only exists beyond the
configured depth stays invisible. The general case (a richer route surfacing regardless of what
remediation is proposed) remains open; the design doc's "Deferred" section frames the fix as a
k-visit BFS generalization.

Consequence for the deep-chain work: e2e chains now reach 4 hops and the 3-plus-hop population
grew from 8 findings to 14, but 5-plus-hop chains will not appear until a subject can reach a
sink *only* by a long route, or via the alternate pass now covering the remediation case.
Surfacing the instructive longer path alongside the shortest one in the general case is still the
next structural change worth making.

### O4. Publicly disclosed since this document was written

Sixteen items not covered by sections A-N. "RBAC-inferable" means detectable from the snapshot
kubesplaining already collects.

| Technique | Disclosed | Inferable | Data needed |
| --- | --- | --- | --- |
| **Copy Fail** CVE-2026-31431: unprivileged container escape via shared image-layer page cache | 2026-04 | yes | `KernelVersion` (collected, unparsed) **plus a new join**: does an unprivileged pod share an image layer with a privileged pod? Defeats every securityContext check we have. |
| runc triad CVE-2025-31133 / -52565 / -52881 | 2025-11 | yes | `ContainerRuntimeVersion` (collected). containerd-to-runc version proxy. |
| NVIDIAScape CVE-2025-23266 (LD_PRELOAD via createContainer OCI hook) | 2025-07 | yes | nvidia-container-toolkit DaemonSet image tag from the pod spec. |
| DRA `resourceclaims/binding` and `resourceclaims/driver` node-aware verbs | 2026-04 (1.36 GA) | yes | Pure RBAC, but the verbs are **prefixed** (`associated-node:update`). The matcher will silently fail to match them: a latent correctness bug, not just a gap. |
| OCI image volumes `volumes[].image` GA | 2026-04 (1.36) | yes | PodSpec field, already collected. |
| ServiceMonitor `bearerTokenFile` token exfil (GHSA-cxh2-4639-vmc5) | 2026-06 | yes | Shipped: `monitoring.coreos.com/servicemonitors` is in the confused-deputy catalog. |
| Argo CD repo-server unauthenticated gRPC RCE (unpatched) | 2026-07 | yes | Not an RBAC edge, a **NetworkPolicy** edge: unauthenticated in-cluster service with no policy selecting it. Generalises to Ray dashboards, Redis, etcd, kubelet 10250. |
| ConstrainedImpersonation KEP-5284 | 2026-04 (beta) | yes | Changes the impersonation threat model that gap A6 targets. |
| User namespaces `hostUsers: false` GA | 2026-04 | yes | Inverse signal: should **attenuate** every escape rule. PodSpec field, uninspected today. |
| CVE-2024-10220 `gitRepo` volume command execution | 2024-11 | yes | PodSpec `volumes[].gitRepo`, collected but never inspected. Missed by section H. |
| 2026 kernel escape band (io_uring, ptrace, nf_tables, epoll, futex) | 2026 | yes | Extends the proposed `KUBE-NODE-KERNEL-CVE-001` bands. |
| flux-operator GHSA-4xh5-jcj2-ch8q (impersonation bypass on empty OIDC claims) | 2026 | yes | Operator deployment presence plus image version band. |
| CVE-2026-42880 Argo CD read-only users read plaintext Secrets | 2026 | no | Policy lives in `argocd-rbac-cm`, whose values the collector blanks. |
| CVE-2025-5187 NodeRestriction OwnerReferences | 2025 | yes | apiserver version band. Availability impact; low priority. |
| CVE-2026-33105 AKS improper authorization | 2026 | no | Control-plane side, invisible to a snapshot. |
| TeamPCP Trivy / Actions supply-chain compromise | 2026-03 | no | Useful only as severity evidence, not as a detection. |

Highest value next, by (impact x cost): the **DRA prefixed-verb matcher fix** (latent bug),
`hostUsers` attenuation and `gitRepo` / image-volume inspection (Tier A, pure PodSpec), then the
**unauthenticated-service NetworkPolicy join** (reuses two subsystems that already exist), then
the Copy Fail image-sharing join (a genuinely new analysis shape).
