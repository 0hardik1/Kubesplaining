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

	"github.com/hardik/kubesplaining/internal/models"
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
		Long:   template.HTML(`<p>A <strong>ServiceAccount</strong> is an in-cluster identity assigned to pods. Every pod gets a token mounted at <code>/var/run/secrets/kubernetes.io/serviceaccount/token</code> — that token <em>is</em> the credential. If an attacker reads that file from inside a compromised container (or creates a pod that mounts the token), they can call the API <em>as</em> the ServiceAccount, with whatever permissions the SA has been granted.</p><p>This is the most common pivot in real-world Kubernetes attacks: compromise one pod, steal its token, ride the token to wherever its RBAC allows.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/security/service-accounts/",
	},
	"Group": {
		Title:  "Group",
		Short:  "A label attached to authenticated identities — e.g. system:masters acts as cluster-admin.",
		Long:   template.HTML(`<p>A <strong>Group</strong> is a string label associated with users or ServiceAccounts at authentication time. RoleBindings can target groups, so <em>everyone</em> in the group inherits the bound permissions. Two groups deserve special care:</p><ul><li><code>system:masters</code> — hardcoded as cluster-admin. Membership is permanent (you cannot un-grant it via RBAC).</li><li><code>system:authenticated</code> — every authenticated identity. Bind anything sensitive to this and you grant it to the world.</li></ul><p>Groups are assigned by the authenticator (OIDC claims, certificate organization fields, etc.), not stored in the API server, which means they don't appear in <code>kubectl get</code>.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings",
	},
	"User": {
		Title:  "User",
		Short:  "A human (or external automation) authenticated by certs, OIDC, or static tokens.",
		Long:   template.HTML(`<p>A <strong>User</strong> in Kubernetes is whoever the authenticator says they are — there is no User object in the API. Identity comes from a client certificate's CN, an OIDC <code>sub</code> claim, a webhook, or a static token. RBAC then targets that identity by name. If you see "User foo" in a finding, foo is whatever string the authentication layer produced.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
	},
	"Pod": {
		Title:  "Pod",
		Short:  "The smallest schedulable unit — one or more containers sharing a network and storage namespace.",
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
		Short: "Runs a copy of a pod on every node (often privileged — log collectors, CNI agents).",
		Long:  template.HTML(`<p>A <strong>DaemonSet</strong> schedules one pod per node, typically for cluster infrastructure (CNI, log shipping, node monitoring). DaemonSets are frequent targets because they often need <code>hostNetwork</code>, <code>hostPath</code>, or <code>privileged</code> to do their job — which makes them ideal for attackers if compromised.</p>`),
	},
	"StatefulSet": {
		Title: "StatefulSet",
		Short: "Pods with stable identities and persistent storage — databases, queues.",
		Long:  template.HTML(`<p>A <strong>StatefulSet</strong> gives each pod a stable DNS name and dedicated PersistentVolume. Compromise here often means access to durable application data — databases, message queues, caches.</p>`),
	},
	"ReplicaSet": {
		Title: "ReplicaSet",
		Short: "Maintains a stable set of pod replicas. Usually managed by a Deployment.",
		Long:  template.HTML(`<p>A <strong>ReplicaSet</strong> keeps a target number of identical pods running. You normally don't manage these directly — a Deployment owns them.</p>`),
	},
	"Job": {
		Title: "Job",
		Short: "Runs a pod (or pods) to completion — batch tasks, migrations.",
		Long:  template.HTML(`<p>A <strong>Job</strong> executes one or more pods that must complete successfully. Jobs are a common attacker mechanism for one-shot privilege use ("create a Job that mounts the host filesystem, do the thing, exit").</p>`),
	},
	"Secret": {
		Title:  "Secret",
		Short:  "Stores credentials — TLS keys, registry creds, API tokens, ServiceAccount tokens.",
		Long:   template.HTML(`<p>A <strong>Secret</strong> holds sensitive data: registry pull credentials, TLS private keys, ServiceAccount tokens. Secrets are base64-encoded, <em>not</em> encrypted by default — anyone with <code>get</code> on the Secret resource can read the contents in cleartext. <code>get</code>/<code>list</code>/<code>watch</code> on Secrets in <code>kube-system</code> is effectively cluster-admin: that namespace holds the controller-manager and kube-scheduler tokens.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/configuration/secret/",
	},
	"ConfigMap": {
		Title: "ConfigMap",
		Short: "Non-sensitive key/value config data injected into pods. Often misused for credentials.",
		Long:  template.HTML(`<p>A <strong>ConfigMap</strong> stores plain-text configuration that pods read at startup. They are <em>not</em> meant to hold secrets, but in practice teams put database URLs (with passwords), API keys, and tokens in ConfigMaps. Kubesplaining flags credential-shaped keys for that reason.</p>`),
	},
	"ClusterRole": {
		Title:  "ClusterRole",
		Short:  "A cluster-wide bag of (verbs × resources) permissions — granted via a binding.",
		Long:   template.HTML(`<p>A <strong>ClusterRole</strong> is a named set of permissions ("can <code>get</code>/<code>list</code> on <code>pods</code> across the cluster"). It does nothing on its own — it must be granted to a subject through a ClusterRoleBinding (cluster-wide) or RoleBinding (one namespace).</p><p>The infamous <code>cluster-admin</code> ClusterRole grants <code>verbs: ["*"]</code> on <code>resources: ["*"]</code> in <code>apiGroups: ["*"]</code> — total control.</p>`),
		DocURL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	},
	"ClusterRoleBinding": {
		Title:  "ClusterRoleBinding",
		Short:  "Grants a ClusterRole's permissions to a subject across the entire cluster.",
		Long:   template.HTML(`<p>A <strong>ClusterRoleBinding</strong> assigns a ClusterRole to subjects (Users, Groups, ServiceAccounts) at cluster scope — not just one namespace. A binding to <code>cluster-admin</code> here means the subject can do anything anywhere. Always look at <em>both</em> what role is bound <em>and</em> who it is bound to.</p>`),
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
		Long:  template.HTML(`<p>A <strong>RoleBinding</strong> assigns permissions inside a single namespace. It can reference a Role from the same namespace or a ClusterRole — when it references a ClusterRole, the permissions still only apply inside the binding's namespace.</p>`),
	},
	"Namespace": {
		Title: "Namespace",
		Short: "A logical partition for resources — most policies, quotas, and RBAC scope to one.",
		Long:  template.HTML(`<p>A <strong>Namespace</strong> divides cluster resources by team, environment, or application. RoleBindings, NetworkPolicies, ResourceQuotas, and most admission rules apply at namespace scope. Compromising one workload in a namespace often gives lateral access to the rest of that namespace's resources.</p>`),
	},
	"hostPath": {
		Title:  "hostPath volume",
		Short:  "Mounts a directory from the underlying node into the pod — a classic container-escape vector.",
		Long:   template.HTML(`<p>A <strong>hostPath</strong> volume bind-mounts a path from the host node into the container. Sensitive paths like <code>/</code>, <code>/etc</code>, <code>/var/run/docker.sock</code>, or <code>/var/lib/kubelet</code> turn the pod into a node-takeover primitive: an attacker inside the pod can write systemd units, read the kubelet's credentials, or directly invoke the container runtime to start privileged containers on the host.</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
	},
	"PrivilegedContainer": {
		Title:  "Privileged container",
		Short:  "Runs with kernel-level access to the host — equivalent to root on the node.",
		Long:   template.HTML(`<p>Setting <code>securityContext.privileged: true</code> disables most container isolation: the container gets every Linux capability, can access all host devices, and can mount host filesystems. From a privileged container an attacker can escape to the node trivially (<code>nsenter</code>, mount the host's <code>/</code>, write a SUID binary, etc.).</p>`),
		DocURL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	},
	"hostNetwork": {
		Title: "hostNetwork",
		Short: "Pod shares the node's network namespace — sees and binds host ports.",
		Long:  template.HTML(`<p>With <code>hostNetwork: true</code>, the pod sees the host's network interfaces directly. It can reach the kubelet on <code>localhost:10250</code>, sniff or spoof traffic between other workloads on that node, and bind privileged ports without going through the CNI.</p>`),
	},
	"hostPID": {
		Title: "hostPID",
		Short: "Pod sees and can signal every process on the node — including the kubelet.",
		Long:  template.HTML(`<p>With <code>hostPID: true</code>, the pod's PID namespace is the host's. It can <code>ps</code> all processes (including the kubelet), read <code>/proc/&lt;pid&gt;/environ</code> for credentials, and join other processes' namespaces with <code>nsenter</code>.</p>`),
	},
	"RunAsRoot": {
		Title: "Container runs as root (UID 0)",
		Short: "No runAsNonRoot constraint — kernel exploits and breakout primitives apply.",
		Long:  template.HTML(`<p>Containers that run as UID 0 are not automatically dangerous, but they remove a layer of defence. Combined with capabilities or hostPath, root-in-container becomes root-on-node much more easily.</p>`),
	},
	"Capabilities": {
		Title: "Linux capabilities",
		Short: "Fine-grained kernel privileges — SYS_ADMIN, NET_ADMIN, etc. are container-escape primitives.",
		Long:  template.HTML(`<p>Linux <strong>capabilities</strong> split root's powers into ~40 buckets. <code>SYS_ADMIN</code> alone is enough to mount filesystems and break out of most container runtimes. <code>NET_ADMIN</code> allows traffic redirection. <code>SYS_PTRACE</code> lets a container read other processes' memory. The principle is: drop everything, add only what is needed.</p>`),
	},
	"NetworkPolicy": {
		Title: "NetworkPolicy",
		Short: "Cluster-internal firewall — without one, every pod can talk to every other pod.",
		Long:  template.HTML(`<p>A <strong>NetworkPolicy</strong> restricts which pods can talk to which. The default in Kubernetes is <em>allow-all</em>: a pod with no NetworkPolicies covering it can reach every pod in the cluster, including the API server, etcd via metrics endpoints, and internal services. Lateral movement after pod compromise depends on whether NetworkPolicies are enforced.</p>`),
	},
	"AdmissionWebhook": {
		Title: "Admission webhook",
		Short: "A pluggable validator/mutator for API requests — failurePolicy: Ignore is a security gap.",
		Long:  template.HTML(`<p>An <strong>admission webhook</strong> intercepts API requests before they are persisted, allowing custom policy. If a security-critical webhook has <code>failurePolicy: Ignore</code>, an outage of the webhook backend silently disables enforcement — attackers can race a webhook restart and slip through.</p>`),
	},
	"kube-system": {
		Title: "kube-system namespace",
		Short: "Holds the control plane's ServiceAccounts and tokens — read-access here is cluster-admin.",
		Long:  template.HTML(`<p>The <strong>kube-system</strong> namespace contains tokens for the controller-manager, kube-scheduler, and other privileged controllers. Anyone who can <code>get</code>/<code>list</code>/<code>watch</code> Secrets in kube-system can read those tokens and act as those controllers — which is effectively cluster-admin.</p>`),
	},
	"system:masters": {
		Title: "system:masters group",
		Short: "Hardcoded as cluster-admin. Membership cannot be revoked through RBAC.",
		Long:  template.HTML(`<p>The <strong>system:masters</strong> group is special-cased in the API server: members bypass RBAC and act as cluster-admin. The membership comes from the authenticator (typically certificate <code>O=system:masters</code>) and <em>cannot</em> be removed by deleting bindings — it is wired in below the RBAC layer.</p>`),
	},
}

// Techniques maps a privesc-action key (matching the Action strings in
// internal/analyzer/privesc/graph.go) to its educational content.
var Techniques = map[string]TechniqueExplainer{
	"impersonate": {
		Title: "RBAC impersonation",
		Plain: template.HTML(`<p>Kubernetes has a built-in "act as another user" feature — the <code>impersonate</code> verb on <code>users</code>, <code>groups</code>, or <code>serviceaccounts</code>. Anyone with that verb can submit requests as <em>any</em> identity, bypassing whatever permissions they don't have themselves.</p><p>Granting <code>impersonate</code> on <code>groups</code> = <code>["*"]</code> is equivalent to cluster-admin: the holder can impersonate <code>system:masters</code>.</p>`),
		Mitre: "T1078.004 — Cloud Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Confirm impersonation works", Cmd: "kubectl auth can-i --list --as=system:masters"},
			{Note: "Exfiltrate every secret", Cmd: "kubectl --as=system:masters get secrets -A"},
			{Note: "Pin permanent cluster-admin for an attacker-controlled user", Cmd: "kubectl --as=system:masters create clusterrolebinding pwn --clusterrole=cluster-admin --user=attacker"},
		},
	},
	"bind_or_escalate": {
		Title: "RBAC bind/escalate bypass",
		Plain: template.HTML(`<p>RBAC has a guardrail: you can only grant permissions you yourself hold. Two verbs override that guardrail — <code>bind</code> (on a Role/ClusterRole) and <code>escalate</code> (also on Roles). Holding either lets the attacker create a binding to a Role they don't have themselves — including <code>cluster-admin</code>.</p>`),
		Mitre: "T1098.003 — Account Manipulation: Additional Cloud Roles",
		AttackerSteps: []AttackerStep{
			{Note: "Bind a chosen ServiceAccount to cluster-admin", Cmd: "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=ns:me"},
			{Note: "Verify cluster-admin reach", Cmd: "kubectl get secrets -A"},
		},
	},
	"pod_create_token_theft": {
		Title: "Pod creation → ServiceAccount token theft",
		Plain: template.HTML(`<p>Anyone who can create pods in a namespace can mount any ServiceAccount in that namespace into the pod. Cluster-scoped pod-create lets you mount any ServiceAccount in <em>any</em> namespace. Once the pod is running, the attacker reads <code>/var/run/secrets/kubernetes.io/serviceaccount/token</code> from inside it — and now holds a token for that SA.</p><p>This is the single most common privilege-escalation pattern in production Kubernetes.</p>`),
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
		Plain: template.HTML(`<p>The <code>create</code> verb on <code>serviceaccounts/token</code> mints a fresh, valid token for any ServiceAccount in scope — no pod required. Cleaner than the pod-creation route and harder to spot in audit logs.</p>`),
		Mitre: "T1528 — Steal Application Access Token",
		AttackerSteps: []AttackerStep{
			{Note: "Mint a fresh 24h token for any ServiceAccount in scope", Cmd: "kubectl create token <sa> --duration=24h --bound-object-kind=Pod --bound-object-name=irrelevant"},
			{Note: "Call the API as the ServiceAccount using the minted token", Cmd: "curl --header 'Authorization: Bearer <token>' https://kubernetes.default.svc/api/..."},
		},
	},
	"bound_to_cluster_admin": {
		Title: "Direct cluster-admin binding",
		Plain: template.HTML(`<p>The subject is bound directly to the <code>cluster-admin</code> ClusterRole through a ClusterRoleBinding. No chain needed — they are already cluster-admin. The only question is whether the subject itself can be compromised.</p>`),
		Mitre: "T1078 — Valid Accounts",
		AttackerSteps: []AttackerStep{
			{Note: "Enumerate every subject already bound to cluster-admin", Cmd: "kubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects'"},
			{Note: "Compromise any subject in that list — done."},
		},
	},
	"wildcard_permission": {
		Title: "Wildcard verbs × wildcard resources",
		Plain: template.HTML(`<p>An RBAC rule with <code>verbs: ["*"]</code>, <code>resources: ["*"]</code>, and <code>apiGroups: ["*"]</code> is functionally identical to cluster-admin, even if it isn't called that. Often introduced by careless Helm charts or "give it permission to everything until it works" debugging.</p>`),
		Mitre: "T1078 — Valid Accounts",
	},
	"modify_role_binding": {
		Title: "RoleBinding write access",
		Plain: template.HTML(`<p><code>create</code>/<code>update</code>/<code>patch</code> on <code>rolebindings</code> or <code>clusterrolebindings</code> lets the attacker bind themselves to any role — typically cluster-admin. They don't need the role's permissions today, only the ability to change bindings.</p>`),
		Mitre: "T1098 — Account Manipulation",
		AttackerSteps: []AttackerStep{
			{Note: "Append yourself as a subject on an existing high-privilege binding", Cmd: "kubectl patch clusterrolebinding existing-binding --type=json -p='[{\"op\":\"add\",\"path\":\"/subjects/-\",\"value\":{\"kind\":\"ServiceAccount\",\"name\":\"me\",\"namespace\":\"ns\"}}]'"},
		},
	},
	"read_secrets": {
		Title: "Secrets read access",
		Plain: template.HTML(`<p><code>get</code>/<code>list</code>/<code>watch</code> on Secrets in kube-system or cluster-wide reads the controller-manager, scheduler, and node-bootstrap tokens — every credential needed to act as the control plane.</p>`),
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
	"pod_host_escape": {
		Title: "Container escape to host",
		Plain: template.HTML(`<p>The pod is configured in a way that makes escaping to the underlying node trivial: <code>privileged: true</code>, <code>hostPID</code>, <code>hostNetwork</code>, or a sensitive <code>hostPath</code> mount (root, docker.sock, etc.). An attacker who controls the container reaches root on the node, then has access to every pod and kubelet credential on that node.</p>`),
		Mitre: "T1611 — Escape to Host",
		AttackerSteps: []AttackerStep{
			{Note: "From inside the privileged pod, drop into PID 1's namespaces on the host", Cmd: "nsenter -t 1 -m -u -i -n -p -- /bin/sh"},
			{Note: "Steal the kubelet's client cert — the node's identity to the API server", Cmd: "cat /var/lib/kubelet/pki/kubelet-client-current.pem"},
			{Note: "Pivot to other pods on the same node via the container runtime socket", Cmd: "crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps"},
		},
	},
}

// Categories maps a RiskCategory to plain-language explainer copy used on the impact-lane nodes.
var Categories = map[string]CategoryExplainer{
	string(models.CategoryPrivilegeEscalation): {
		Title: "Privilege Escalation",
		Plain: template.HTML(`<p>An identity that started with limited permissions ends up acting as cluster-admin (or <code>system:masters</code>, or the kubelet on a node). Privilege escalation is the gateway impact — every other category becomes possible once an attacker has it.</p>`),
		Examples: []string{
			"A compromised application pod's ServiceAccount mints a cluster-admin token via TokenRequest.",
			"A namespace-admin abuses bind/escalate to grant themselves cluster-admin.",
			"A privileged DaemonSet's pod is exec'd into and the attacker pivots to the node, then to the kubelet's credentials.",
		},
	},
	string(models.CategoryLateralMovement): {
		Title: "Lateral Reach",
		Plain: template.HTML(`<p>The attacker spreads sideways — across namespaces, across nodes, or out of the pod onto cluster-internal services. NetworkPolicy gaps, default-allow service meshes, and over-broad ServiceAccounts in shared namespaces all enable this.</p>`),
		Examples: []string{
			"From a compromised pod, reach the API server, etcd metrics endpoints, or internal databases that have no NetworkPolicy.",
			"hostNetwork pods can sniff or spoof traffic for every other pod on the same node.",
		},
	},
	string(models.CategoryDataExfiltration): {
		Title: "Data Exfiltration",
		Plain: template.HTML(`<p>Reading data the attacker should not see — Secrets, ConfigMap-stored credentials, application data in PersistentVolumes, or audit logs that reveal internal structure.</p>`),
		Examples: []string{
			"Reading every Secret in kube-system to harvest controller credentials.",
			"Mounting a PersistentVolume from a database StatefulSet.",
			"Pulling registry pull-secrets and using them to clone private images.",
		},
	},
	string(models.CategoryInfrastructureModification): {
		Title: "Control Bypass",
		Plain: template.HTML(`<p>The attacker turns off, weakens, or works around the cluster's policy enforcement — admission webhooks, Pod Security admission, OPA/Gatekeeper, or audit configuration. After this, follow-on actions become invisible to defenders.</p>`),
		Examples: []string{
			"Patching a `ValidatingWebhookConfiguration` to `failurePolicy: Ignore`, then deleting the backing service.",
			"Removing a Pod Security label from a namespace to allow privileged pods.",
		},
	},
	string(models.CategoryDefenseEvasion): {
		Title: "Detection Evasion",
		Plain: template.HTML(`<p>The attacker hides their tracks — disabling audit logging, deleting events, rolling back resource versions, or abusing legitimate-looking patterns (impersonation, service accounts) so the activity blends in.</p>`),
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
	case f.RuleID == "KUBE-PRIVESC-001":
		return "pod_create_token_theft"
	case f.RuleID == "KUBE-PRIVESC-004":
		return "pod_exec"
	case f.RuleID == "KUBE-PRIVESC-005":
		return "read_secrets"
	case f.RuleID == "KUBE-PRIVESC-008":
		return "impersonate"
	case f.RuleID == "KUBE-PRIVESC-009":
		return "bind_or_escalate"
	case f.RuleID == "KUBE-PRIVESC-010":
		return "modify_role_binding"
	case f.RuleID == "KUBE-PRIVESC-012":
		return "nodes_proxy"
	case f.RuleID == "KUBE-PRIVESC-014":
		return "token_request"
	case f.RuleID == "KUBE-PRIVESC-017":
		return "wildcard_permission"
	case f.RuleID == "KUBE-RBAC-OVERBROAD-001":
		return "bound_to_cluster_admin"
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
	switch ref.Kind {
	case "Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job",
		"Secret", "ConfigMap", "Namespace",
		"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
		return ref.Kind
	}
	return ""
}
