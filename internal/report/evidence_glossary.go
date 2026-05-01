// Package report — evidence glossary. Static lookup tables that turn opaque cluster
// observations (verb names, host paths, CIDRs, secret types, …) into one-sentence
// "what does this mean and why does it matter" hints rendered next to the raw value
// in the Findings tab. Keep entries terse: the surrounding finding card already carries
// Description / Impact / AttackScenario prose, so this is annotation, not exposition.
package report

import (
	"net"
	"strings"
)

// dangerousVerbs maps RBAC verbs that carry outsized blast radius to a one-line hint.
// Used by the verb chip renderer to flag verbs that aren't merely "broad" but actively
// dangerous. Lowercase keys; verb input is lowercased before lookup.
var dangerousVerbs = map[string]string{
	"impersonate":      "Act as any user, group, or ServiceAccount",
	"escalate":         "Grant rules beyond the caller's own permissions",
	"bind":             "Bind any role to any subject",
	"approve":          "Approve CertificateSigningRequests (issue cluster certs)",
	"sign":             "Sign CertificateSigningRequests (issue cluster certs)",
	"create":           "Create new objects of this resource",
	"delete":           "Permanently remove objects",
	"deletecollection": "Bulk-delete every object of this resource",
	"patch":            "Mutate existing objects in place",
	"update":           "Replace existing objects",
	"*":                "Wildcard: every verb (get, list, create, update, delete, …)",
}

// sensitiveResources flags Kubernetes resources whose access is itself a high-impact
// capability (secrets read = credential theft, pods/exec = remote shell, etc.). Lowercase.
var sensitiveResources = map[string]string{
	"secrets":                         "Holds credentials, tokens, TLS keys",
	"pods/exec":                       "Remote shell into any pod",
	"pods/attach":                     "Attach to a running container's stdio",
	"pods/portforward":                "Tunnel arbitrary TCP into the cluster network",
	"pods":                            "Workload primitive: create = run code on the cluster",
	"nodes/proxy":                     "Direct kubelet access (bypasses API server authz)",
	"clusterroles":                    "Cluster-scoped RBAC rules",
	"clusterrolebindings":             "Cluster-scoped RBAC grants",
	"roles":                           "Namespace-scoped RBAC rules",
	"rolebindings":                    "Namespace-scoped RBAC grants",
	"serviceaccounts":                 "Pod identities (and their tokens)",
	"serviceaccounts/token":           "Mint short-lived ServiceAccount tokens",
	"certificatesigningrequests":      "Issue X.509 certs honored by the API server",
	"validatingwebhookconfigurations": "Admission policy: bypassing it disables enforcement",
	"mutatingwebhookconfigurations":   "Admission policy: controls what enters the cluster",
	"persistentvolumes":               "Cluster-scoped storage that can mount host paths",
	"*":                               "Wildcard: every resource",
}

// sensitiveAPIGroups annotates well-known API groups that carry RBAC-relevant power.
// Empty group ("") is the core API; we render that as "core/v1" and skip the hint.
var sensitiveAPIGroups = map[string]string{
	"rbac.authorization.k8s.io":    "RBAC objects (write access is roughly cluster takeover)",
	"admissionregistration.k8s.io": "Admission webhooks (controls policy enforcement)",
	"certificates.k8s.io":          "Issues cluster-trusted certificates",
	"policy":                       "PodSecurityPolicy / PodDisruptionBudget",
	"*":                            "Wildcard: every API group",
}

// sensitiveHostPathHints annotates host paths whose mount into a container is a
// well-known escape primitive. The lookup tries an exact match first, then walks
// up the path segments so e.g. "/var/run/docker.sock" matches even if scanned
// against "/var/run/docker.sock/". Keys are lowercased and trimmed of trailing slashes.
var sensitiveHostPathHints = map[string]string{
	"/":                                   "Node root filesystem (full host takeover)",
	"/etc":                                "Node config: kubelet/CNI/auth files",
	"/etc/kubernetes":                     "Kubelet kubeconfig & PKI material",
	"/etc/kubernetes/pki":                 "Cluster PKI: root CA private keys",
	"/var":                                "Node persistent state",
	"/var/lib":                            "Persistent state for system daemons",
	"/var/lib/kubelet":                    "Kubelet credentials & pod tokens for every pod on the node",
	"/var/lib/docker":                     "Container engine state (image & layer access)",
	"/var/lib/containerd":                 "Container engine state (image & layer access)",
	"/var/log":                            "Node logs (symlinks let you read other pods' logs)",
	"/var/run":                            "Container runtime sockets live here",
	"/var/run/docker.sock":                "Docker socket (container engine takeover)",
	"/var/run/containerd/containerd.sock": "containerd socket (container engine takeover)",
	"/var/run/crio/crio.sock":             "CRI-O socket (container engine takeover)",
	"/run":                                "Runtime sockets & state",
	"/run/containerd/containerd.sock":     "containerd socket (container engine takeover)",
	"/proc":                               "Host process tree (read /proc/1/root for full FS access)",
	"/sys":                                "Kernel interfaces (cgroup/namespace abuse)",
	"/dev":                                "Host devices (direct disk / kmem access)",
	"/root":                               "Root user home directory",
	"/home":                               "User home directories",
}

// sensitiveCIDRs is checked in order; the first match wins. We keep it ordered so
// the broadest "internet" entries are tried first and noisy private-range hints
// don't shadow more meaningful annotations.
var sensitiveCIDRs = []struct {
	CIDR string
	Note string
}{
	{"0.0.0.0/0", "Entire IPv4 internet: egress here can exfiltrate to any host"},
	{"::/0", "Entire IPv6 internet: egress here can exfiltrate to any host"},
	{"169.254.169.254/32", "Cloud instance metadata service (can mint cloud credentials)"},
	{"169.254.0.0/16", "Link-local range (includes cloud metadata service)"},
	{"10.0.0.0/8", "RFC1918 private range"},
	{"172.16.0.0/12", "RFC1918 private range"},
	{"192.168.0.0/16", "RFC1918 private range"},
	{"127.0.0.0/8", "Loopback"},
}

// secretTypeLabels maps Kubernetes built-in Secret types to a one-line label that
// explains what the secret holds and why it matters. Strings — analyzers emit the
// raw type string, we don't import corev1 just for this.
var secretTypeLabels = map[string]string{
	"Opaque":                              "Generic key/value secret",
	"kubernetes.io/service-account-token": "Long-lived ServiceAccount token (holding it is acting as the SA)",
	"kubernetes.io/dockercfg":             "Docker registry credentials (legacy format)",
	"kubernetes.io/dockerconfigjson":      "Docker registry credentials",
	"kubernetes.io/basic-auth":            "Basic-auth username + password",
	"kubernetes.io/ssh-auth":              "SSH private key",
	"kubernetes.io/tls":                   "TLS certificate + private key",
	"bootstrap.kubernetes.io/token":       "Bootstrap token (joins new nodes to the cluster)",
}

// hostNamespaceHints explains what each pod-level "host*" boolean grants when set.
var hostNamespaceHints = map[string]string{
	"hostNetwork":              "Shares the node's network namespace (sees every pod's traffic, binds to node IPs)",
	"hostPID":                  "Shares the node's process namespace (can ptrace/kill node processes)",
	"hostIPC":                  "Shares the node's IPC namespace (reads other processes' shared memory)",
	"privileged":               "Disables nearly all container isolation (effective root on the node)",
	"allowPrivilegeEscalation": "Lets a child process gain more privileges than its parent",
	"runAsNonRoot":             "When false, the container can run as UID 0",
}

// dangerousImagePatterns describes container image references that warrant a hint —
// mutable tags that defeat reproducibility / supply-chain integrity.
func mutableImageHint(image string) string {
	if image == "" {
		return ""
	}
	// No tag at all → defaults to :latest
	if !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") {
		return "No tag, so pulls :latest, which is mutable"
	}
	if strings.HasSuffix(image, ":latest") {
		return ":latest is mutable: the same tag can resolve to different images over time"
	}
	return ""
}

// hostPathHint returns the explanatory note for a host path, or "" if none.
// Tries an exact match, then walks parent directories upward.
func hostPathHint(path string) string {
	if path == "" {
		return ""
	}
	clean := strings.TrimRight(strings.ToLower(strings.TrimSpace(path)), "/")
	if clean == "" {
		clean = "/"
	}
	if note, ok := sensitiveHostPathHints[clean]; ok {
		return note
	}
	// Walk parent directories: /var/run/docker.sock/foo → /var/run/docker.sock → /var/run → ...
	for {
		idx := strings.LastIndex(clean, "/")
		if idx < 0 {
			return ""
		}
		if idx == 0 {
			if note, ok := sensitiveHostPathHints["/"]; ok {
				return note
			}
			return ""
		}
		clean = clean[:idx]
		if note, ok := sensitiveHostPathHints[clean]; ok {
			return note
		}
	}
}

// cidrHint returns the explanatory note for a CIDR block, or "" if none.
// Matches the input CIDR exactly first, then checks containment for non-universal
// well-known ranges (so 10.5.0.0/16 still hits the 10.0.0.0/8 hint, but 0.0.0.0/0
// only matches an exact 0.0.0.0/0 input).
func cidrHint(cidr string) string {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return ""
	}
	for _, entry := range sensitiveCIDRs {
		if entry.CIDR == cidr {
			return entry.Note
		}
	}
	_, target, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	for _, entry := range sensitiveCIDRs {
		// Skip universal-internet entries — they "contain" every IPv4/IPv6 address,
		// so they'd shadow more specific ranges and produce false positives for
		// any non-matching CIDR.
		if entry.CIDR == "0.0.0.0/0" || entry.CIDR == "::/0" {
			continue
		}
		_, well, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			continue
		}
		if well.Contains(target.IP) {
			targetOnes, _ := target.Mask.Size()
			wellOnes, _ := well.Mask.Size()
			if targetOnes >= wellOnes {
				return entry.Note
			}
		}
	}
	return ""
}

// verbHint returns a one-line meaning for a known dangerous verb (case-insensitive).
func verbHint(verb string) string {
	return dangerousVerbs[strings.ToLower(strings.TrimSpace(verb))]
}

// resourceHint returns a one-line meaning for a known sensitive resource (case-insensitive).
func resourceHint(resource string) string {
	return sensitiveResources[strings.ToLower(strings.TrimSpace(resource))]
}

// apiGroupHint returns the meaning of a known sensitive API group; "" core group is
// labelled separately by the renderer.
func apiGroupHint(group string) string {
	return sensitiveAPIGroups[strings.TrimSpace(group)]
}

// secretTypeLabel returns the friendly label for a Kubernetes Secret type, or the
// raw type if unknown.
func secretTypeLabel(t string) string {
	if label, ok := secretTypeLabels[t]; ok {
		return label
	}
	return t
}

// hostNamespaceHint returns the explanatory note for a pod-level host* boolean field.
func hostNamespaceHint(key string) string {
	return hostNamespaceHints[key]
}
