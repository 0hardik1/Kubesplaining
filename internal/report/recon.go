// Package report — top-of-report reconnaissance panel data builder. The panel
// surfaces pentester-relevant snapshot facts at the top of the HTML report so a
// reader can grasp blast radius, who already owns the cluster, what is exposed,
// and what guardrails are missing before scrolling to the Findings tab.
//
// Everything here is derived from a Snapshot at render time — adding or removing
// rows is a report-layer concern only, no collector or model change required.
package report

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Recon is the rendered cluster-reconnaissance panel: a four-section view plus a
// nested provenance section, with a row of headline chips shown on the closed
// disclosure summary so even the collapsed state hints at what's inside.
type Recon struct {
	Shape         ReconShape
	Ownership     ReconOwnership
	Surface       ReconSurface
	Guardrails    ReconGuardrails
	Provenance    ReconProvenance
	HeadlineChips []ReconChip
}

// ReconShape — "where am I, how big is it" facts.
type ReconShape struct {
	Distribution    string // "EKS v1.28.5" | "v1.28.5" | ""
	CloudLabel      string // "AWS / us-east-1" | "On-prem / unknown"
	NodeCount       int
	ArchBreakdown   string   // "10×amd64, 2×arm64"
	OSImage         string   // most common Status.NodeInfo.OSImage
	KubeletVersions []string // distinct, "vX.Y.Z ×N" rows (sorted descending by count)
	RuntimeVersions []string // same shape for ContainerRuntimeVersion
	NamespaceCount  int
	PodCount        int
	SACount         int
	APIHost         string // host portion of APIServerURL
	APIReachability string // "private" | "public" | "loopback" | "linklocal" | "unknown"
}

// ReconOwnership — who already owns the cluster.
type ReconOwnership struct {
	ClusterAdmins        ReconSubjectList
	WildcardVerbSubjects ReconSubjectList
	SecretReaders        ReconSubjectList
	PrivescToAdminCount  int
	PrivescToAdminAnchor string // "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN" or ""
	NodeEscapeCount      int
	NodeEscapeAnchor     string
}

// ReconSurface — what an outside scanner sees.
type ReconSurface struct {
	LoadBalancers        ReconResourceList
	NodePorts            int
	ExternalIPs          int
	HostNetworkPods      ReconResourceList
	PrivilegedPods       ReconResourceList
	MutatingWebhooks     int
	OutOfClusterWebhooks int
}

// ReconGuardrails — what is/isn't protecting the cluster.
type ReconGuardrails struct {
	NetworkPolicies       int
	NamespacesProtected   int
	NamespacesUnprotected int
	PSAEnforce            map[string]int // mode → namespace count (e.g. "restricted" → 4)
	Engines               []string       // "Kyverno", "Gatekeeper", "VAP"
	DefaultSATokenMounts  int
}

// ReconProvenance — collection-time meta. Tucked behind a nested disclosure since
// it's operational metadata rather than a recon "wow" fact.
type ReconProvenance struct {
	CollectorIdentity     string
	PermissionsAvailable  []string
	PermissionsMissing    []string
	CollectionWarnings    []string
	NamespacesScanned     []string
	CollectionDurationSec float64
}

// ReconSubjectList is the count + sample-of-three pattern for RBAC subjects.
type ReconSubjectList struct {
	Total     int
	Sample    []string // up to 3 "Kind/[Namespace/]Name" labels, sorted alphabetically
	MoreCount int      // Total - len(Sample); zero when nothing was elided
	Anchor    string   // optional Findings-tab deep link
}

// ReconResourceList is the parallel pattern for Pod/Service object samples.
type ReconResourceList struct {
	Total     int
	Sample    []string // up to 3 "namespace/name" labels
	MoreCount int
}

// ReconChip is a small headline pill rendered in the collapsed disclosure summary.
// Tone is "ok" | "warn" | "danger"; the template maps each to a CSS class.
type ReconChip struct {
	Label string
	Value string
	Tone  string
}

// buildRecon aggregates a snapshot into a Recon panel. Safe on empty inputs —
// nil maps/slices are returned unmodified so the template can range over them.
func buildRecon(
	snapshot models.Snapshot,
	findings []models.Finding,
	subjects map[string]*permissions.EffectivePermissions,
) Recon {
	r := Recon{
		Shape:      buildReconShape(snapshot),
		Ownership:  buildReconOwnership(snapshot, findings, subjects),
		Surface:    buildReconSurface(snapshot),
		Guardrails: buildReconGuardrails(snapshot),
		Provenance: buildReconProvenance(snapshot),
	}
	r.HeadlineChips = buildHeadlineChips(r)
	return r
}

func buildReconShape(s models.Snapshot) ReconShape {
	shape := ReconShape{
		NamespaceCount: len(s.Resources.Namespaces),
		PodCount:       len(s.Resources.Pods),
		SACount:        len(s.Resources.ServiceAccounts),
		NodeCount:      len(s.Resources.Nodes),
		CloudLabel:     "On-prem / unknown",
	}

	clusterVersion := strings.TrimSpace(s.Metadata.ClusterVersion)
	var firstKubelet string
	if len(s.Resources.Nodes) > 0 {
		firstKubelet = s.Resources.Nodes[0].Status.NodeInfo.KubeletVersion
	}
	shape.Distribution = distroFromVersion(clusterVersion, firstKubelet)

	if cloud := strings.TrimSpace(s.Metadata.CloudProvider); cloud != "" && !strings.EqualFold(cloud, "none") {
		region := mostCommonNodeLabel(s.Resources.Nodes, "topology.kubernetes.io/region")
		if region != "" {
			shape.CloudLabel = strings.ToUpper(cloud) + " / " + region
		} else {
			shape.CloudLabel = strings.ToUpper(cloud)
		}
	} else if c := cloudFromNodes(s.Resources.Nodes); c != "" {
		shape.CloudLabel = c
	}

	shape.ArchBreakdown = nodeArchBreakdown(s.Resources.Nodes)
	shape.OSImage = mostCommonOSImage(s.Resources.Nodes)
	shape.KubeletVersions = nodeFieldHistogram(s.Resources.Nodes, func(n corev1.Node) string {
		return n.Status.NodeInfo.KubeletVersion
	})
	shape.RuntimeVersions = nodeFieldHistogram(s.Resources.Nodes, func(n corev1.Node) string {
		return n.Status.NodeInfo.ContainerRuntimeVersion
	})

	shape.APIHost, shape.APIReachability = apiReachability(s.Metadata.APIServerURL)
	return shape
}

// distroFromVersion sniffs managed-Kubernetes flavour suffixes (-eks, -gke, -aks)
// in the cluster + kubelet version strings, falling back to the cluster version
// alone when no flavour signature is found.
func distroFromVersion(clusterVersion, kubeletVersion string) string {
	v := strings.TrimSpace(clusterVersion)
	if v == "" {
		v = strings.TrimSpace(kubeletVersion)
	}
	if v == "" {
		return ""
	}
	merged := strings.ToLower(clusterVersion + " " + kubeletVersion)
	switch {
	case strings.Contains(merged, "-eks") || strings.Contains(merged, "+eks"):
		return "EKS " + v
	case strings.Contains(merged, "-gke") || strings.Contains(merged, "+gke"):
		return "GKE " + v
	case strings.Contains(merged, "-aks") || strings.Contains(merged, "+aks"):
		return "AKS " + v
	}
	return v
}

// cloudFromNodes infers a cloud-provider label from the first node's ProviderID
// scheme combined with the most common topology.kubernetes.io/region label.
func cloudFromNodes(nodes []corev1.Node) string {
	if len(nodes) == 0 {
		return ""
	}
	provider := ""
	for _, n := range nodes {
		if pid := n.Spec.ProviderID; pid != "" {
			if i := strings.Index(pid, ":"); i > 0 {
				provider = strings.ToUpper(pid[:i])
				break
			}
		}
	}
	region := mostCommonNodeLabel(nodes, "topology.kubernetes.io/region")
	switch {
	case provider != "" && region != "":
		return provider + " / " + region
	case provider != "":
		return provider
	case region != "":
		return region
	}
	return ""
}

func mostCommonNodeLabel(nodes []corev1.Node, key string) string {
	counts := map[string]int{}
	for _, n := range nodes {
		if v := n.Labels[key]; v != "" {
			counts[v]++
		}
	}
	return mostCommonKey(counts)
}

// mostCommonKey returns the highest-count key with an alphabetical tiebreak so
// repeated calls on the same input return a stable result.
func mostCommonKey(m map[string]int) string {
	best := ""
	bestN := 0
	for k, n := range m {
		if n > bestN || (n == bestN && (best == "" || k < best)) {
			best, bestN = k, n
		}
	}
	return best
}

func nodeArchBreakdown(nodes []corev1.Node) string {
	if len(nodes) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, n := range nodes {
		arch := strings.TrimSpace(n.Status.NodeInfo.Architecture)
		if arch == "" {
			arch = "unknown"
		}
		counts[arch]++
	}
	keys := sortedKeysByCount(counts)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d×%s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}

func mostCommonOSImage(nodes []corev1.Node) string {
	counts := map[string]int{}
	for _, n := range nodes {
		img := strings.TrimSpace(n.Status.NodeInfo.OSImage)
		if img != "" {
			counts[img]++
		}
	}
	return mostCommonKey(counts)
}

func nodeFieldHistogram(nodes []corev1.Node, get func(corev1.Node) string) []string {
	if len(nodes) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, n := range nodes {
		v := strings.TrimSpace(get(n))
		if v != "" {
			counts[v]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	keys := sortedKeysByCount(counts)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s ×%d", k, counts[k]))
	}
	return out
}

// sortedKeysByCount sorts map keys by descending count, alphabetical tiebreak.
func sortedKeysByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// apiReachability classifies the API-server host as private/public/loopback/linklocal
// based on a literal IP. DNS names yield "unknown" — we never resolve, by design.
func apiReachability(rawURL string) (host, label string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "unknown"
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, "unknown"
	}
	host = u.Hostname()
	if host == "" {
		return rawURL, "unknown"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host, "unknown"
	}
	switch {
	case ip.IsLoopback():
		return host, "loopback"
	case ip.IsLinkLocalUnicast():
		return host, "linklocal"
	case ip.IsPrivate():
		return host, "private"
	default:
		return host, "public"
	}
}

func buildReconOwnership(s models.Snapshot, findings []models.Finding, subjects map[string]*permissions.EffectivePermissions) ReconOwnership {
	o := ReconOwnership{}
	o.ClusterAdmins = collectClusterAdmins(s.Resources.ClusterRoleBindings)
	o.WildcardVerbSubjects = collectWildcardVerbSubjects(subjects)
	o.SecretReaders = collectSecretReaders(subjects)

	for _, f := range findings {
		switch f.RuleID {
		case "KUBE-PRIVESC-PATH-CLUSTER-ADMIN":
			o.PrivescToAdminCount++
			if o.PrivescToAdminAnchor == "" {
				o.PrivescToAdminAnchor = "finding-" + f.RuleID
			}
		case "KUBE-PRIVESC-PATH-NODE-ESCAPE":
			o.NodeEscapeCount++
			if o.NodeEscapeAnchor == "" {
				o.NodeEscapeAnchor = "finding-" + f.RuleID
			}
		}
	}
	return o
}

// collectClusterAdmins walks ClusterRoleBindings for refs to the well-known
// `cluster-admin` ClusterRole and emits the bound subjects. The canonical
// `system:masters` group is filtered out — it's the bootstrap binding present
// on every cluster, and surfacing it would dominate the list with a single
// line of meaningless "every cluster has this" noise.
func collectClusterAdmins(bindings []rbacv1.ClusterRoleBinding) ReconSubjectList {
	names := []string{}
	for _, b := range bindings {
		if b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, sub := range b.Subjects {
			if sub.Kind == "Group" && sub.Name == "system:masters" {
				continue
			}
			ref := models.SubjectRef{Kind: sub.Kind, Name: sub.Name, Namespace: sub.Namespace}
			names = append(names, ref.Key())
		}
	}
	return makeSubjectList(names, "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN")
}

func collectWildcardVerbSubjects(subjects map[string]*permissions.EffectivePermissions) ReconSubjectList {
	keys := []string{}
	for key, perm := range subjects {
		if hasWildcardEffective(perm.Rules) {
			keys = append(keys, key)
		}
	}
	return makeSubjectList(keys, "")
}

// hasWildcardEffective flags subjects whose effective rules wildcard verbs against
// a non-trivial resource/apiGroup footprint. Rules that wildcard verbs against a
// single named resource are excluded — "secrets get/list/watch" already lights up
// SecretReaders without inflating the wildcard count.
func hasWildcardEffective(rules []permissions.EffectiveRule) bool {
	for _, r := range rules {
		if !sliceContains(r.Verbs, "*") {
			continue
		}
		if sliceContains(r.Resources, "*") || sliceContains(r.APIGroups, "*") || len(r.Resources) >= 3 {
			return true
		}
	}
	return false
}

func collectSecretReaders(subjects map[string]*permissions.EffectivePermissions) ReconSubjectList {
	keys := []string{}
	for key, perm := range subjects {
		if grantsSecretRead(perm.Rules) {
			keys = append(keys, key)
		}
	}
	return makeSubjectList(keys, "")
}

func grantsSecretRead(rules []permissions.EffectiveRule) bool {
	for _, r := range rules {
		if !(sliceContains(r.Resources, "secrets") || sliceContains(r.Resources, "*")) {
			continue
		}
		if !(sliceContains(r.APIGroups, "") || sliceContains(r.APIGroups, "*")) {
			continue
		}
		if sliceContains(r.Verbs, "*") || sliceContains(r.Verbs, "get") || sliceContains(r.Verbs, "list") || sliceContains(r.Verbs, "watch") {
			return true
		}
	}
	return false
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func makeSubjectList(keys []string, anchor string) ReconSubjectList {
	uniq := uniqueSorted(keys)
	if len(uniq) == 0 {
		return ReconSubjectList{Anchor: anchor}
	}
	sample := uniq
	if len(sample) > 3 {
		sample = sample[:3]
	}
	return ReconSubjectList{
		Total:     len(uniq),
		Sample:    append([]string(nil), sample...),
		MoreCount: len(uniq) - len(sample),
		Anchor:    anchor,
	}
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func buildReconSurface(s models.Snapshot) ReconSurface {
	sf := ReconSurface{}
	lbNames := []string{}
	for _, svc := range s.Resources.Services {
		switch svc.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			lbNames = append(lbNames, svc.Namespace+"/"+svc.Name)
		case corev1.ServiceTypeNodePort:
			sf.NodePorts++
		}
		if len(svc.Spec.ExternalIPs) > 0 {
			sf.ExternalIPs++
		}
	}
	sf.LoadBalancers = makeResourceList(lbNames)

	hostNet := []string{}
	priv := []string{}
	for _, p := range s.Resources.Pods {
		if p.Spec.HostNetwork {
			hostNet = append(hostNet, p.Namespace+"/"+p.Name)
		}
		if podHasPrivilegedContainer(p) {
			priv = append(priv, p.Namespace+"/"+p.Name)
		}
	}
	sf.HostNetworkPods = makeResourceList(hostNet)
	sf.PrivilegedPods = makeResourceList(priv)

	sf.MutatingWebhooks = len(s.Resources.MutatingWebhookConfigs)
	for _, m := range s.Resources.MutatingWebhookConfigs {
		for _, w := range m.Webhooks {
			if w.ClientConfig.URL != nil && *w.ClientConfig.URL != "" {
				sf.OutOfClusterWebhooks++
				break
			}
		}
	}
	return sf
}

func podHasPrivilegedContainer(p corev1.Pod) bool {
	if containerListIsPrivileged(p.Spec.Containers) {
		return true
	}
	return containerListIsPrivileged(p.Spec.InitContainers)
}

func containerListIsPrivileged(containers []corev1.Container) bool {
	for _, c := range containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

func makeResourceList(items []string) ReconResourceList {
	uniq := uniqueSorted(items)
	if len(uniq) == 0 {
		return ReconResourceList{}
	}
	sample := uniq
	if len(sample) > 3 {
		sample = sample[:3]
	}
	return ReconResourceList{
		Total:     len(uniq),
		Sample:    append([]string(nil), sample...),
		MoreCount: len(uniq) - len(sample),
	}
}

func buildReconGuardrails(s models.Snapshot) ReconGuardrails {
	g := ReconGuardrails{
		NetworkPolicies: len(s.Resources.NetworkPolicies),
		PSAEnforce:      map[string]int{},
	}

	npByNamespace := map[string]bool{}
	for _, np := range s.Resources.NetworkPolicies {
		npByNamespace[np.Namespace] = true
	}
	g.NamespacesProtected = len(npByNamespace)

	podByNamespace := map[string]bool{}
	for _, p := range s.Resources.Pods {
		if p.Namespace != "" {
			podByNamespace[p.Namespace] = true
		}
	}
	for ns := range podByNamespace {
		if !npByNamespace[ns] {
			g.NamespacesUnprotected++
		}
	}

	for _, ns := range s.Resources.Namespaces {
		if mode := strings.TrimSpace(ns.Labels["pod-security.kubernetes.io/enforce"]); mode != "" {
			g.PSAEnforce[mode]++
		}
	}

	if len(s.Resources.KyvernoClusterPolicies)+len(s.Resources.KyvernoPolicies) > 0 {
		g.Engines = append(g.Engines, "Kyverno")
	}
	if len(s.Resources.GatekeeperConstraintTemplates) > 0 {
		g.Engines = append(g.Engines, "Gatekeeper")
	}
	if len(s.Resources.ValidatingAdmissionPolicies) > 0 {
		g.Engines = append(g.Engines, "VAP")
	}

	for _, p := range s.Resources.Pods {
		sa := p.Spec.ServiceAccountName
		if sa != "" && sa != "default" {
			continue
		}
		// AutomountServiceAccountToken == nil means the apiserver default applies (true).
		if p.Spec.AutomountServiceAccountToken != nil && !*p.Spec.AutomountServiceAccountToken {
			continue
		}
		g.DefaultSATokenMounts++
	}
	return g
}

func buildReconProvenance(s models.Snapshot) ReconProvenance {
	return ReconProvenance{
		CollectorIdentity:     s.Metadata.CollectorIdentity,
		PermissionsAvailable:  append([]string(nil), s.Metadata.PermissionsAvailable...),
		PermissionsMissing:    append([]string(nil), s.Metadata.PermissionsMissing...),
		CollectionWarnings:    append([]string(nil), s.Metadata.CollectionWarnings...),
		NamespacesScanned:     append([]string(nil), s.Metadata.NamespacesScanned...),
		CollectionDurationSec: s.Metadata.CollectionDurationSecond,
	}
}

// buildHeadlineChips picks the four numbers that best tell the story at a glance:
// node count (size), cluster-admin holders (compromise blast radius),
// LoadBalancers (external attack surface), and NetworkPolicies (lateral-movement
// containment). Each tone reflects whether the count is alarming for a pentester.
func buildHeadlineChips(r Recon) []ReconChip {
	return []ReconChip{
		{
			Label: pluralizeSimple(r.Shape.NodeCount, "node", "nodes"),
			Value: strconv.Itoa(r.Shape.NodeCount),
			Tone:  toneIf(r.Shape.NodeCount == 0, "warn", "ok"),
		},
		{
			Label: pluralizeSimple(r.Ownership.ClusterAdmins.Total, "cluster-admin", "cluster-admins"),
			Value: strconv.Itoa(r.Ownership.ClusterAdmins.Total),
			Tone:  toneIf(r.Ownership.ClusterAdmins.Total > 0, "danger", "ok"),
		},
		{
			Label: pluralizeSimple(r.Surface.LoadBalancers.Total, "LoadBalancer", "LoadBalancers"),
			Value: strconv.Itoa(r.Surface.LoadBalancers.Total),
			Tone:  toneIf(r.Surface.LoadBalancers.Total > 0, "warn", "ok"),
		},
		{
			Label: pluralizeSimple(r.Guardrails.NetworkPolicies, "NetworkPolicy", "NetworkPolicies"),
			Value: strconv.Itoa(r.Guardrails.NetworkPolicies),
			Tone:  toneIf(r.Guardrails.NetworkPolicies == 0, "danger", "ok"),
		},
	}
}

func toneIf(condition bool, ifTrue, ifFalse string) string {
	if condition {
		return ifTrue
	}
	return ifFalse
}
