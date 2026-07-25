package models

// EscalationTarget enumerates the high-value "sinks" the privesc module searches for paths to.
type EscalationTarget string

const (
	TargetClusterAdmin      EscalationTarget = "cluster_admin_equivalent"
	TargetKubeSystemSecrets EscalationTarget = "kube_system_secrets"
	TargetNamespaceAdmin    EscalationTarget = "namespace_admin"
	TargetNodeEscape        EscalationTarget = "node_escape"
	TargetSystemMasters     EscalationTarget = "system_masters"
	TargetTokenMint         EscalationTarget = "token_mint"
	TargetAWSIAMRole        EscalationTarget = "aws_iam_role"
)

// EscalationGraph is the directed privilege-escalation graph: subject nodes, sink nodes, and labeled edges.
type EscalationGraph struct {
	Nodes map[string]*EscalationNode `json:"nodes"`
	Edges []*EscalationEdge          `json:"edges"`
}

// EscalationNode represents either a subject (with Subject populated) or a terminal sink (IsSink=true) in the graph.
type EscalationNode struct {
	ID       string     `json:"id"`
	Subject  SubjectRef `json:"subject,omitempty"`
	IsSystem bool       `json:"is_system,omitempty"` // built-in control-plane subjects; not traversed during path search
	// IsControlPlane marks a non-built-in ServiceAccount living in a control-plane
	// namespace (kube-system, kube-public, kube-node-lease). Unlike IsSystem these
	// ARE traversed as chain intermediates, because a co-located controller SA is
	// exactly what a real escalation launders through. They are still never seeded
	// as path-search sources, which would report the control plane escalating to itself.
	IsControlPlane bool `json:"is_control_plane,omitempty"`
	// external (non-Kubernetes) subject such as a cloud IAM role; not seeded as a BFS source this slot
	IsExternal bool `json:"is_external,omitempty"`
	IsSink     bool `json:"is_sink,omitempty"`
	// Traversable marks a sink that path search should keep walking past rather
	// than halting on. A traversable sink still produces its own path finding; it
	// additionally lets longer chains run through it (namespace-admin implying
	// token theft in that namespace, node-root implying control-plane PKI theft,
	// an external cloud identity implying a return route into the cluster).
	Traversable     bool             `json:"traversable,omitempty"`
	Target          EscalationTarget `json:"target,omitempty"`           // set only when IsSink is true
	TargetNamespace string           `json:"target_namespace,omitempty"` // populated only when Target == TargetNamespaceAdmin to identify which namespace the sink represents
}

// EscalationEdge is a directed labeled edge describing how one subject can obtain another subject's identity or reach a sink.
type EscalationEdge struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	Technique   string  `json:"technique"`            // stable technique identifier, e.g. "KUBE-PRIVESC-001"
	Action      string  `json:"action"`               // short machine-friendly action label
	Permission  string  `json:"permission,omitempty"` // RBAC permission or condition that enables this edge
	Description string  `json:"description"`          // human-readable one-liner
	Score       float64 `json:"score,omitempty"`
	// Difficulty rates how much has to go right for an attacker to walk this edge:
	// "easy" (holding the RBAC grant is the whole exploit), "moderate" (needs a
	// workload to exist, be created, or land somewhere specific), "hard" (needs
	// attacker-controlled infrastructure or a timing window). Path scoring sums
	// these rather than penalizing raw hop count, so a long chain of trivial grants
	// outranks a short chain that needs a race.
	Difficulty string `json:"difficulty,omitempty"`
	// SourceBinding, SourceRole, and BindingNamespace record which (Cluster)RoleBinding
	// and (Cluster)Role granted the RBAC rule that justified this edge. Remediation uses
	// them to cut the binding that actually enabled the hop rather than the first binding
	// listing the subject, and path search uses them to model what removing that binding
	// would do (see pathfinder.go's cut-resilient pass).
	//
	// All three are empty for synthetic edges that no single binding grants: pod escapes,
	// the node-escape continuation, the namespace-admin token-theft fan-out, and cloud
	// identity edges. An empty BindingNamespace on a populated SourceBinding means a
	// ClusterRoleBinding, matching how permissions.Aggregate builds the rule.
	SourceBinding    string `json:"source_binding,omitempty"`
	SourceRole       string `json:"source_role,omitempty"`
	BindingNamespace string `json:"binding_namespace,omitempty"`
}

// EscalationPath is one source → sink chain returned by path search, with each hop annotated.
type EscalationPath struct {
	Source          SubjectRef       `json:"source"`
	Target          EscalationTarget `json:"target"`
	TargetNamespace string           `json:"target_namespace,omitempty"` // populated only when Target == TargetNamespaceAdmin
	Hops            []EscalationHop  `json:"hops"`
	// AlternateHops is a route to the same Target that survives cutting the binding
	// named by Hops[0]. Non-empty means the obvious remediation is not sufficient on
	// its own. Empty means either that no such route exists, or that Hops[0] is a
	// synthetic edge with no binding to model cutting.
	AlternateHops []EscalationHop `json:"alternate_hops,omitempty"`
}
