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
)

// EscalationGraph is the directed privilege-escalation graph: subject nodes, sink nodes, and labeled edges.
type EscalationGraph struct {
	Nodes map[string]*EscalationNode `json:"nodes"`
	Edges []*EscalationEdge          `json:"edges"`
}

// EscalationNode represents either a subject (with Subject populated) or a terminal sink (IsSink=true) in the graph.
type EscalationNode struct {
	ID              string           `json:"id"`
	Subject         SubjectRef       `json:"subject,omitempty"`
	IsSystem        bool             `json:"is_system,omitempty"` // built-in control-plane subjects; not traversed during path search
	IsSink          bool             `json:"is_sink,omitempty"`
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
}

// EscalationPath is one source → sink chain returned by path search, with each hop annotated.
type EscalationPath struct {
	Source          SubjectRef       `json:"source"`
	Target          EscalationTarget `json:"target"`
	TargetNamespace string           `json:"target_namespace,omitempty"` // populated only when Target == TargetNamespaceAdmin
	Hops            []EscalationHop  `json:"hops"`
}
