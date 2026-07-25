package privesc

import (
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// pathStep is one edge traversal during BFS: the node we entered and the edge we used to reach it.
type pathStep struct {
	nodeID string
	edge   *models.EscalationEdge
}

// FindPaths runs shortest-path BFS from every non-system subject node to any sink, up to maxDepth hops, and returns
// one EscalationPath per (source, sink) pair sorted by source key, target, then hop count.
//
// A returned path may also carry AlternateHops: a second route to the same sink that survives cutting the binding named
// by its first hop, i.e. the fix remediation prints. Non-empty means that fix does not close the route on its own.
// See alternatesForSource. Alternates attach as a field, never as extra returned paths.
func FindPaths(graph *models.EscalationGraph, maxDepth int) []models.EscalationPath {
	adj := map[string][]*models.EscalationEdge{}
	for _, edge := range graph.Edges {
		adj[edge.From] = append(adj[edge.From], edge)
	}

	var sources []string
	for id, node := range graph.Nodes {
		if node.IsSink || node.IsSystem {
			continue
		}
		// External (cloud-IAM) subjects are added by Unit 4 as terminal-ish
		// nodes reachable from cluster ServiceAccounts via IRSA edges; they
		// must never be seeded as BFS sources or every external identity in
		// aws-auth would generate spurious "external -> sink" paths.
		if node.IsExternal {
			continue
		}
		// Control-plane controller SAs are traversable intermediates (see
		// models.EscalationNode.IsControlPlane) but seeding them as sources would
		// report the control plane escalating to itself on every cluster.
		if node.IsControlPlane {
			continue
		}
		sources = append(sources, id)
	}
	sort.Strings(sources)

	var paths []models.EscalationPath
	for _, sourceID := range sources {
		sourceNode := graph.Nodes[sourceID]
		if sourceNode == nil {
			continue
		}
		found := bfsToSinks(graph, adj, sourceID, maxDepth, nil)
		alternates := alternatesForSource(graph, adj, sourceID, maxDepth, found)
		for targetID, chain := range found {
			targetNode := graph.Nodes[targetID]
			path := buildPath(graph, sourceNode.Subject, targetNode.Target, chain)
			path.TargetNamespace = targetNode.TargetNamespace
			path.TargetID = targetID
			if alt, ok := alternates[targetID]; ok {
				path.AlternateHops = buildPath(graph, sourceNode.Subject, targetNode.Target, alt).Hops
			}
			paths = append(paths, path)
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Source.Key() != paths[j].Source.Key() {
			return paths[i].Source.Key() < paths[j].Source.Key()
		}
		if paths[i].Target != paths[j].Target {
			return paths[i].Target < paths[j].Target
		}
		if paths[i].TargetNamespace != paths[j].TargetNamespace {
			return paths[i].TargetNamespace < paths[j].TargetNamespace
		}
		if len(paths[i].Hops) != len(paths[j].Hops) {
			return len(paths[i].Hops) < len(paths[j].Hops)
		}
		// Final tiebreak: TargetID is the graph node ID, unique per sink node even
		// when several nodes share one Target enum and TargetNamespace, which every
		// external AWS IAM role does (one graph node per ARN, but Target is always
		// TargetAWSIAMRole and TargetNamespace is always empty). Without this, two
		// same-length paths to two different IAM roles tie on every key above, and
		// sort.Slice is documented unstable: it is fed by the "for targetID, chain
		// := range found" map above, so without a total order the tied elements'
		// relative order depends on map iteration, which Go re-randomizes per run.
		return paths[i].TargetID < paths[j].TargetID
	})

	return paths
}

// bfsToSinks walks the graph from sourceID and returns, for each reachable sink, the shortest step chain that got there.
// System subjects (e.g. system:masters) are treated as non-traversable intermediates but still valid as sinks via explicit edges.
// banned, when non-nil, removes edges from consideration: the cut-resilient pass uses it to ask what stays reachable once a
// given binding is revoked. Passing nil bans nothing.
func bfsToSinks(
	graph *models.EscalationGraph,
	adj map[string][]*models.EscalationEdge,
	sourceID string,
	maxDepth int,
	banned func(*models.EscalationEdge) bool,
) map[string][]pathStep {
	type queueItem struct {
		nodeID string
		path   []pathStep
	}

	visited := map[string]int{sourceID: 0}
	queue := []queueItem{{nodeID: sourceID}}
	sinks := map[string][]pathStep{}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if len(item.path) >= maxDepth {
			continue
		}
		for _, edge := range adj[item.nodeID] {
			if banned != nil && banned(edge) {
				continue
			}
			neighbor := graph.Nodes[edge.To]
			if neighbor == nil {
				continue
			}
			nextDepth := len(item.path) + 1
			if prev, ok := visited[edge.To]; ok && prev <= nextDepth {
				continue
			}
			visited[edge.To] = nextDepth
			nextPath := make([]pathStep, len(item.path)+1)
			copy(nextPath, item.path)
			nextPath[len(item.path)] = pathStep{nodeID: edge.To, edge: edge}

			if neighbor.IsSink {
				// First arrival is the shortest: the visited prune above rejects every
				// later one, so this assignment happens at most once per sink.
				sinks[edge.To] = nextPath
				// A traversable sink records its own path and is then walked past,
				// so richer chains routed through it are captured as separate,
				// longer paths. External cloud-IAM nodes carry outbound aws-auth
				// edges; namespace-admin implies token theft in that namespace;
				// node-root on a control-plane node implies PKI theft. Sinks that
				// are not traversable have no outbound edges by construction.
				if !neighbor.Traversable {
					continue
				}
			}

			if neighbor.IsSystem {
				continue
			}

			queue = append(queue, queueItem{nodeID: edge.To, path: nextPath})
		}
	}

	return sinks
}

// cutKey identifies a (Cluster)RoleBinding whose removal we want to model. An empty
// namespace means a ClusterRoleBinding, matching permissions.EffectiveRule.
type cutKey struct {
	binding   string
	namespace string
}

// edgeCut returns the binding an edge came from. The false return covers synthetic
// edges (pod escape, node-escape continuation, namespace-admin fan-out, cloud
// identity) that no single binding grants, so there is nothing to model cutting.
func edgeCut(edge *models.EscalationEdge) (cutKey, bool) {
	if edge == nil || edge.SourceBinding == "" {
		return cutKey{}, false
	}
	return cutKey{binding: edge.SourceBinding, namespace: edge.BindingNamespace}, true
}

// edgeBrokenBy reports whether removing the subject from the binding named by key
// would break edge. That is true either when key is the single binding that
// granted the edge (edgeCut), or when key appears in the edge's CutBreakers: a
// two-rule correlation edge (see addSecretMintEdge, addNodeMigrateEdge,
// finalizeCSRApprovals) that
// carries no single granting binding but whose key IS the sole grantor of one of
// the two required halves, so cutting it un-grants that half and the correlation
// no longer holds.
func edgeBrokenBy(edge *models.EscalationEdge, key cutKey) bool {
	if k, ok := edgeCut(edge); ok && k == key {
		return true
	}
	for _, breaker := range edge.CutBreakers {
		if (cutKey{binding: breaker.Name, namespace: breaker.Namespace}) == key {
			return true
		}
	}
	return false
}

// alternatesForSource returns, per reachable sink, a chain that survives cutting the
// binding named by that sink's own first hop.
//
// Removing a subject from a binding revokes every capability that binding conferred
// on THAT subject and nothing else, so the banned set is scoped to edges leaving the
// source node. Edges elsewhere in the graph are untouched.
//
// One BFS runs per distinct first-hop binding, not one per path, because a single
// banned run reports every sink still reachable. Each path then reads only the run
// for its OWN first hop: a source reaching cluster-admin via binding A and node-escape
// via binding B gets two runs, and reading run A's node-escape result would answer a
// question nobody asked, since cutting A was never the proposed fix for that path.
func alternatesForSource(
	graph *models.EscalationGraph,
	adj map[string][]*models.EscalationEdge,
	sourceID string,
	maxDepth int,
	primary map[string][]pathStep,
) map[string][]pathStep {
	targetsByCut := map[cutKey][]string{}
	for targetID, chain := range primary {
		if len(chain) == 0 {
			continue
		}
		if key, ok := edgeCut(chain[0].edge); ok {
			targetsByCut[key] = append(targetsByCut[key], targetID)
		}
	}
	if len(targetsByCut) == 0 {
		return nil
	}

	alternates := map[string][]pathStep{}
	for key, targetIDs := range targetsByCut {
		banned := func(edge *models.EscalationEdge) bool {
			if edge.From != sourceID {
				return false
			}
			return edgeBrokenBy(edge, key)
		}
		surviving := bfsToSinks(graph, adj, sourceID, maxDepth, banned)
		for _, targetID := range targetIDs {
			if chain, ok := surviving[targetID]; ok && len(chain) > 0 {
				alternates[targetID] = chain
			}
		}
	}
	return alternates
}

// buildPath materializes the BFS chain into an EscalationPath, numbering hops and threading the evolving "current" subject.
func buildPath(graph *models.EscalationGraph, source models.SubjectRef, target models.EscalationTarget, chain []pathStep) models.EscalationPath {
	hops := make([]models.EscalationHop, 0, len(chain))
	current := source
	for i, step := range chain {
		var next models.SubjectRef
		// External (cloud-IAM) nodes are sinks-with-a-Subject: the ARN itself is
		// the meaningful "ToSubject" for the hop, unlike the synthetic outcome
		// sinks (sinkClusterAdmin, sinkSystemMasters, ...) whose Subject is empty.
		if node, ok := graph.Nodes[step.nodeID]; ok && (!node.IsSink || node.IsExternal) {
			next = node.Subject
		}
		hops = append(hops, models.EscalationHop{
			Step:             i + 1,
			Action:           step.edge.Action,
			Technique:        step.edge.Technique,
			Difficulty:       step.edge.Difficulty,
			FromSubject:      current,
			ToSubject:        next,
			Permission:       step.edge.Permission,
			Gains:            step.edge.Description,
			SourceBinding:    step.edge.SourceBinding,
			SourceRole:       step.edge.SourceRole,
			BindingNamespace: step.edge.BindingNamespace,
		})
		if next.Name != "" {
			current = next
		}
	}
	return models.EscalationPath{Source: source, Target: target, Hops: hops}
}
