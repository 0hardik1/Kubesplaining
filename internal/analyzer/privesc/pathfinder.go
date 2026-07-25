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

	seen := map[string]bool{}
	var paths []models.EscalationPath
	for _, sourceID := range sources {
		sourceNode := graph.Nodes[sourceID]
		if sourceNode == nil {
			continue
		}
		found := bfsToSinks(graph, adj, sourceID, maxDepth)
		for targetID, chain := range found {
			key := sourceID + "->" + targetID
			if seen[key] {
				continue
			}
			seen[key] = true
			targetNode := graph.Nodes[targetID]
			path := buildPath(graph, sourceNode.Subject, targetNode.Target, chain)
			path.TargetNamespace = targetNode.TargetNamespace
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
		return len(paths[i].Hops) < len(paths[j].Hops)
	})

	return paths
}

// bfsToSinks walks the graph from sourceID and returns, for each reachable sink, the shortest step chain that got there.
// System subjects (e.g. system:masters) are treated as non-traversable intermediates but still valid as sinks via explicit edges.
func bfsToSinks(
	graph *models.EscalationGraph,
	adj map[string][]*models.EscalationEdge,
	sourceID string,
	maxDepth int,
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
				if existing, ok := sinks[edge.To]; !ok || len(nextPath) < len(existing) {
					sinks[edge.To] = nextPath
				}
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
