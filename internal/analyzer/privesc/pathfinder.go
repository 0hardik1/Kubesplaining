package privesc

import (
	"sort"

	"github.com/hardik/kubesplaining/internal/models"
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
			paths = append(paths, buildPath(graph, sourceNode.Subject, graph.Nodes[targetID].Target, chain))
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Source.Key() != paths[j].Source.Key() {
			return paths[i].Source.Key() < paths[j].Source.Key()
		}
		if paths[i].Target != paths[j].Target {
			return paths[i].Target < paths[j].Target
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
				continue
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
		if node, ok := graph.Nodes[step.nodeID]; ok && !node.IsSink {
			next = node.Subject
		}
		hops = append(hops, models.EscalationHop{
			Step:        i + 1,
			Action:      step.edge.Action,
			FromSubject: current,
			ToSubject:   next,
			Permission:  step.edge.Permission,
			Gains:       step.edge.Description,
		})
		if next.Name != "" {
			current = next
		}
	}
	return models.EscalationPath{Source: source, Target: target, Hops: hops}
}
