package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// TestFindPathsContinuesThroughTraversableSink proves a sink marked Traversable
// yields both its own path and the longer chain that runs through it.
func TestFindPathsContinuesThroughTraversableSink(t *testing.T) {
	graph := &models.EscalationGraph{Nodes: map[string]*models.EscalationNode{}}
	src := models.SubjectRef{Kind: "ServiceAccount", Name: "src", Namespace: "app"}
	ensureSubjectNode(graph, src)
	graph.Nodes["sink:mid"] = &models.EscalationNode{
		ID: "sink:mid", IsSink: true, Traversable: true, Target: models.TargetNamespaceAdmin,
	}
	graph.Nodes["sink:end"] = &models.EscalationNode{
		ID: "sink:end", IsSink: true, Target: models.TargetClusterAdmin,
	}
	addEdge(graph, nodeID(src), "sink:mid", &models.EscalationEdge{Action: "a1"})
	addEdge(graph, "sink:mid", "sink:end", &models.EscalationEdge{Action: "a2"})

	paths := FindPaths(graph, 5)
	if len(paths) != 2 {
		t.Fatalf("want 2 paths (mid and end), got %d", len(paths))
	}
	var deepest int
	for _, p := range paths {
		if len(p.Hops) > deepest {
			deepest = len(p.Hops)
		}
	}
	if deepest != 2 {
		t.Fatalf("want a 2-hop chain through the traversable sink, deepest was %d", deepest)
	}
}
