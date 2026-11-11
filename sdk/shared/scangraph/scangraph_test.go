package scangraph

import (
	"testing"

	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/crn"
)

func TestRejectsInvalidResourceNamesBeforeGraphMutation(t *testing.T) {
	g := New()
	valid := crn.New("custom", "", "svc", "kind", "", "id")
	invalid := crn.New("custom", "", "svc", "kind", "", "")
	if err := g.AddNode(invalid, map[string]interface{}{"state": "x"}); err == nil || g.NodeCount() != 0 {
		t.Fatal("invalid node entered plugin graph")
	}
	if err := g.AddEdge(valid, invalid); err == nil || len(g.Edges()) != 0 {
		t.Fatal("invalid relationship entered plugin graph")
	}
	if err := g.AddNode(valid, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.AddNode(valid, map[string]interface{}{"state": "ready"}); err != nil || g.GetNode(valid).Properties["state"] != "ready" {
		t.Fatalf("valid node merge failed: %v", err)
	}
}
