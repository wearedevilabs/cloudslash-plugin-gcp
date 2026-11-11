// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Package scangraph provides a minimal in-memory resource graph that
// provider plugins build during a scan. Plugins stream the collected nodes
// and edges to the core engine over gRPC (see shared/proto), so this type
// never crosses the process boundary — it exists purely as a convenient
// collection surface for scanner implementations.
package scangraph

import (
	"sync"

	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/crn"
)

// Node is a scanned resource with its properties and estimated monthly cost.
type Node struct {
	CRN        crn.CRN
	Properties map[string]interface{}
	Cost       float64
	ValidFrom  int64
	ValidTo    int64
}

// IDStr returns the canonical CRN string for the node.
func (n *Node) IDStr() string {
	return n.CRN.String()
}

// Edge is a relationship between two scanned resources.
type Edge struct {
	Source crn.CRN
	Target crn.CRN
}

// Graph collects nodes and edges during a plugin scan. It is safe for
// concurrent use.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges []Edge
}

// New returns an empty scan graph.
func New() *Graph {
	return &Graph{nodes: make(map[string]*Node)}
}

// AddNode inserts (or merges) a node identified by its CRN.
func (g *Graph) AddNode(id crn.CRN, props map[string]interface{}) error {
	if err := id.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := id.String()
	if existing, ok := g.nodes[key]; ok {
		if existing.Properties == nil {
			existing.Properties = make(map[string]interface{}, len(props))
		}
		for k, v := range props {
			existing.Properties[k] = v
		}
		return nil
	}
	g.nodes[key] = &Node{CRN: id, Properties: props}
	return nil
}

// GetNode returns the node for a CRN, or nil.
func (g *Graph) GetNode(id crn.CRN) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id.String()]
}

// AddEdge records a relationship between two resources.
func (g *Graph) AddEdge(source, target crn.CRN) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, Edge{Source: source, Target: target})
	return nil
}

// Nodes returns all collected nodes.
func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// Edges returns all collected edges.
func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Edge, len(g.edges))
	copy(out, g.edges)
	return out
}

// NodeCount returns the number of collected nodes.
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// AddNodeWithCost inserts a node and sets its estimated monthly cost when
// cost is positive.
func AddNodeWithCost(g *Graph, id crn.CRN, props map[string]interface{}, cost float64) {
	_ = g.AddNode(id, props)
	if cost > 0 {
		if n := g.GetNode(id); n != nil {
			n.Cost = cost
		}
	}
}
