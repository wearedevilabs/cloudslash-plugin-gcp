// SPDX-License-Identifier: MIT
// Copyright 2024-2026 CloudSlash Contributors

// Package scan orchestrates a read-only GCP inventory scan and streams
// normalized nodes and relationships to the engine.
package scan

import (
	"context"
	"errors"
	"log/slog"

	"github.com/DrSkyle/cloudslash-plugin-gcp/internal/gcp"
	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
)

const batchSize = 50

// Run scans one GCP project and streams batches to the engine.
func Run(ctx context.Context, config map[string]string, stream pb.Provider_ScanServer) error {
	logger := slog.Default().With("component", "gcp-plugin")
	client, err := gcp.New(ctx, config)
	if err != nil {
		return err
	}
	project, err := client.Verify(ctx)
	if err != nil {
		return err
	}
	nodes, edges, scanErrors := gcp.Collect(ctx, client, project, logger)

	for i := 0; i < len(nodes); i += batchSize {
		end := i + batchSize
		if end > len(nodes) {
			end = len(nodes)
		}
		if err := stream.Send(&pb.ScanResponse{Nodes: nodes[i:end]}); err != nil {
			return err
		}
	}
	for i := 0; i < len(edges); i += batchSize {
		end := i + batchSize
		if end > len(edges) {
			end = len(edges)
		}
		if err := stream.Send(&pb.ScanResponse{Edges: edges[i:end]}); err != nil {
			return err
		}
	}
	return errors.Join(scanErrors...)
}

// ConfigFields are the plugin-owned connection fields surfaced by CloudSlash.
func ConfigFields() []map[string]any {
	return []map[string]any{
		{"key": "project_id", "label": "Project ID", "type": "text", "required": true, "help": "Google Cloud project ID, e.g. my-production-project"},
		{"key": "service_account_json", "label": "Service account key (JSON)", "type": "secret", "required": true, "help": "Paste the JSON key for a read-only service account"},
	}
}

// Describe returns a short summary used by the local provider metadata.
func Describe() string {
	return "GCP"
}
