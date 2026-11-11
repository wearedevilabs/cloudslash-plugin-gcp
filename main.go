// SPDX-License-Identifier: MIT
// Copyright 2024-2026 CloudSlash Contributors

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/go-plugin"

	"github.com/DrSkyle/cloudslash-plugin-gcp/internal/scan"
	"github.com/DrSkyle/cloudslash-plugin-sdk/shared"
	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
)

// GCPProvider is the local (v1) provider adapter. All Google Cloud logic lives
// in internal/; the core sees only normalized nodes and edges.
type GCPProvider struct {
	pb.UnimplementedProviderServer
	pb.UnimplementedRemediatorServer
}

const (
	gcpPluginName    = "cloudslash-plugin-gcp"
	gcpPluginVersion = "1.0.0"
	gcpProviderName  = "GCP"
)

func (p *GCPProvider) GetMetadata(context.Context, *pb.GetMetadataRequest) (*pb.GetMetadataResponse, error) {
	return &pb.GetMetadataResponse{
		PluginName:    gcpPluginName,
		PluginVersion: gcpPluginVersion,
		ProviderName:  gcpProviderName,
		Capabilities: []*pb.Capability{
			{Name: "discovery", Version: gcpPluginVersion, Available: true},
			{Name: "remediation", Version: gcpPluginVersion, Available: false},
			{Name: "pricing", Version: gcpPluginVersion, Available: false},
		},
		Health: &pb.HealthStatus{State: pb.HealthStatus_HEALTHY, Message: "GCP plugin ready"},
		Metadata: map[string]string{
			"cloud_provider":     "gcp",
			"supported_services": "compute,storage,networking",
		},
	}, nil
}

func (p *GCPProvider) Handshake(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	return &pb.HandshakeResponse{Compatible: true, PluginVersion: gcpPluginVersion, Message: "GCP plugin ready — read-only inventory"}, nil
}

func (p *GCPProvider) Scan(req *pb.ScanRequest, stream pb.Provider_ScanServer) error {
	return scan.Run(stream.Context(), req.Config, stream)
}

func (p *GCPProvider) CheckReversibility(_ context.Context, req *pb.ReversibilityRequest) (*pb.ReversibilityProof, error) {
	if req == nil || req.Crn == "" {
		return &pb.ReversibilityProof{Safe: false, Reason: "missing CRN"}, nil
	}
	return &pb.ReversibilityProof{Safe: false, Reason: "GCP plugin is read-only; no mutation is performed"}, nil
}

func (p *GCPProvider) ApplyQuarantine(context.Context, *pb.QuarantineRequest) (*pb.QuarantineResponse, error) {
	return &pb.QuarantineResponse{Success: false}, fmt.Errorf("GCP plugin is read-only")
}

func (p *GCPProvider) Remediate(context.Context, *pb.RemediateRequest) (*pb.RemediateResponse, error) {
	return &pb.RemediateResponse{Success: false}, nil
}

func (p *GCPProvider) RenderDetail(context.Context, *pb.RenderDetailRequest) (*pb.RenderDetailResponse, error) {
	return &pb.RenderDetailResponse{}, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("cloudslash-plugin-gcp v1.0.0")
		return
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"provider":   &shared.ProviderPlugin{Impl: &GCPProvider{}},
			"remediator": &shared.RemediatorPlugin{Impl: &GCPProvider{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
