// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

// Copyright 2026 The CloudSlash Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shared

import (
	"context"
	"net/rpc"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
)

// Handshake is a common handshake config between core and plugins.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "CLOUDSLASH_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "engine.cloudslash.io",
}

// Provider is the interface that plugins must implement and core will use.
type Provider interface {
	Handshake(ctx context.Context, coreVersion string) (*pb.HandshakeResponse, error)
	Scan(ctx context.Context, config map[string]string) (pb.Provider_ScanClient, error)
	// S.A.U: Quarantine Protocol
	ApplyQuarantine(ctx context.Context, crn string, properties map[string]string) (bool, map[string]string, error)
	CheckReversibility(ctx context.Context, crn string, properties map[string]string) (bool, string, error)
	// PreflightCheck: plugin verifies its own cloud credentials before scan.
	PreflightCheck(ctx context.Context) (*pb.PreflightResponse, error)
	// GetMetadata: Returns plugin metadata for capability-based routing.
	GetMetadata(ctx context.Context) (*pb.GetMetadataResponse, error)
	// GetPricing: Returns pricing data for a specific region/service.
	GetPricing(ctx context.Context, region, service string) (*pb.PricingResponse, error)
	// GetLadders: Returns right-sizing ladders for instance type hierarchies.
	GetLadders(ctx context.Context, resourceKind string) (*pb.GetLaddersResponse, error)
	// RenderDetail: Returns a ViewModel and available Actions for a resource.
	RenderDetail(ctx context.Context, resourceID, resourceType, paneContext string) (*pb.RenderDetailResponse, error)
}

// Remediator is the legacy active-remediation extension.
//
// Deprecated: plugins are read/compute extensions. Mutation is moving to the
// local CLI/TUI executor-adapter boundary and must never be exposed to Horizon
// or a hosted plugin runtime.
type Remediator interface {
	Remediate(ctx context.Context, crn string, action string, properties map[string]string, dryRun bool) (*pb.RemediateResponse, error)
}

// ProviderPlugin is the implementation of plugin.GRPCPlugin.
type ProviderPlugin struct {
	// Impl is the server implementation (for the plugin side)
	Impl pb.ProviderServer
}

func (p *ProviderPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterProviderServer(s, p.Impl)
	return nil
}

func (p *ProviderPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: pb.NewProviderClient(c)}, nil
}

// GRPCClient matches the Provider interface but wraps the protobuf client.
type GRPCClient struct {
	client pb.ProviderClient
}

func (c *GRPCClient) Handshake(ctx context.Context, coreVersion string) (*pb.HandshakeResponse, error) {
	return c.client.Handshake(ctx, &pb.HandshakeRequest{CoreVersion: coreVersion})
}

func (c *GRPCClient) Scan(ctx context.Context, config map[string]string) (pb.Provider_ScanClient, error) {
	return c.client.Scan(ctx, &pb.ScanRequest{Config: config})
}

func (c *GRPCClient) ApplyQuarantine(ctx context.Context, crn string, properties map[string]string) (bool, map[string]string, error) {
	resp, err := c.client.ApplyQuarantine(ctx, &pb.QuarantineRequest{
		Crn:        crn,
		Properties: properties,
	})
	if err != nil {
		return false, nil, err
	}
	return resp.Success, resp.Manifest, nil
}

func (c *GRPCClient) CheckReversibility(ctx context.Context, crn string, properties map[string]string) (bool, string, error) {
	resp, err := c.client.CheckReversibility(ctx, &pb.ReversibilityRequest{
		Crn:        crn,
		Properties: properties,
	})
	if err != nil {
		return false, "", err
	}
	return resp.Safe, resp.Reason, nil
}

func (c *GRPCClient) PreflightCheck(ctx context.Context) (*pb.PreflightResponse, error) {
	return c.client.PreflightCheck(ctx, &pb.PreflightRequest{})
}

func (c *GRPCClient) GetMetadata(ctx context.Context) (*pb.GetMetadataResponse, error) {
	return c.client.GetMetadata(ctx, &pb.GetMetadataRequest{})
}

func (c *GRPCClient) GetPricing(ctx context.Context, region, service string) (*pb.PricingResponse, error) {
	return c.client.GetPricing(ctx, &pb.GetPricingRequest{
		Region:  region,
		Service: service,
	})
}

func (c *GRPCClient) GetLadders(ctx context.Context, resourceKind string) (*pb.GetLaddersResponse, error) {
	return c.client.GetLadders(ctx, &pb.GetLaddersRequest{
		ResourceKind: resourceKind,
	})
}

func (c *GRPCClient) RenderDetail(ctx context.Context, resourceID, resourceType, paneContext string) (*pb.RenderDetailResponse, error) {
	return c.client.RenderDetail(ctx, &pb.RenderDetailRequest{
		ResourceId:   resourceID,
		ResourceType: resourceType,
		PaneContext:  paneContext,
	})
}

// RemediatorPlugin is the implementation of plugin.GRPCPlugin for the
// Remediator service.
type RemediatorPlugin struct {
	// Impl is the server implementation (for the plugin side)
	Impl pb.RemediatorServer
}

func (p *RemediatorPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterRemediatorServer(s, p.Impl)
	return nil
}

func (p *RemediatorPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &RemediatorGRPCClient{client: pb.NewRemediatorClient(c)}, nil
}

// RemediatorGRPCClient matches the Remediator interface but wraps the
// protobuf client.
type RemediatorGRPCClient struct {
	client pb.RemediatorClient
}

func (c *RemediatorGRPCClient) Remediate(ctx context.Context, crn string, action string, properties map[string]string, dryRun bool) (*pb.RemediateResponse, error) {
	return c.client.Remediate(ctx, &pb.RemediateRequest{
		Crn:        crn,
		Action:     action,
		Properties: properties,
		DryRun:     dryRun,
	})
}

// Implement Plugin interface for go-plugin compatibility
func (p *ProviderPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return nil, nil
}

func (p *ProviderPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return nil, nil
}

func (p *RemediatorPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return nil, nil
}

func (p *RemediatorPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return nil, nil
}
