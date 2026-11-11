// SPDX-License-Identifier: MIT
// Copyright 2024-2026 CloudSlash Contributors

// Hosted GCP source: a read-only v3 gRPC/gRPC-Web endpoint for Horizon or a
// customer runner. The service account is supplied by the plugin-owned
// connection form; the plugin never uses ambient Google credentials.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DrSkyle/cloudslash-plugin-gcp/internal/gcp"
	"github.com/DrSkyle/cloudslash-plugin-gcp/internal/scan"
	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
	v3 "github.com/DrSkyle/cloudslash-plugin-sdk/shared/v3"
	v3hosted "github.com/DrSkyle/cloudslash-plugin-sdk/shared/v3/hosted"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const pluginName = "cloudslash-plugin-gcp-hosted"

// version is injected by the CloudSlash CLI from the installed plugin manifest.
var version = "0.0.0"

const capabilityName = "read.inventory"

type source struct{}

func Capability() v3.Capability {
	return v3.Capability{
		Name: capabilityName, Version: version, Role: v3.Source, Effect: v3.Read,
		Environments: []v3.Environment{v3.Hosted, v3.CustomerRunner},
		InputSchema:  "scan.request/v1", OutputSchema: "scan.batch/v1",
		ConnectionMethodIDs:  []string{"gcp-service-account"},
		ReadDataClasses:      []string{"resource.observations"},
		OutputDataClasses:    []string{"resource.observations"},
		Limits:               v3.Limits{MaxBatchBytes: 64 << 10, MaxOutputBytes: 64 << 20, MaxResources: 50000, MaxDurationMS: 900000, MaxConcurrency: 8},
		SupportsCancellation: true, SupportsPartial: true, Deterministic: false,
	}
}

func configMap(raw json.RawMessage) (map[string]string, error) {
	var cfg map[string]string
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid connection configuration")
	}
	return cfg, nil
}

func (source) Preflight(ctx context.Context, req v3.PreflightRequest) (v3.PreflightResult, error) {
	cfg, err := configMap(req.ConnectionConfig)
	if err != nil {
		return v3.PreflightResult{}, err
	}
	client, err := gcp.New(ctx, cfg)
	if err != nil {
		return v3.PreflightResult{}, err
	}
	project, err := client.Verify(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcp preflight verify: %v\n", err)
		return v3.PreflightResult{}, err
	}
	return v3.PreflightResult{
		DisplayName:        "GCP " + project,
		ObservedScopes:     []string{"gcp:" + project},
		ReachableScopes:    []string{"gcp:" + project},
		CapabilityVersions: []string{capabilityName + "@" + version},
		ExpiresAt:          time.Now().Add(15 * time.Minute),
	}, nil
}

func (source) Scan(ctx context.Context, req v3.ScanRequest, emit func(v3.Batch) error) error {
	cfg, err := configMap(req.ConnectionConfig)
	if err != nil {
		return err
	}
	stream := &legacyStream{ctx: ctx, emit: emit, envelope: req.ExpectedEnvelope}
	if err := scan.Run(ctx, cfg, stream); err != nil {
		return err
	}
	stream.envelope.Sequence++
	return emit(v3.Batch{Envelope: stream.envelope, Final: true, State: v3.ResultComplete})
}

type legacyStream struct {
	grpc.ServerStream
	ctx      context.Context
	emit     func(v3.Batch) error
	envelope v3.Envelope
}

func (s *legacyStream) Context() context.Context     { return s.ctx }
func (s *legacyStream) SetHeader(metadata.MD) error  { return nil }
func (s *legacyStream) SendHeader(metadata.MD) error { return nil }
func (s *legacyStream) SetTrailer(metadata.MD)       {}
func (s *legacyStream) SendMsg(any) error            { return nil }
func (s *legacyStream) RecvMsg(any) error            { return nil }

func (s *legacyStream) Send(resp *pb.ScanResponse) error {
	batch := v3.Batch{Envelope: s.envelope}
	for _, node := range resp.Nodes {
		props := json.RawMessage(node.Properties)
		if len(props) == 0 || !json.Valid(props) {
			props = json.RawMessage(`{}`)
		}
		batch.Resources = append(batch.Resources, v3.Resource{CRN: node.Crn, Properties: props})
	}
	for _, edge := range resp.Edges {
		batch.Relationships = append(batch.Relationships, v3.Relationship{SourceCRN: edge.SourceCrn, TargetCRN: edge.TargetCrn, Kind: edge.Relation})
	}
	batch.Envelope.Sequence++
	return s.emit(batch)
}

type hostedConnectionField struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Help      string `json:"help"`
	Required  bool   `json:"required"`
	MaxLength int    `json:"max_length"`
}

type hostedConnectionMethod struct {
	ID           string                  `json:"id"`
	Title        string                  `json:"title"`
	Instructions string                  `json:"instructions"`
	Permissions  []string                `json:"permissions"`
	Fields       []hostedConnectionField `json:"fields"`
	ReadOnly     bool                    `json:"read_only"`
	SetupURL     string                  `json:"setup_url,omitempty"`
	SetupMode    string                  `json:"setup_mode,omitempty"`
}

func connectionMethods() []hostedConnectionMethod {
	return []hostedConnectionMethod{{
		ID:    "gcp-service-account",
		Title: "GCP service account",
		Instructions: "Create a read-only service account in the Google Cloud project, grant it Viewer plus Storage Object Viewer " +
			"(or a custom read-only role), create a JSON key, and paste the key here. CloudSlash only reads resource metadata.",
		Permissions: []string{
			"resourcemanager.projects.get",
			"compute.instances.list",
			"compute.disks.list",
			"compute.addresses.list",
			"compute.forwardingRules.list",
			"compute.networks.list",
			"compute.subnetworks.list",
			"storage.buckets.list",
		},
		ReadOnly:  true,
		SetupURL:  "https://console.cloud.google.com/iam-admin/serviceaccounts",
		SetupMode: "console",
		Fields: []hostedConnectionField{
			{Key: "project_id", Label: "Project ID", Type: "text", Help: "Google Cloud project ID", Required: true, MaxLength: 256},
			{Key: "service_account_json", Label: "Service account key (JSON)", Type: "secret", Help: "Paste the read-only service account JSON key", Required: true, MaxLength: 32768},
		},
	}}
}

func connectionMethodsDigest(methods []hostedConnectionMethod) string {
	raw, _ := json.Marshal(methods)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runtimePluginName() string {
	if value := strings.TrimSpace(os.Getenv("PLUGIN_NAME")); value != "" {
		return value
	}
	return pluginName
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--manifest" {
		capability := Capability()
		rawCapability, _ := json.Marshal(capability)
		var capabilityMap map[string]any
		_ = json.Unmarshal(rawCapability, &capabilityMap)
		methods := connectionMethods()
		capabilityMap["connection_schema_digest"] = connectionMethodsDigest(methods)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"plugin_name":        pluginName,
			"version":            version,
			"capabilities":       []string{capabilityName},
			"v3_capabilities":    map[string]any{capabilityName: capabilityMap},
			"connection_methods": methods,
		})
		return
	}
	key, err := hex.DecodeString(os.Getenv("HORIZON_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "HORIZON_PUBLIC_KEY must be a 32-byte Ed25519 public key in hex")
		os.Exit(1)
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "TLS_CERT_FILE and TLS_KEY_FILE are required")
		os.Exit(1)
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8443"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot listen:", err)
		os.Exit(1)
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(64<<10), grpc.MaxSendMsgSize(16<<20), grpc.MaxConcurrentStreams(4),
	)
	v3.RegisterSource(server, source{}, ed25519.PublicKey(key), runtimePluginName())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stdout, `{"listening":"`+lis.Addr().String()+`"}`)
	if err := v3hosted.ServeTLS(ctx, lis, server, cert); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
