// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"

	"github.com/DrSkyle/cloudslash-plugin-sdk/shared/remote"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const SourceScanMethod = "/cloudslash.remote.v3.Source/Scan"
const SourcePreflightMethod = "/cloudslash.remote.v3.Source/Preflight"
const maxScanRequestBytes = 64 << 10

// ScanRequest is sent only after Horizon has authorized the organization,
// installation, capability, connection lease and job attempt. Configuration is
// opaque to Horizon and must never be included in a batch or diagnostic.
type ScanRequest struct {
	PluginName       string          `json:"plugin_name"`
	OrganizationID   string          `json:"organization_id"`
	ExpectedEnvelope Envelope        `json:"expected_envelope"`
	LeaseID          string          `json:"lease_id"`
	ConnectionConfig json.RawMessage `json:"connection_config"`
	CapabilityInput  json.RawMessage `json:"capability_input,omitempty"`
}

type SourceServer interface {
	Scan(context.Context, ScanRequest, func(Batch) error) error
}

type PreflightRequest struct {
	PluginName       string          `json:"plugin_name"`
	OrganizationID   string          `json:"organization_id"`
	CapabilityName   string          `json:"capability_name"`
	LeaseID          string          `json:"lease_id"`
	ConnectionConfig json.RawMessage `json:"connection_config"`
}

type ConnectionPreflighter interface {
	Preflight(context.Context, PreflightRequest) (PreflightResult, error)
}

type sourceService interface {
	handleScan(grpc.ServerStream) error
	handlePreflight(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}

type authenticatedSource struct {
	source     SourceServer
	publicKey  ed25519.PublicKey
	pluginName string
}

// RegisterSource exposes only a server-streaming read scan method. The signed
// bearer token binds organization, plugin and capability before invocation.
func RegisterSource(server grpc.ServiceRegistrar, source SourceServer, publicKey ed25519.PublicKey, pluginName string) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "cloudslash.remote.v3.Source", HandlerType: (*sourceService)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Preflight", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			request := new(wrapperspb.BytesValue)
			if err := decode(request); err != nil {
				return nil, status.Error(codes.InvalidArgument, "invalid preflight request")
			}
			if interceptor == nil {
				return srv.(sourceService).handlePreflight(ctx, request)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: SourcePreflightMethod}
			return interceptor(ctx, request, info, func(ctx context.Context, req any) (any, error) {
				return srv.(sourceService).handlePreflight(ctx, req.(*wrapperspb.BytesValue))
			})
		}}},
		Streams: []grpc.StreamDesc{{StreamName: "Scan", ServerStreams: true,
			Handler: func(srv any, stream grpc.ServerStream) error {
				return srv.(sourceService).handleScan(stream)
			}}},
	}, authenticatedSource{source: source, publicKey: publicKey, pluginName: pluginName})
}

func (s authenticatedSource) handlePreflight(ctx context.Context, message *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if len(message.Value) == 0 || len(message.Value) > maxScanRequestBytes {
		return nil, status.Error(codes.InvalidArgument, "invalid preflight request")
	}
	var request PreflightRequest
	decoder := json.NewDecoder(bytes.NewReader(message.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid preflight request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || request.PluginName != s.pluginName ||
		request.OrganizationID == "" || request.CapabilityName == "" || request.LeaseID == "" ||
		!json.Valid(request.ConnectionConfig) {
		return nil, status.Error(codes.InvalidArgument, "invalid preflight binding")
	}
	orgID, err := remote.VerifyRequest(ctx, s.publicKey, s.pluginName, request.CapabilityName)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid plugin token")
	}
	if orgID != request.OrganizationID {
		return nil, status.Error(codes.PermissionDenied, "organization mismatch")
	}
	preflighter, ok := s.source.(ConnectionPreflighter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "preflight unavailable")
	}
	result, err := preflighter.Preflight(ctx, request)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "preflight failed")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, status.Error(codes.Internal, "preflight result invalid")
	}
	return &wrapperspb.BytesValue{Value: encoded}, nil
}

func RunPreflight(ctx context.Context, conn grpc.ClientConnInterface, request PreflightRequest) (PreflightResult, error) {
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > maxScanRequestBytes {
		return PreflightResult{}, errors.New("invalid preflight request")
	}
	response := new(wrapperspb.BytesValue)
	if err := conn.Invoke(ctx, SourcePreflightMethod, &wrapperspb.BytesValue{Value: encoded}, response); err != nil {
		return PreflightResult{}, err
	}
	var result PreflightResult
	if err := json.Unmarshal(response.Value, &result); err != nil {
		return PreflightResult{}, errors.New("invalid preflight response")
	}
	return result, nil
}

func (s authenticatedSource) handleScan(stream grpc.ServerStream) error {
	requestBytes := new(wrapperspb.BytesValue)
	if err := stream.RecvMsg(requestBytes); err != nil || len(requestBytes.Value) > maxScanRequestBytes {
		return status.Error(codes.InvalidArgument, "invalid scan request")
	}
	var request ScanRequest
	decoder := json.NewDecoder(bytes.NewReader(requestBytes.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return status.Error(codes.InvalidArgument, "invalid scan request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return status.Error(codes.InvalidArgument, "invalid scan request")
	}
	if request.PluginName != s.pluginName || request.OrganizationID == "" || request.LeaseID == "" ||
		request.ExpectedEnvelope.ProtocolVersion != ProtocolVersion ||
		request.ExpectedEnvelope.CapabilityName == "" || !json.Valid(request.ConnectionConfig) {
		return status.Error(codes.InvalidArgument, "invalid scan binding")
	}
	orgID, err := remote.VerifyRequest(stream.Context(), s.publicKey, s.pluginName, request.ExpectedEnvelope.CapabilityName)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid plugin token")
	}
	if orgID != request.OrganizationID {
		return status.Error(codes.PermissionDenied, "organization mismatch")
	}
	return s.source.Scan(stream.Context(), request, func(batch Batch) error {
		encoded, err := json.Marshal(batch)
		if err != nil {
			return errors.New("invalid source batch")
		}
		return stream.SendMsg(&wrapperspb.BytesValue{Value: encoded})
	})
}

type ScanStream struct{ stream grpc.ClientStream }

// OpenScan starts an authenticated scan. The caller must set authorization
// metadata and bounded gRPC message limits on the connection.
func OpenScan(ctx context.Context, conn grpc.ClientConnInterface, request ScanRequest) (*ScanStream, error) {
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > maxScanRequestBytes {
		return nil, errors.New("invalid scan request")
	}
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, SourceScanMethod)
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(&wrapperspb.BytesValue{Value: encoded}); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	return &ScanStream{stream: stream}, nil
}

func (s *ScanStream) Next() (Batch, error) {
	message := new(wrapperspb.BytesValue)
	if err := s.stream.RecvMsg(message); err != nil {
		return Batch{}, err
	}
	var batch Batch
	if err := json.Unmarshal(message.Value, &batch); err != nil {
		return Batch{}, errors.New("invalid source batch")
	}
	return batch, nil
}
