// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 CloudSlash Contributors

package shared

import (
	"context"
	"log/slog"
	"time"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
)

// Default values for security limits
const (
	// DefaultMaxResponseSize is the default maximum response size (100KB)
	DefaultMaxResponseSize = 100 * 1024
	// DefaultRPCTimeout is the default RPC timeout (2 seconds)
	DefaultRPCTimeout = 2 * time.Second
)

// SecurityConfig holds configuration for gRPC security limits.
type SecurityConfig struct {
	// MaxResponseSize is the maximum allowed response size in bytes.
	// Defaults to 100KB if not set.
	MaxResponseSize int
	// RPCTimeout is the default timeout for RPC calls.
	// Defaults to 2 seconds if not set.
	RPCTimeout time.Duration
}

// DefaultSecurityConfig returns a SecurityConfig with sensible defaults.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxResponseSize: DefaultMaxResponseSize,
		RPCTimeout:      DefaultRPCTimeout,
	}
}

// securityInterceptor provides gRPC interceptors for enforcing security limits.
type securityInterceptor struct {
	maxResponseSize int
	defaultTimeout  time.Duration
	logger          *slog.Logger
	pluginName      string
}

// newSecurityInterceptor creates a new securityInterceptor.
func newSecurityInterceptor(config SecurityConfig, pluginName string) *securityInterceptor {
	maxSize := config.MaxResponseSize
	if maxSize <= 0 {
		maxSize = DefaultMaxResponseSize
	}

	timeout := config.RPCTimeout
	if timeout <= 0 {
		timeout = DefaultRPCTimeout
	}

	return &securityInterceptor{
		maxResponseSize: maxSize,
		defaultTimeout:  timeout,
		logger:          slog.Default().With("component", "security.interceptor", "plugin", pluginName),
		pluginName:      pluginName,
	}
}

// unaryInterceptor implements grpc.UnaryServerInterceptor.
func (s *securityInterceptor) unaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Check for context deadline exceeded before processing
	if ctx.Err() == context.DeadlineExceeded {
		s.logger.Warn("RPC deadline already exceeded before handler execution",
			"method", info.FullMethod,
			"plugin", s.pluginName)
		return nil, status.Error(codes.DeadlineExceeded, "RPC deadline exceeded before handler execution")
	}

	// Check for context cancellation
	if ctx.Err() == context.Canceled {
		s.logger.Warn("RPC context cancelled before handler execution",
			"method", info.FullMethod,
			"plugin", s.pluginName)
		return nil, status.Error(codes.Canceled, "RPC context cancelled")
	}

	// Execute the handler
	resp, err := handler(ctx, req)

	// Check if response exceeds size limit
	if err == nil && resp != nil {
		if err := s.checkResponseSize(resp, info.FullMethod); err != nil {
			return nil, err
		}
	}

	return resp, err
}

// checkResponseSize measures the response size and enforces the limit.
func (s *securityInterceptor) checkResponseSize(resp interface{}, method string) error {
	// Try to get the size using proto.Size if available
	if sized, ok := resp.(interface{ Size() int }); ok {
		size := sized.Size()
		if size > s.maxResponseSize {
			s.logger.Warn("Response size limit exceeded",
				"method", method,
				"plugin", s.pluginName,
				"actual_size", size,
				"limit", s.maxResponseSize)
			return status.Errorf(
				codes.ResourceExhausted,
				"response size %d bytes exceeds maximum allowed %d bytes for method %s",
				size, s.maxResponseSize, method,
			)
		}
	}
	return nil
}

// WithSecurityInterceptor creates a grpc.ServerOption that adds security interceptors.
// This should be used by plugins to protect against large responses.
func WithSecurityInterceptor(config SecurityConfig, pluginName string) grpc.ServerOption {
	interceptor := newSecurityInterceptor(config, pluginName)
	return grpc.UnaryInterceptor(interceptor.unaryInterceptor)
}

// ProviderPluginWithSecurity is a ProviderPlugin that includes security interceptors.
type ProviderPluginWithSecurity struct {
	Impl        pb.ProviderServer
	SecurityCfg SecurityConfig
	PluginName  string
}

func (p *ProviderPluginWithSecurity) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	// Register the provider server
	pb.RegisterProviderServer(s, p.Impl)
	return nil
}

func (p *ProviderPluginWithSecurity) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: pb.NewProviderClient(c)}, nil
}

// GetSecurityOptions returns security interceptors for use when creating a gRPC server.
// Plugins should pass these to grpc.NewServer() when instantiating their server.
func (p *ProviderPluginWithSecurity) GetSecurityOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		WithSecurityInterceptor(p.SecurityCfg, p.PluginName),
	}
}

// RemediatorPluginWithSecurity is a RemediatorPlugin that includes security interceptors.
type RemediatorPluginWithSecurity struct {
	Impl        pb.RemediatorServer
	SecurityCfg SecurityConfig
	PluginName  string
}

func (p *RemediatorPluginWithSecurity) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterRemediatorServer(s, p.Impl)
	return nil
}

func (p *RemediatorPluginWithSecurity) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &RemediatorGRPCClient{client: pb.NewRemediatorClient(c)}, nil
}

func (p *RemediatorPluginWithSecurity) GetSecurityOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		WithSecurityInterceptor(p.SecurityCfg, p.PluginName),
	}
}

// ServerInterceptorFunc is a type for custom server interceptors
type ServerInterceptorFunc func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)

// ChainServerInterceptors chains multiple interceptors together
func ChainServerInterceptors(interceptors ...grpc.ServerOption) []grpc.ServerOption {
	return interceptors
}
