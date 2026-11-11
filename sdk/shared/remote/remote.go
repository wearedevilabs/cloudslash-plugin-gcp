// Package remote defines the hosted plugin gRPC contract. A plugin may expose
// any named capability; CloudSlash sends and receives JSON-compatible values.
package remote

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const RunMethod = "/cloudslash.remote.v1.Plugin/Run"

// Runner receives a Struct with plugin_name, org_id, capability and input.
// The caller authenticates with a short-lived signed bearer token in gRPC
// metadata. A result may contain any JSON-compatible fields; a scan result
// contains a snapshot object with schema_version and resources.
type Runner interface {
	Run(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

// Register requires an Ed25519 trust key and enforces token scope before
// calling the plugin. The caller's JSON org_id cannot override the token.
func Register(server grpc.ServiceRegistrar, runner Runner, publicKey ed25519.PublicKey, pluginName string) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "cloudslash.remote.v1.Plugin",
		HandlerType: (*Runner)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Run", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			request := new(structpb.Struct)
			if err := decode(request); err != nil {
				return nil, status.Error(codes.InvalidArgument, "invalid request")
			}
			if interceptor == nil {
				return srv.(Runner).Run(ctx, request)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: RunMethod}
			return interceptor(ctx, request, info, func(ctx context.Context, req any) (any, error) { return srv.(Runner).Run(ctx, req.(*structpb.Struct)) })
		}}},
	}, authenticatedRunner{runner: runner, publicKey: publicKey, pluginName: pluginName})
}

type authenticatedRunner struct {
	runner     Runner
	publicKey  ed25519.PublicKey
	pluginName string
}

func (a authenticatedRunner) Run(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	fields := request.AsMap()
	capability, _ := fields["capability"].(string)
	if capability == "" {
		return nil, status.Error(codes.InvalidArgument, "capability required")
	}
	org, err := VerifyRequest(ctx, a.publicKey, a.pluginName, capability)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid plugin token")
	}
	if fields["plugin_name"] != a.pluginName || fields["org_id"] != org {
		return nil, status.Error(codes.PermissionDenied, "request scope mismatch")
	}
	return a.runner.Run(ctx, request)
}

func Run(ctx context.Context, conn grpc.ClientConnInterface, request *structpb.Struct) (*structpb.Struct, error) {
	response := new(structpb.Struct)
	if err := conn.Invoke(ctx, RunMethod, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

// VerifyRequest authenticates a call from CloudSlash SaaS. Publishers obtain
// the Ed25519 public key from /v1/keys/signing and must verify every request.
// The returned org ID is signed; do not trust the org_id field in the request.
func VerifyRequest(ctx context.Context, publicKey ed25519.PublicKey, pluginName, capability string) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid public key")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing authorization")
	}
	values := md.Get("authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(strings.TrimPrefix(values[0], "Bearer "), claims,
		func(token *jwt.Token) (any, error) { return publicKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer("https://api.cloudslash.dev"),
		jwt.WithAudience(pluginName),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return "", errors.New("invalid plugin token")
	}
	if claims["capability"] != capability {
		return "", errors.New("capability mismatch")
	}
	org, ok := claims["org_id"].(string)
	if !ok || org == "" {
		return "", errors.New("missing organization")
	}
	return org, nil
}
