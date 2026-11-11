package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

type testRunner struct{ calls int }

func (runner *testRunner) Run(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	runner.calls++
	return structpb.NewStruct(map[string]any{"org_id": request.AsMap()["org_id"]})
}

func TestRegisteredServiceEnforcesSignedScope(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	runner := &testRunner{}
	Register(server, runner, public, "sample")
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request, err := structpb.NewStruct(map[string]any{"plugin_name": "sample", "org_id": "org_123", "capability": "scan", "input": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), conn, request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unsigned call: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "https://api.cloudslash.dev", "aud": "sample", "org_id": "org_123", "capability": "scan", "exp": time.Now().Add(time.Minute).Unix()})
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+signed)
	response, err := Run(ctx, conn, request)
	if err != nil || response.AsMap()["org_id"] != "org_123" {
		t.Fatalf("authorized call: response=%v err=%v", response, err)
	}
	wrong, err := structpb.NewStruct(map[string]any{"plugin_name": "sample", "org_id": "org_other", "capability": "scan", "input": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, conn, wrong); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("mismatched org: %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner called %d times, want 1", runner.calls)
	}
}

func TestVerifyRequestScopesPluginAndCapability(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://api.cloudslash.dev", "aud": "sample", "org_id": "org_123", "capability": "scan",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+signed))
	org, err := VerifyRequest(ctx, public, "sample", "scan")
	if err != nil || org != "org_123" {
		t.Fatalf("expected verified org, got %q: %v", org, err)
	}
	if _, err := VerifyRequest(ctx, public, "another", "scan"); err == nil {
		t.Fatal("accepted wrong plugin audience")
	}
	if _, err := VerifyRequest(ctx, public, "sample", "remediate"); err == nil {
		t.Fatal("accepted wrong capability")
	}
}
