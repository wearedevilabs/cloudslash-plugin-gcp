package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
)

type sourceFixture struct{ called int }

func (s *sourceFixture) Preflight(_ context.Context, _ PreflightRequest) (PreflightResult, error) {
	return PreflightResult{DisplayName: "Test account", ObservedScopes: []string{"read"},
		CapabilityVersions: []string{"inventory@1"}}, nil
}

func (s *sourceFixture) Scan(_ context.Context, req ScanRequest, send func(Batch) error) error {
	s.called++
	return send(Batch{Envelope: req.ExpectedEnvelope, Resources: []Resource{{
		CRN: "crn:devi:custom::svc:item::one", Properties: json.RawMessage(`{"count":9007199254740993}`),
	}}, Final: true, State: ResultComplete})
}

func TestRemoteSourceRequiresSignedScopeAndPreservesJSONNumbers(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	source := &sourceFixture{}
	RegisterSource(server, source, publicKey, "plugin-x")
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///v3-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := ScanRequest{PluginName: "plugin-x", OrganizationID: "org-a", LeaseID: "lease-1",
		ConnectionConfig: json.RawMessage(`{"api_key":"private"}`),
		ExpectedEnvelope: Envelope{ProtocolVersion: ProtocolVersion, CapabilityName: "inventory",
			JobID: "job-1", OrganizationNonce: "nonce", PluginDigest: "digest", CapabilityVersion: "1", InputDigest: "input"}}
	stream, err := OpenScan(context.Background(), conn, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(); status.Code(err) != codes.Unauthenticated || source.called != 0 {
		t.Fatalf("unsigned scan ran: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://api.cloudslash.dev", "aud": "plugin-x", "org_id": "org-a",
		"capability": "inventory", "exp": time.Now().Add(time.Minute).Unix(),
	})
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+signed)
	stream, err = OpenScan(ctx, conn, request)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := stream.Next()
	if err != nil || string(batch.Resources[0].Properties) != `{"count":9007199254740993}` || source.called != 1 {
		t.Fatalf("batch corrupted: %+v, %v", batch, err)
	}
	request.OrganizationID = "org-b"
	stream, err = OpenScan(ctx, conn, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(); status.Code(err) != codes.PermissionDenied || source.called != 1 {
		t.Fatalf("cross-org scan ran: %v", err)
	}
	preflight := PreflightRequest{PluginName: "plugin-x", OrganizationID: "org-a", CapabilityName: "inventory",
		LeaseID: "lease-1", ConnectionConfig: json.RawMessage(`{"api_key":"private"}`)}
	result, err := RunPreflight(ctx, conn, preflight)
	if err != nil || result.DisplayName != "Test account" || len(result.ObservedScopes) != 1 {
		t.Fatalf("preflight failed: %+v, %v", result, err)
	}
	preflight.OrganizationID = "org-b"
	if _, err := RunPreflight(ctx, conn, preflight); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-org preflight accepted: %v", err)
	}
}
