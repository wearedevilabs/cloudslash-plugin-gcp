package hosted

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	grpcweb "github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"
)

// ServeTLS serves the same source over native gRPC (HTTP/2) and gRPC-Web
// (HTTP/1.1). gRPC-Web is what makes a public Cloudflare quick tunnel usable:
// those tunnels forward HTTP/1.1 but do not preserve native gRPC trailers.
func ServeTLS(ctx context.Context, listener net.Listener, server *grpc.Server, cert tls.Certificate) error {
	wrapper := grpcweb.WrapServer(server, grpcweb.WithOriginFunc(func(string) bool { return true }))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wrapper.IsGrpcWebRequest(r) {
			wrapper.ServeHTTP(w, r)
			return
		}
		server.ServeHTTP(w, r)
	})
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	httpServer := &http.Server{Handler: handler, TLSConfig: tlsConfig}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		server.GracefulStop()
	}()
	err := httpServer.Serve(tls.NewListener(listener, tlsConfig))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
