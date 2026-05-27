// Package api assembles the HTTP server for registry and MQ REST APIs.
package api

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/libp2p/go-libp2p/core/host"
)

//go:embed web/*
var webAssets embed.FS

// Server is the HTTP API server.
type Server struct {
	srv *http.Server
}

// New creates and configures the HTTP server with all API routes mounted.
func New(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, hostID string, h host.Host) *Server {
	mux := http.NewServeMux()

	// Registry API
	mux.Handle("/api/v1/registry/", registrypkg.HTTPHandler(regStore))

	// MQ API
	mux.Handle("/api/v1/mq/", mqpkg.HTTPHandler(mqStore))

	// Admin API
	mux.Handle("/api/v1/admin/", AdminHandler(cfg, regStore, mqStore, h))

	// Bootstrap info API
	mux.HandleFunc("/api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"peer_id":"` + hostID + `"}`))
	})

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Basic metrics (counts only; use Prometheus exporter for production)
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		urns, _ := regStore.ListURNs()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"registry_urns":` + itoa(len(urns)) + `}`))
	})

	// Admin Web Console
	subFS, err := fs.Sub(webAssets, "web")
	if err != nil {
		log.Printf("[api] failed to load embedded web assets: %v", err)
	} else {
		fileServer := http.FileServer(http.FS(subFS))
		mux.Handle("/admin/", http.StripPrefix("/admin", fileServer))
		mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
		})
	}

	handler := loggingMiddleware(mux)

	return &Server{
		srv: &http.Server{
			Addr:         cfg.API.ListenAddr,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// Start starts listening. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	log.Printf("[api] HTTP server listening on %s", s.srv.Addr)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx)
	}()
	if err := s.srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
