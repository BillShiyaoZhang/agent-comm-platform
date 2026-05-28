// Package api assembles the HTTP server for registry and MQ REST APIs.
package api

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/libp2p/go-libp2p/core/host"
	"golang.org/x/time/rate"
	"sync/atomic"
)

//go:embed web/*
var webAssets embed.FS

// SecurityPolicies holds thread-safe runtime policies for platform security.
type SecurityPolicies struct {
	StoreUserData            atomic.Bool
	ForwardToStoragePlatforms atomic.Bool
}

// Server is the HTTP API server.
type Server struct {
	srv        *http.Server
	AuditLog   *AuditLog
	Policies   *SecurityPolicies
	ConfigPath string
}

// New creates and configures the HTTP server with all API routes mounted.
func New(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, hostID string, h host.Host, cfgPath string) *Server {
	mux := http.NewServeMux()

	policies := &SecurityPolicies{}
	policies.StoreUserData.Store(cfg.Platform.StoreUserData)
	policies.ForwardToStoragePlatforms.Store(cfg.Platform.ForwardToStoragePlatforms)

	// Set retention days on MQ Store
	mqStore.SetHistoryRetentionDays(cfg.Platform.HistoryRetentionDays)

	// Registry API
	isForwardAllowedRegistry := func(urn string) bool {
		if policies.ForwardToStoragePlatforms.Load() {
			return true
		}
		entry, err := regStore.ResolveEntry(urn)
		if err != nil || entry == nil {
			return true
		}
		return !entry.StoresUserData
	}
	mux.Handle("/api/v1/registry/", registrypkg.HTTPHandler(regStore, isForwardAllowedRegistry))

	// MQ API
	isStoreAllowedMQ := func() bool {
		return policies.StoreUserData.Load()
	}
	isForwardAllowedMQ := func(recipientURN string) bool {
		if policies.ForwardToStoragePlatforms.Load() {
			return true
		}
		entry, err := regStore.ResolveEntry(recipientURN)
		if err != nil || entry == nil {
			return true
		}
		return !entry.StoresUserData
	}
	mux.Handle("/api/v1/mq/", mqpkg.HTTPHandler(mqStore, isStoreAllowedMQ, isForwardAllowedMQ))

	// Audit Log (persistent to SQLite)
	var auditLog *AuditLog
	if al, err := NewAuditLog(cfg.Platform.DataDir); err != nil {
		log.Printf("[api] WARNING: failed to create audit log: %v (admin audit logging disabled)", err)
	} else {
		auditLog = al
		log.Printf("[api] Audit log initialized at %s/audit.db", cfg.Platform.DataDir)
	}

	// Admin API
	mux.Handle("/api/v1/admin/", AdminHandler(cfg, regStore, mqStore, h, auditLog, policies, cfgPath))

	// Bootstrap info API
	mux.HandleFunc("/api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		storesUserDataVal := "false"
		if policies.StoreUserData.Load() {
			storesUserDataVal = "true"
		}
		w.Write([]byte(`{"peer_id":"` + hostID + `","stores_user_data":` + storesUserDataVal + `}`))
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
		mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
		})
		mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, r *http.Request) {
			data, err := fs.ReadFile(subFS, "docs.html")
			if err != nil {
				http.Error(w, "Documentation not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
		})
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			data, err := fs.ReadFile(subFS, "homepage.html")
			if err != nil {
				http.Error(w, "Homepage not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
		})
	}

	handler := loggingMiddleware(mux)

	if cfg.API.RateLimitRate > 0 {
		burst := cfg.API.RateLimitBurst
		if burst <= 0 {
			burst = int(cfg.API.RateLimitRate)
			if burst <= 0 {
				burst = 1
			}
		}
		limiter := NewIPRateLimiter(rate.Limit(cfg.API.RateLimitRate), burst)
		handler = limitMiddleware(limiter, handler)
	}

	return &Server{
		srv: &http.Server{
			Addr:         cfg.API.ListenAddr,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		AuditLog:   auditLog,
		Policies:   policies,
		ConfigPath: cfgPath,
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

// IPRateLimiter is a thread-safe registry of rate limiters per IP.
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter creates a new rate limiter registry.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

// GetLimiter retrieves or creates a rate limiter for the given IP address.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter
}

// limitMiddleware intercepts requests and restricts client IP request rates.
func limitMiddleware(limiter *IPRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		if !limiter.GetLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too Many Requests"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts client IP address, supporting standard reverse proxy headers.
func getClientIP(r *http.Request) string {
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if idx := indexOfComma(forwarded); idx != -1 {
			return trimSpace(forwarded[:idx])
		}
		return trimSpace(forwarded)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func indexOfComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
