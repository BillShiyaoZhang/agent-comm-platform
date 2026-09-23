// Package api assembles the HTTP server for registry and MQ REST APIs.
package api

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
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
	StoreUserData             atomic.Bool
	ForwardToStoragePlatforms atomic.Bool
	RegistryResetPending      atomic.Bool
	ConfigRestartPending      atomic.Bool
	restart                   func()
}

// Server is the HTTP API server.
type Server struct {
	srv        *http.Server
	AuditLog   *AuditLog
	Policies   *SecurityPolicies
	ConfigPath string
	tlsCert    string
	tlsKey     string
}

// New creates and configures the HTTP server with all API routes mounted.
func New(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, hostID string, h host.Host, cfgPath string) *Server {
	mux := http.NewServeMux()

	policies := &SecurityPolicies{}
	policies.StoreUserData.Store(cfg.Platform.StoreUserData)
	policies.ForwardToStoragePlatforms.Store(cfg.Platform.ForwardToStoragePlatforms)
	policies.RegistryResetPending.Store(cfg.AdminRegistryResetPending)

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
	mqStore.SetStoragePolicy(isStoreAllowedMQ, isForwardAllowedMQ)
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
		const apiDocsURL = "https://agent-communication.online/docs/?path=platform/guides/API.md"
		mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, apiDocsURL, http.StatusPermanentRedirect)
		})
		mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, apiDocsURL, http.StatusPermanentRedirect)
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
		for _, cidr := range cfg.API.TrustedProxyCIDRs {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				limiter.trustedProxies = append(limiter.trustedProxies, network)
			}
		}
		handler = limitMiddleware(limiter, handler)
	}

	return &Server{
		srv: &http.Server{
			Addr:              cfg.API.ListenAddr,
			Handler:           handler,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		AuditLog:   auditLog,
		Policies:   policies,
		ConfigPath: cfgPath,
		tlsCert:    cfg.API.TLSCert,
		tlsKey:     cfg.API.TLSKey,
	}
}

// Start starts listening. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if (s.tlsCert == "") != (s.tlsKey == "") {
		return fmt.Errorf("tls_cert and tls_key must be configured together")
	}
	if s.tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
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
	var serveErr error
	if s.tlsCert != "" {
		serveErr = s.srv.ServeTLS(ln, "", "")
	} else {
		serveErr = s.srv.Serve(ln)
	}
	if serveErr != http.ErrServerClosed {
		return serveErr
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
	ips            map[string]*rate.Limiter
	lastSeen       map[string]time.Time
	nextCleanup    time.Time
	overflow       *rate.Limiter
	trustedProxies []*net.IPNet
	mu             sync.Mutex
	r              rate.Limit
	b              int
}

// NewIPRateLimiter creates a new rate limiter registry.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips:      make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		overflow: rate.NewLimiter(r, b),
		r:        r,
		b:        b,
	}
}

// GetLimiter retrieves or creates a rate limiter for the given IP address.
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	if !now.Before(i.nextCleanup) {
		for key, seen := range i.lastSeen {
			if now.Sub(seen) > 10*time.Minute {
				delete(i.ips, key)
				delete(i.lastSeen, key)
			}
		}
		i.nextCleanup = now.Add(time.Minute)
	}

	limiter, exists := i.ips[ip]
	if !exists {
		// Never evict active buckets: rotating IPs must not reset their quota.
		if len(i.ips) >= maxTrackedIPs {
			return i.overflow
		}
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	i.lastSeen[ip] = now
	return limiter
}

const maxTrackedIPs = 10000

// limitMiddleware intercepts requests and restricts client IP request rates.
func limitMiddleware(limiter *IPRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		for _, network := range limiter.trustedProxies {
			if network.Contains(net.ParseIP(ip)) {
				// The edge proxy must overwrite this header with the actual client IP.
				if forwarded := net.ParseIP(r.Header.Get("X-Real-IP")); forwarded != nil {
					ip = forwarded.String()
				}
				break
			}
		}

		if !limiter.GetLimiter(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too Many Requests"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getClientIP uses the socket peer; arbitrary forwarded headers are not identity.
func getClientIP(r *http.Request) string {
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
