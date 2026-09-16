package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestTrustedProxyRateLimit(t *testing.T) {
	l := NewIPRateLimiter(rate.Limit(0.001), 1)
	_, subnet, _ := net.ParseCIDR("172.20.0.0/24")
	l.trustedProxies = []*net.IPNet{subnet}
	h := limitMiddleware(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		remote, header string
		status         int
	}{
		{"172.20.0.2:1", "192.0.2.1", 204},
		{"172.20.0.2:2", "192.0.2.2", 204},
		{"172.20.0.2:3", "192.0.2.1", 429},
		{"198.51.100.1:1", "192.0.2.3", 204},
		{"198.51.100.1:2", "192.0.2.4", 429},
		{"172.20.0.2:4", "untrusted-text", 204},
		{"172.20.0.2:5", "different-text", 429},
	} {
		r := httptest.NewRequest("GET", "/healthz", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Real-IP", tc.header)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s header=%s: got %d, want %d", tc.remote, tc.header, w.Code, tc.status)
		}
	}
}

func TestRateLimiterMemoryBoundAndExpiry(t *testing.T) {
	l := NewIPRateLimiter(1, 1)
	for n := 0; n < maxTrackedIPs+100; n++ {
		l.GetLimiter(fmt.Sprint(n))
	}
	if len(l.ips) != maxTrackedIPs {
		t.Fatalf("unbounded limiter map: %d", len(l.ips))
	}
	if l.GetLimiter("overflow") != l.GetLimiter("overflow-two") {
		t.Fatal("overflow must share a bucket")
	}
	l.lastSeen["0"] = time.Now().Add(-11 * time.Minute)
	l.nextCleanup = time.Time{}
	l.GetLimiter("new")
	if _, exists := l.ips["0"]; exists {
		t.Fatal("idle limiter retained")
	}
	if _, exists := l.ips["new"]; !exists {
		t.Fatal("expired slot not reused")
	}
}

func TestAdminTokenOnlyInHeader(t *testing.T) {
	h := adminAuth("secret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, withHeader := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/api/v1/admin/config?token=secret", nil)
		if withHeader {
			r.Header.Set("X-Admin-Token", "secret")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 401
		if withHeader {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("header=%v: got %d", withHeader, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("admin response cacheable")
		}
	}
}

func TestInvalidTLSNeverFallsBackToPlainHTTP(t *testing.T) {
	for _, cert := range []string{"", "missing-cert.pem"} {
		s := &Server{srv: &http.Server{Addr: "127.0.0.1:0"}, tlsCert: cert, tlsKey: "missing-key.pem"}
		if err := s.Start(context.Background()); err == nil {
			t.Fatal("invalid TLS configuration accepted")
		}
	}
}
