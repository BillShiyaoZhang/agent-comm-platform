package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
)

func TestRateLimiter(t *testing.T) {
	// Setup standard server configuration
	cfg := &config.Config{
		API: config.APIConfig{
			ListenAddr:     ":8080",
			RateLimitRate:  5.0, // 5 requests per second
			RateLimitBurst: 2,   // burst of 2
		},
	}

	// Create dummy/empty stores for the Server init
	regStore, _ := registrypkg.NewStore(":memory:", 24)
	mqStore, _ := mqpkg.NewStore(":memory:", 7, 100)

	// Initialize server (ignoring host ID and p2p Host since we won't hit endpoints requiring them)
	server := New(cfg, regStore, mqStore, "dummy-host", nil, "")
	handler := server.srv.Handler

	t.Run("Under rate limit", func(t *testing.T) {
		// Make 2 quick requests (burst size is 2, so this should succeed)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/healthz", nil)
			req.RemoteAddr = "1.2.3.4:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", w.Code)
			}
		}
	})

	t.Run("Over rate limit", func(t *testing.T) {
		// Make 3 quick requests (burst is 2, so the 3rd request should fail with 429)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/healthz", nil)
			req.RemoteAddr = "2.3.4.5:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if i < 2 {
				if w.Code != http.StatusOK {
					t.Fatalf("expected status 200 for request %d, got %d", i, w.Code)
				}
			} else {
				if w.Code != http.StatusTooManyRequests {
					t.Fatalf("expected status 429 for request 2, got %d", w.Code)
				}
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to parse response body: %v", err)
				}
				if resp["error"] != "Too Many Requests" {
					t.Errorf("expected 'Too Many Requests' error message, got %q", resp["error"])
				}
			}
		}
	})

	t.Run("Client IP - X-Real-IP header support", func(t *testing.T) {
		// Verify that different IPs get separate limit pools
		// Request 1 from IP-A
		req1 := httptest.NewRequest("GET", "/healthz", nil)
		req1.RemoteAddr = "8.8.8.8:1234"
		req1.Header.Set("X-Real-IP", "10.0.0.1")
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w1.Code)
		}

		// Request 2 from IP-A
		req2 := httptest.NewRequest("GET", "/healthz", nil)
		req2.RemoteAddr = "8.8.8.8:1234"
		req2.Header.Set("X-Real-IP", "10.0.0.1")
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w2.Code)
		}

		// Request 3 from IP-A (exceeds limit)
		req3 := httptest.NewRequest("GET", "/healthz", nil)
		req3.RemoteAddr = "8.8.8.8:1234"
		req3.Header.Set("X-Real-IP", "10.0.0.1")
		w3 := httptest.NewRecorder()
		handler.ServeHTTP(w3, req3)
		if w3.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429 for IP-A, got %d", w3.Code)
		}

		// Request from IP-B (should succeed because it's a different client IP)
		req4 := httptest.NewRequest("GET", "/healthz", nil)
		req4.RemoteAddr = "8.8.8.8:1234"
		req4.Header.Set("X-Real-IP", "10.0.0.2")
		w4 := httptest.NewRecorder()
		handler.ServeHTTP(w4, req4)
		if w4.Code != http.StatusOK {
			t.Errorf("expected 200 for IP-B, got %d", w4.Code)
		}
	})

	t.Run("Client IP - X-Forwarded-For header support", func(t *testing.T) {
		// Test multiple IPs in X-Forwarded-For (we should take the first one)
		req1 := httptest.NewRequest("GET", "/healthz", nil)
		req1.RemoteAddr = "8.8.8.8:1234"
		req1.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w1.Code)
		}

		req2 := httptest.NewRequest("GET", "/healthz", nil)
		req2.RemoteAddr = "8.8.8.8:1234"
		req2.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w2.Code)
		}

		req3 := httptest.NewRequest("GET", "/healthz", nil)
		req3.RemoteAddr = "8.8.8.8:1234"
		req3.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
		w3 := httptest.NewRecorder()
		handler.ServeHTTP(w3, req3)
		if w3.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429 for first IP in X-Forwarded-For list, got %d", w3.Code)
		}
	})

	t.Run("Rate limit disabled (rate=0)", func(t *testing.T) {
		cfgDisabled := &config.Config{
			API: config.APIConfig{
				ListenAddr:     ":8080",
				RateLimitRate:  0.0, // disabled
				RateLimitBurst: 0,
			},
		}
		serverDisabled := New(cfgDisabled, regStore, mqStore, "dummy-host", nil, "")
		handlerDisabled := serverDisabled.srv.Handler

		// Make 10 quick requests, all should succeed
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "/healthz", nil)
			req.RemoteAddr = "5.5.5.5:1234"
			w := httptest.NewRecorder()
			handlerDisabled.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 with rate limiter disabled, got %d", w.Code)
			}
		}
	})
}

func TestClientIPExtractorHelper(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "remoteAddr only",
			remoteAddr: "1.2.3.4:5678",
			expected:   "1.2.3.4",
		},
		{
			name:       "remoteAddr invalid split",
			remoteAddr: "1.2.3.4",
			expected:   "1.2.3.4",
		},
		{
			name:       "X-Real-IP override",
			remoteAddr: "1.2.3.4:5678",
			headers:    map[string]string{"X-Real-IP": "5.6.7.8"},
			expected:   "5.6.7.8",
		},
		{
			name:       "X-Forwarded-For simple",
			remoteAddr: "1.2.3.4:5678",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9"},
			expected:   "9.9.9.9",
		},
		{
			name:       "X-Forwarded-For list with spaces",
			remoteAddr: "1.2.3.4:5678",
			headers:    map[string]string{"X-Forwarded-For": " 10.0.0.1, 10.0.0.2, 10.0.0.3 "},
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Real-IP takes precedence over X-Forwarded-For",
			remoteAddr: "1.2.3.4:5678",
			headers:    map[string]string{"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "10.0.0.2"},
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/healthz", nil)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.expected {
				t.Errorf("expected IP %q, got %q", tt.expected, ip)
			}
		})
	}
}

func TestTrimSpaceHelper(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"   ", ""},
		{"abc", "abc"},
		{"  abc  ", "abc"},
		{"\tabc\t", "abc"},
		{"\t  abc  \t", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := trimSpace(tt.input)
			if res != tt.expected {
				t.Errorf("expected %q for %q, got %q", tt.expected, tt.input, res)
			}
		})
	}
}

func TestIndexOfCommaHelper(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", -1},
		{"abc", -1},
		{"a,b,c", 1},
		{",b,c", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := indexOfComma(tt.input)
			if res != tt.expected {
				t.Errorf("expected %d for %q, got %d", tt.expected, tt.input, res)
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	handler := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "/test-logging", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("expected 418 status code, got %d", w.Code)
	}
}

func TestBootstrapAndStatusEndpoints(t *testing.T) {
	cfg := &config.Config{
		API: config.APIConfig{
			ListenAddr: ":8080",
		},
	}
	regStore, _ := registrypkg.NewStore(":memory:", 24)
	mqStore, _ := mqpkg.NewStore(":memory:", 7, 100)
	server := New(cfg, regStore, mqStore, "test-peer-id", nil, "")
	handler := server.srv.Handler

	t.Run("/api/v1/bootstrap", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/bootstrap", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["peer_id"] != "test-peer-id" {
			t.Errorf("expected peer_id 'test-peer-id', got %q", resp["peer_id"])
		}
	})

	t.Run("/api/v1/status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/status", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["registry_urns"].(float64) != 0 {
			t.Errorf("expected registry_urns to be 0, got %v", resp["registry_urns"])
		}
	})
}

// TestItoaHelper exercises the itoa helper function directly, covering all branches.
func TestItoaHelper(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{5, "5"},
		{42, "42"},
		{100, "100"},
		{987654321, "987654321"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			res := itoa(tt.input)
			if res != tt.expected {
				t.Errorf("expected %s for %d, got %s", tt.expected, tt.input, res)
			}
		})
	}
}

func TestServerStartShutdown(t *testing.T) {
	// Try to start the server on a random port and shut it down using context cancellation.
	// Use port 0 to let OS choose a free port.
	cfg := &config.Config{
		API: config.APIConfig{
			ListenAddr: "127.0.0.1:0",
		},
	}
	regStore, _ := registrypkg.NewStore(":memory:", 24)
	mqStore, _ := mqpkg.NewStore(":memory:", 7, 100)
	server := New(cfg, regStore, mqStore, "test-peer-id", nil, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Wait a brief moment for the server to spin up, then cancel context
	time.Sleep(100 * time.Millisecond) // Wait 100ms
	cancel()

	err := <-errChan
	if err != nil && err != http.ErrServerClosed {
		t.Errorf("expected no error or server closed, got: %v", err)
	}
}
