package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	golibp2p "github.com/libp2p/go-libp2p"
)

func TestAdminAPIs(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "api-admin-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	regStore, err := registrypkg.NewStore(filepath.Join(tempDir, "registry.db"), 24)
	if err != nil {
		t.Fatalf("create registry store: %v", err)
	}
	defer regStore.Close()

	mqStore, err := mqpkg.NewStore(filepath.Join(tempDir, "mq.db"), 7, 100)
	if err != nil {
		t.Fatalf("create mq store: %v", err)
	}
	defer mqStore.Close()

	h, err := golibp2p.New(golibp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create libp2p host: %v", err)
	}
	defer h.Close()

	cfg := &config.Config{
		Platform: config.PlatformConfig{Mode: "privacy", DataDir: tempDir},
		API:      config.APIConfig{AdminToken: "test-secret-token"},
	}

	auditLog, err := NewAuditLog(tempDir)
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
	defer auditLog.Close()

	adminHandler := AdminHandler(cfg, regStore, mqStore, h, auditLog)

	t.Run("Unauthorized - No Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("Unauthorized - Wrong Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
		req.Header.Set("X-Admin-Token", "wrong-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("Authorized - Overview Stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode overview resp: %v", err)
		}

		if resp["status"] != "ok" {
			t.Errorf("expected status 'ok', got %v", resp["status"])
		}
		if resp["peer_id"] != h.ID().String() {
			t.Errorf("expected peer_id %s, got %v", h.ID().String(), resp["peer_id"])
		}
		if resp["platform_mode"] != "privacy" {
			t.Errorf("expected platform_mode 'privacy', got %v", resp["platform_mode"])
		}
	})

	t.Run("Authorized - Registry List and Evict", func(t *testing.T) {
		// Register a dummy node
		err := regStore.RegisterWithSignature("urn:hermes:agent:testnode", "peer-id-xyz", []string{"/ip4/1.2.3.4/tcp/123"}, nil, nil, nil, nil, 0)
		if err != nil {
			t.Fatalf("register test node: %v", err)
		}

		// List
		req := httptest.NewRequest("GET", "/api/v1/admin/registry", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		entries := resp["entries"].([]interface{})
		if len(entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(entries))
		}

		// Evict
		evictReq := httptest.NewRequest("DELETE", "/api/v1/admin/registry?urn="+url.QueryEscape("urn:hermes:agent:testnode"), nil)
		evictReq.Header.Set("X-Admin-Token", "test-secret-token")
		w2 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w2, evictReq)

		if w2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for evict, got %d", w2.Code)
		}

		// Verify evicted
		entry, err := regStore.ResolveEntry("urn:hermes:agent:testnode")
		if err != nil {
			t.Fatalf("resolve error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected entry to be evicted/deleted")
		}
	})

	t.Run("Authorized - MQ Queue Stats and Clear", func(t *testing.T) {
		// Mock storing a message
		recipient := "urn:hermes:agent:offline-recipient"
		env := &pb.EncryptedEnvelope{
			MessageId:  "msg-1234",
			Ciphertext: []byte("fake-payload"),
		}
		_, err = mqStore.StoreEnvelope(context.Background(), recipient, env, time.Now().Add(1*time.Hour).Unix())
		if err != nil {
			t.Fatalf("mock MQ message insert: %v", err)
		}

		// List MQ queues
		req := httptest.NewRequest("GET", "/api/v1/admin/mq", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		queues := resp["queues"].([]interface{})
		if len(queues) != 1 {
			t.Errorf("expected 1 queue stats row, got %d", len(queues))
		}

		stat := queues[0].(map[string]interface{})
		if stat["recipient"] != recipient {
			t.Errorf("expected recipient %s, got %v", recipient, stat["recipient"])
		}
		if int(stat["count"].(float64)) != 1 {
			t.Errorf("expected count 1, got %v", stat["count"])
		}

		// Clear MQ queue
		clearReq := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/admin/mq/clear?urn=%s", url.QueryEscape(recipient)), nil)
		clearReq.Header.Set("X-Admin-Token", "test-secret-token")
		w2 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w2, clearReq)

		if w2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w2.Code)
		}

		// Verify cleared
		stats, err := mqStore.ListQueueStats(context.Background())
		if err != nil {
			t.Fatalf("list queue stats error: %v", err)
		}
		if len(stats) != 0 {
			t.Errorf("expected 0 queues, got %d", len(stats))
		}
	})

	t.Run("Authorized - Redacted Config", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/config", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp config.Config
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.API.AdminToken != "******" {
			t.Errorf("expected admin token to be redacted, got %s", resp.API.AdminToken)
		}
	})

	t.Run("Authorized - Peers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/peers", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode peers resp: %v", err)
		}
		if _, ok := resp["peers"]; !ok {
			t.Errorf("expected 'peers' key in response")
		}
		if _, ok := resp["count"]; !ok {
			t.Errorf("expected 'count' key in response")
		}
	})

	t.Run("Authorized - Logs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/logs", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode logs resp: %v", err)
		}
		entries := resp["entries"].([]interface{})
		if len(entries) < 2 {
			t.Errorf("expected at least 2 log entries from registry eviction and MQ purge, got %d", len(entries))
		}

		// Verify fields of the first entry (should be the MQ purge or eviction, order desc)
		entry := entries[0].(map[string]interface{})
		if _, ok := entry["timestamp"]; !ok {
			t.Errorf("expected 'timestamp' key in log entry")
		}
		if _, ok := entry["level"]; !ok {
			t.Errorf("expected 'level' key in log entry")
		}
		if _, ok := entry["source"]; !ok {
			t.Errorf("expected 'source' key in log entry")
		}
		if _, ok := entry["message"]; !ok {
			t.Errorf("expected 'message' key in log entry")
		}
	})
}
