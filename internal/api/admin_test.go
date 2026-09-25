package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/registry"
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
		Registry: config.RegistryConfig{TTLHours: 24},
		MQ:       config.MQConfig{MaxMsgsPerURN: 100},
		API:      config.APIConfig{AdminToken: "test-secret-token"},
	}

	auditLog, err := NewAuditLog(tempDir)
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
	defer auditLog.Close()

	policies := &SecurityPolicies{restart: func() {}}
	policies.StoreUserData.Store(true)
	policies.ForwardToStoragePlatforms.Store(true)

	cfgPath := filepath.Join(tempDir, "config.yaml")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save initial config: %v", err)
	}

	adminHandler := AdminHandler(cfg, regStore, mqStore, h, auditLog, policies, cfgPath, nil)

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
		if resp["registry_ttl_hours"] != float64(24) || resp["mq_max_msgs_per_urn"] != float64(100) {
			t.Errorf("expected configured registry TTL and MQ limit, got %v", resp)
		}
	})

	t.Run("Authorized - Registry List and Evict", func(t *testing.T) {
		key, err := crypto.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		registerAdminTestIdentity(t, regStore, key)

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
		evictReq := httptest.NewRequest("DELETE", "/api/v1/admin/registry?urn="+url.QueryEscape(key.URN()), nil)
		evictReq.Header.Set("X-Admin-Token", "test-secret-token")
		w2 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w2, evictReq)

		if w2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for evict, got %d", w2.Code)
		}

		// Verify evicted
		entry, err := regStore.ResolveEntry(key.URN())
		if err != nil {
			t.Fatalf("resolve error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected entry to be evicted/deleted")
		}
	})

	t.Run("Authorized - MQ Queue Stats and Clear", func(t *testing.T) {
		// Mock storing a message
		fixtureKey, _ := crypto.GenerateIdentityKeyPair()
		fixtureCtx := coremq.WithAuthenticatedPublicKey(context.Background(), fixtureKey.PublicKey)
		recipient := fixtureKey.URN()
		env := &pb.EncryptedEnvelope{
			MessageId:  "msg-1234",
			Ciphertext: []byte("fake-payload"),
		}
		_, err = mqStore.StoreEnvelope(fixtureCtx, recipient, signAdminTestEnvelope(t, fixtureKey, env), time.Now().Add(1*time.Hour).Unix())
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
		for _, rawPeer := range resp["peers"].([]interface{}) {
			peer := rawPeer.(map[string]interface{})
			if _, ok := peer["stores_user_data"]; ok {
				t.Error("peer connection must not imply an unverified storage policy")
			}
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

	t.Run("Authorized - Toggle Policies", func(t *testing.T) {
		// 1. Toggle Storage Policy
		reqToggleStorage := httptest.NewRequest("POST", "/api/v1/admin/config/toggle-storage", nil)
		reqToggleStorage.Header.Set("X-Admin-Token", "test-secret-token")
		w1 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w1, reqToggleStorage)

		if w1.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w1.Code)
		}

		var resp1 map[string]interface{}
		json.NewDecoder(w1.Body).Decode(&resp1)
		if resp1["ok"] != true || resp1["store_user_data"] != false {
			t.Errorf("expected store_user_data toggle to return false, got %v", resp1)
		}

		// Verify state in policies
		if policies.StoreUserData.Load() != false {
			t.Error("expected StoreUserData policy to be false in memory")
		}

		// 2. Toggle Forwarding Policy
		reqToggleForwarding := httptest.NewRequest("POST", "/api/v1/admin/config/toggle-forwarding", nil)
		reqToggleForwarding.Header.Set("X-Admin-Token", "test-secret-token")
		w2 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w2, reqToggleForwarding)

		if w2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w2.Code)
		}

		var resp2 map[string]interface{}
		json.NewDecoder(w2.Body).Decode(&resp2)
		if resp2["ok"] != true || resp2["forward_to_storage_platforms"] != false {
			t.Errorf("expected forward_to_storage_platforms toggle to return false, got %v", resp2)
		}

		// Verify state in policies
		if policies.ForwardToStoragePlatforms.Load() != false {
			t.Error("expected ForwardToStoragePlatforms policy to be false in memory")
		}

		// 3. Verify in Overview
		reqOverview := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
		reqOverview.Header.Set("X-Admin-Token", "test-secret-token")
		w3 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w3, reqOverview)

		var resp3 map[string]interface{}
		json.NewDecoder(w3.Body).Decode(&resp3)
		if resp3["stores_user_data"] != false || resp3["forward_to_storage_platforms"] != false {
			t.Errorf("expected overview to show false policies, got: %+v", resp3)
		}
		configReq := httptest.NewRequest("GET", "/api/v1/admin/config", nil)
		configReq.Header.Set("X-Admin-Token", "test-secret-token")
		configResp := httptest.NewRecorder()
		adminHandler.ServeHTTP(configResp, configReq)
		var runtimeConfig config.Config
		if err := json.NewDecoder(configResp.Body).Decode(&runtimeConfig); err != nil {
			t.Fatal(err)
		}
		if runtimeConfig.Platform.StoreUserData || runtimeConfig.Platform.ForwardToStoragePlatforms {
			t.Errorf("config endpoint must report current runtime policies: %+v", runtimeConfig.Platform)
		}

		// 4. A second request before restart must not reverse the policy.
		w4 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w4, reqToggleStorage)
		var resp4 map[string]interface{}
		json.NewDecoder(w4.Body).Decode(&resp4)
		if w4.Code != http.StatusConflict || resp4["restart_pending"] != true {
			t.Errorf("expected restart-pending conflict, got status %d body %v", w4.Code, resp4)
		}
		if policies.StoreUserData.Load() || !policies.RegistryResetPending.Load() {
			t.Fatal("second toggle changed policy while restart was pending")
		}
		reloaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.Platform.StoreUserData || !reloaded.AdminRegistryResetPending {
			t.Errorf("second toggle changed persisted policy: %+v", reloaded)
		}
		retentionDuringRestart := httptest.NewRequest("POST", "/api/v1/admin/config/set-retention?days=45", nil)
		retentionDuringRestart.Header.Set("X-Admin-Token", "test-secret-token")
		retentionResp := httptest.NewRecorder()
		adminHandler.ServeHTTP(retentionResp, retentionDuringRestart)
		if retentionResp.Code != http.StatusConflict {
			t.Errorf("retention update during pending storage restart returned %d", retentionResp.Code)
		}
		reloadedAfterConflict, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if reloadedAfterConflict.Platform.HistoryRetentionDays != reloaded.Platform.HistoryRetentionDays || !reloadedAfterConflict.AdminRegistryResetPending {
			t.Fatal("retention conflict overwrote pending storage transition")
		}
		// Simulate completion of the startup recovery before following subtests.
		reloaded.AdminRegistryResetPending = false
		if err := config.SaveAdminPolicies(reloaded); err != nil {
			t.Fatal(err)
		}
		policies.RegistryResetPending.Store(false)
	})

	t.Run("Authorized - Set Retention Days", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/admin/config/set-retention?days=45", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["ok"] != true || int(resp["history_retention_days"].(float64)) != 45 {
			t.Errorf("unexpected response: %v", resp)
		}

		// Verify on mqStore
		if mqStore.GetHistoryRetentionDays() != 45 {
			t.Errorf("expected retention days on mqStore to be 45, got %d", mqStore.GetHistoryRetentionDays())
		}

		// Verify configuration was persisted by reloading config
		reloaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("load reloaded config: %v", err)
		}
		if reloaded.Platform.HistoryRetentionDays != 45 {
			t.Errorf("expected platform history_retention_days to be 45, got %d", reloaded.Platform.HistoryRetentionDays)
		}
		for _, invalid := range []string{"-1", "36501", "1.9", "1e3"} {
			req := httptest.NewRequest("POST", "/api/v1/admin/config/set-retention?days="+url.QueryEscape(invalid), nil)
			req.Header.Set("X-Admin-Token", "test-secret-token")
			w := httptest.NewRecorder()
			adminHandler.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest || mqStore.GetHistoryRetentionDays() != 45 {
				t.Errorf("invalid days %q changed retention or returned %d", invalid, w.Code)
			}
		}
		zeroReq := httptest.NewRequest("POST", "/api/v1/admin/config/set-retention?days=0", nil)
		zeroReq.Header.Set("X-Admin-Token", "test-secret-token")
		zeroResp := httptest.NewRecorder()
		adminHandler.ServeHTTP(zeroResp, zeroReq)
		if zeroResp.Code != http.StatusOK || mqStore.GetHistoryRetentionDays() != 0 {
			t.Errorf("zero-day retention rejected: %d %s", zeroResp.Code, zeroResp.Body.String())
		}
	})

	t.Run("Authorized - MQ Messages Detail", func(t *testing.T) {
		fixtureKey, _ := crypto.GenerateIdentityKeyPair()
		fixtureCtx := coremq.WithAuthenticatedPublicKey(context.Background(), fixtureKey.PublicKey)
		recipient := fixtureKey.URN()
		env1 := &pb.EncryptedEnvelope{
			MessageId:  "msg-detail-pending",
			Ciphertext: []byte("pending-payload"),
		}
		env2 := &pb.EncryptedEnvelope{
			MessageId:  "msg-detail-history",
			Ciphertext: []byte("history-payload"),
		}

		// Store pending
		_, err := mqStore.StoreEnvelope(fixtureCtx, recipient, signAdminTestEnvelope(t, fixtureKey, env1), time.Now().Add(1*time.Hour).Unix())
		if err != nil {
			t.Fatalf("store pending error: %v", err)
		}

		// Store history (by storing and then ACK-ing it)
		id2, err := mqStore.StoreEnvelope(fixtureCtx, recipient, signAdminTestEnvelope(t, fixtureKey, env2), time.Now().Add(1*time.Hour).Unix())
		if err != nil {
			t.Fatalf("store history msg error: %v", err)
		}
		_, err = mqStore.Ack(fixtureCtx, recipient, []string{id2})
		if err != nil {
			t.Fatalf("ack msg error: %v", err)
		}

		// 1. Query pending messages details
		req1 := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/admin/mq/messages?urn=%s&status=pending", url.QueryEscape(recipient)), nil)
		req1.Header.Set("X-Admin-Token", "test-secret-token")
		w1 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w1, req1)

		if w1.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w1.Code)
		}

		var pendingMsgs []mqpkg.MessageDetail
		json.NewDecoder(w1.Body).Decode(&pendingMsgs)
		if len(pendingMsgs) != 1 {
			t.Errorf("expected 1 pending msg detail, got %d", len(pendingMsgs))
		} else {
			if pendingMsgs[0].ID != "msg-detail-pending" {
				t.Errorf("expected message ID 'msg-detail-pending', got %s", pendingMsgs[0].ID)
			}
			if pendingMsgs[0].Payload != "70656e64696e672d7061796c6f6164" { // "pending-payload" in hex
				t.Errorf("expected hex payload, got %s", pendingMsgs[0].Payload)
			}
			if pendingMsgs[0].ReadAt != 0 {
				t.Errorf("expected read_at to be 0 for pending message, got %d", pendingMsgs[0].ReadAt)
			}
		}

		// 2. Query history messages details
		req2 := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/admin/mq/messages?urn=%s&status=history", url.QueryEscape(recipient)), nil)
		req2.Header.Set("X-Admin-Token", "test-secret-token")
		w2 := httptest.NewRecorder()
		adminHandler.ServeHTTP(w2, req2)

		if w2.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w2.Code)
		}

		var historyMsgs []mqpkg.MessageDetail
		json.NewDecoder(w2.Body).Decode(&historyMsgs)
		if len(historyMsgs) != 1 {
			t.Errorf("expected 1 history msg detail, got %d", len(historyMsgs))
		} else {
			if historyMsgs[0].ID != "msg-detail-history" {
				t.Errorf("expected message ID 'msg-detail-history', got %s", historyMsgs[0].ID)
			}
			if historyMsgs[0].Payload != "686973746f72792d7061796c6f6164" { // "history-payload" in hex
				t.Errorf("expected hex payload, got %s", historyMsgs[0].Payload)
			}
			if historyMsgs[0].ReadAt == 0 {
				t.Error("expected read_at > 0 for history message")
			}
		}
	})
}

func TestAdminFiltering(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "api-admin-filter-test")
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

	// Local host
	h, err := golibp2p.New(golibp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create libp2p host: %v", err)
	}
	defer h.Close()

	cfg := &config.Config{
		Platform: config.PlatformConfig{Mode: "privacy", DataDir: tempDir},
		API:      config.APIConfig{AdminToken: "test-secret-token"},
	}
	policies := &SecurityPolicies{}
	policies.StoreUserData.Store(true)
	policies.ForwardToStoragePlatforms.Store(true)

	cfgPath := filepath.Join(tempDir, "config.yaml")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	adminHandler := AdminHandler(cfg, regStore, mqStore, h, nil, policies, cfgPath, nil)

	localPeerID := h.ID().String()

	// 1. Register local platform
	rawPrivate, err := h.Peerstore().PrivKey(h.ID()).Raw()
	if err != nil {
		t.Fatal(err)
	}
	localPrivate := ed25519.PrivateKey(rawPrivate)
	localKey := &crypto.IdentityKeyPair{PrivateKey: localPrivate, PublicKey: localPrivate.Public().(ed25519.PublicKey)}
	registerAdminTestIdentity(t, regStore, localKey)

	// 2. Register a separate agent
	agentKey, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	registerAdminTestIdentity(t, regStore, agentKey)

	// Test registry list filters out local platform
	t.Run("Registry list filters local platform", func(t *testing.T) {
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

		// Should only contain the agent, not the local platform
		if len(entries) != 1 {
			t.Errorf("expected 1 entry, got %d", len(entries))
		}

		entryMap := entries[0].(map[string]interface{})
		if entryMap["PeerID"] == localPeerID {
			t.Errorf("expected agent peer ID, got local platform peer ID")
		}
	})

	// Test overview registry count filters local platform
	t.Run("Overview registry_count filters local platform", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/admin/overview", nil)
		req.Header.Set("X-Admin-Token", "test-secret-token")
		w := httptest.NewRecorder()
		adminHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)

		regCount := int(resp["registry_count"].(float64))
		if regCount != 1 {
			t.Errorf("expected registry_count to be 1 (only Normal Agent), got %d", regCount)
		}
	})
}

func TestAdminPolicyWriteFailureDoesNotChangeLiveState(t *testing.T) {
	dataDir := t.TempDir()
	regStore, err := registrypkg.NewStore(filepath.Join(dataDir, "registry.db"), 24)
	if err != nil {
		t.Fatal(err)
	}
	defer regStore.Close()
	mqStore, err := mqpkg.NewStore(filepath.Join(dataDir, "mq.db"), 7, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer mqStore.Close()
	h, err := golibp2p.New(golibp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	key, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	registerAdminTestIdentity(t, regStore, key)

	blockedDir := filepath.Join(dataDir, "not-a-directory")
	if err := os.WriteFile(blockedDir, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Platform.DataDir = blockedDir
	cfg.Platform.HistoryRetentionDays = 30
	cfg.API.AdminToken = "test-secret-token"
	policies := &SecurityPolicies{restart: func() { t.Error("restart on failed policy write") }}
	policies.StoreUserData.Store(true)
	mqStore.SetHistoryRetentionDays(30)
	handler := AdminHandler(cfg, regStore, mqStore, h, nil, policies, "", nil)

	for _, endpoint := range []string{
		"/api/v1/admin/config/toggle-storage",
		"/api/v1/admin/config/set-retention?days=0",
	} {
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)
		req.Header.Set("X-Admin-Token", cfg.API.AdminToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: expected persistence error, got %d: %s", endpoint, w.Code, w.Body.String())
		}
	}
	if !policies.StoreUserData.Load() || !cfg.Platform.StoreUserData {
		t.Fatal("storage policy changed despite persistence failure")
	}
	if cfg.Platform.HistoryRetentionDays != 30 || mqStore.GetHistoryRetentionDays() != 30 {
		t.Fatal("retention changed despite persistence failure")
	}
	entry, err := regStore.ResolveEntry(key.URN())
	if err != nil || entry == nil {
		t.Fatalf("registry was cleared despite persistence failure: entry=%v err=%v", entry, err)
	}
}

func registerAdminTestIdentity(t *testing.T, store registry.Store, key *crypto.IdentityKeyPair) {
	t.Helper()
	peerID, err := key.PeerID()
	if err != nil {
		t.Fatal(err)
	}
	_, x25519PK, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().Unix()
	signature := ed25519.Sign(key.PrivateKey, registry.BuildSignedMsg(key.URN(), peerID, x25519PK, false, timestamp))
	if err := store.RegisterWithSignature(key.URN(), peerID, []string{"/ip4/127.0.0.1/tcp/123"}, nil,
		x25519PK, key.PublicKey, signature, false, timestamp); err != nil {
		t.Fatalf("register test identity: %v", err)
	}
}

func signAdminTestEnvelope(t *testing.T, key *crypto.IdentityKeyPair, env *pb.EncryptedEnvelope) *pb.EncryptedEnvelope {
	t.Helper()
	env.SenderUrn, env.RecipientUrn = key.URN(), key.URN()
	env.SenderStaticPubkey, env.EphemeralPubkey = make([]byte, 32), make([]byte, 32)
	env.Nonce, env.Tag = make([]byte, 12), make([]byte, 16)
	if err := crypto.SignEnvelope(env, key); err != nil {
		t.Fatal(err)
	}
	return env
}
