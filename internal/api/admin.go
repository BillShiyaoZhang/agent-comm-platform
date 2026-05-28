package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

var startTime = time.Now()

// AdminHandler returns an http.Handler serving all admin APIs, wrapped with token auth.
func AdminHandler(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host, auditLog *AuditLog, policies *SecurityPolicies, cfgPath string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/admin/overview", handleOverview(cfg, regStore, mqStore, h, policies))
	mux.HandleFunc("GET /api/v1/admin/registry", handleAdminRegistryList(h, regStore))
	mux.HandleFunc("DELETE /api/v1/admin/registry", handleAdminRegistryEvict(regStore, auditLog))
	mux.HandleFunc("GET /api/v1/admin/mq", handleAdminMQList(mqStore))
	mux.HandleFunc("DELETE /api/v1/admin/mq/clear", handleAdminMQClear(mqStore, auditLog))
	mux.HandleFunc("GET /api/v1/admin/mq/messages", handleAdminMQMessages(mqStore))
	mux.HandleFunc("GET /api/v1/admin/config", handleAdminConfig(cfg))
	mux.HandleFunc("POST /api/v1/admin/config/toggle-storage", handleToggleStorage(cfg, regStore, policies, auditLog, cfgPath))
	mux.HandleFunc("POST /api/v1/admin/config/toggle-forwarding", handleToggleForwarding(policies, auditLog))
	mux.HandleFunc("POST /api/v1/admin/config/set-retention", handleSetRetention(cfg, mqStore, auditLog, cfgPath))
	mux.HandleFunc("GET /api/v1/admin/peers", handleAdminPeers(h, regStore))
	mux.HandleFunc("GET /api/v1/admin/logs", handleAdminLogs(auditLog))

	return adminAuth(cfg.API.AdminToken, mux)
}

func adminAuth(adminToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if adminToken == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Admin interface disabled: admin_token not configured in config.yaml"}`))
			return
		}

		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			// Fallback: check query parameter for visual interface convenience
			token = r.URL.Query().Get("token")
		}

		if token != adminToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleOverview(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host, policies *SecurityPolicies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		mqStats, _ := mqStore.ListQueueStats(r.Context())

		totalPendingMessages := 0
		for _, stat := range mqStats {
			totalPendingMessages += stat.Count
		}

		addrs := []string{}
		for _, addr := range h.Addrs() {
			addrs = append(addrs, addr.String()+"/p2p/"+h.ID().String())
		}

		localPeerID := h.ID().String()
		agentPeers := make(map[string]bool)
		agentCount := 0
		if entries, err := regStore.ListEntries(); err == nil {
			for _, entry := range entries {
				if entry.PeerID != localPeerID {
					agentCount++
					agentPeers[entry.PeerID] = true
				}
			}
		}

		// Count inbound/outbound connections for other platforms only
		platformPeersCount := 0
		inbound := 0
		outbound := 0
		for _, peer := range h.Network().Peers() {
			if agentPeers[peer.String()] {
				continue
			}
			platformPeersCount++
			for _, conn := range h.Network().ConnsToPeer(peer) {
				switch conn.Stat().Direction {
				case network.DirInbound:
					inbound++
				case network.DirOutbound:
					outbound++
				}
			}
		}

		resp := map[string]interface{}{
			"status":                       "ok",
			"uptime_seconds":               int64(time.Since(startTime).Seconds()),
			"go_version":                   runtime.Version(),
			"goroutines":                   runtime.NumGoroutine(),
			"memory_alloc_mb":              float64(m.Alloc) / 1024 / 1024,
			"memory_sys_mb":                float64(m.Sys) / 1024 / 1024,
			"platform_mode":                cfg.Platform.Mode,
			"stores_user_data":             policies.StoreUserData.Load(),
			"forward_to_storage_platforms": policies.ForwardToStoragePlatforms.Load(),
			"history_retention_days":       cfg.Platform.HistoryRetentionDays,
			"peer_id":                      h.ID().String(),
			"listen_addrs":                 addrs,
			"connected_peers":              platformPeersCount,
			"inbound_conns":                inbound,
			"outbound_conns":               outbound,
			"registry_count":               agentCount,
			"mq_queues_count":              len(mqStats),
			"mq_messages_count":            totalPendingMessages,
		}

		json.NewEncoder(w).Encode(resp)
	}
}

func handleAdminRegistryList(h host.Host, regStore *registrypkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := regStore.ListEntries()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		localPeerID := h.ID().String()
		filtered := make([]*registrypkg.Entry, 0)
		for _, entry := range entries {
			if entry.PeerID != localPeerID {
				filtered = append(filtered, entry)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": filtered,
			"count":   len(filtered),
		})
	}
}

func handleAdminRegistryEvict(regStore *registrypkg.Store, auditLog *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.URL.Query().Get("urn")
		if urn == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"urn query parameter required"}`))
			return
		}

		if err := regStore.EvictEntry(urn); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		if auditLog != nil {
			auditLog.Record("warn", "registry", "Evicted node from registry: "+urn, "")
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

func handleAdminMQList(mqStore *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := mqStore.ListQueueStats(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"queues": stats,
			"count":  len(stats),
		})
	}
}

func handleAdminMQClear(mqStore *mqpkg.Store, auditLog *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.URL.Query().Get("urn")
		if urn == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"urn query parameter required"}`))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		deleted, err := mqStore.PurgeQueue(ctx, urn)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		if auditLog != nil {
			auditLog.Record("warn", "mq", "Purged MQ queue for: "+urn, "deleted "+itoa(deleted)+" messages")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"deleted": deleted,
		})
	}
}

func handleAdminConfig(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a copy of config and redact sensitive fields
		redacted := *cfg
		redacted.API.AdminToken = "******"
		json.NewEncoder(w).Encode(redacted)
	}
}

func handleToggleStorage(cfg *config.Config, regStore *registrypkg.Store, policies *SecurityPolicies, auditLog *AuditLog, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current := policies.StoreUserData.Load()
		next := !current
		policies.StoreUserData.Store(next)
		cfg.Platform.StoreUserData = next

		// Save configuration
		if err := config.Save(cfgPath, cfg); err != nil {
			log.Printf("[api] failed to save config on toggle-storage: %v", err)
		}

		// Clear all registry entries to force re-registration
		if err := regStore.ClearAllEntries(); err != nil {
			log.Printf("[api] failed to clear registry entries on toggle-storage: %v", err)
		}

		msg := fmt.Sprintf("Changed platform store user data policy to: %t, triggering registry purge and reboot", next)
		if auditLog != nil {
			auditLog.Record("warn", "admin", msg, "")
		}

		// Gracefully restart the platform in 500ms (Docker compose unless-stopped will pull it back up)
		go func() {
			time.Sleep(500 * time.Millisecond)
			log.Printf("[api] rebooting platform for security policy change...")
			os.Exit(0)
		}()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":              true,
			"store_user_data": next,
		})
	}
}

func handleToggleForwarding(policies *SecurityPolicies, auditLog *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current := policies.ForwardToStoragePlatforms.Load()
		next := !current
		policies.ForwardToStoragePlatforms.Store(next)

		msg := fmt.Sprintf("Changed platform forwarding to storage platforms policy to: %t", next)
		if auditLog != nil {
			auditLog.Record("warn", "admin", msg, "")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                           true,
			"forward_to_storage_platforms": next,
		})
	}
}

// PeerInfo represents information about a connected libp2p peer.
type PeerInfo struct {
	PeerID         string   `json:"peer_id"`
	Addrs          []string `json:"addrs"`
	Direction      string   `json:"direction"` // "inbound", "outbound", "both"
	ConnCount      int      `json:"conn_count"`
	Protocols      []string `json:"protocols"`
	StoresUserData bool     `json:"stores_user_data"`
}

func handleAdminPeers(h host.Host, regStore *registrypkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		localPeerID := h.ID().String()
		agentPeers := make(map[string]bool)
		peerToStorage := make(map[string]bool)
		if regStore != nil {
			entries, err := regStore.ListEntries()
			if err == nil {
				for _, entry := range entries {
					if entry.PeerID != localPeerID {
						agentPeers[entry.PeerID] = true
						peerToStorage[entry.PeerID] = entry.StoresUserData
					}
				}
			}
		}

		peers := h.Network().Peers()
		infos := make([]*PeerInfo, 0, len(peers))

		for _, pid := range peers {
			if agentPeers[pid.String()] {
				continue
			}

			conns := h.Network().ConnsToPeer(pid)
			if len(conns) == 0 {
				continue
			}

			info := &PeerInfo{
				PeerID:         pid.String(),
				ConnCount:      len(conns),
				StoresUserData: peerToStorage[pid.String()],
			}

			// Determine direction
			hasIn, hasOut := false, false
			addrsMap := map[string]bool{}
			for _, c := range conns {
				switch c.Stat().Direction {
				case network.DirInbound:
					hasIn = true
				case network.DirOutbound:
					hasOut = true
				}
				addr := c.RemoteMultiaddr().String()
				addrsMap[addr] = true
			}

			if hasIn && hasOut {
				info.Direction = "both"
			} else if hasIn {
				info.Direction = "inbound"
			} else {
				info.Direction = "outbound"
			}

			for addr := range addrsMap {
				info.Addrs = append(info.Addrs, addr)
			}

			// Get protocols
			protos, err := h.Peerstore().GetProtocols(pid)
			if err == nil {
				protoStrs := make([]string, len(protos))
				for i, p := range protos {
					protoStrs[i] = string(p)
				}
				info.Protocols = protoStrs
			}

			infos = append(infos, info)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"peers": infos,
			"count": len(infos),
		})
	}
}

func handleSetRetention(cfg *config.Config, mqStore *mqpkg.Store, auditLog *AuditLog, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"error":"Method Not Allowed"}`))
			return
		}

		daysStr := r.URL.Query().Get("days")
		if daysStr == "" {
			daysStr = r.FormValue("days")
		}
		if daysStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"days parameter required"}`))
			return
		}

		days, err := strconv.Atoi(daysStr)
		if err != nil || days < 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid days value: must be a positive integer"}`))
			return
		}

		cfg.Platform.HistoryRetentionDays = days
		mqStore.SetHistoryRetentionDays(days)

		if err := config.Save(cfgPath, cfg); err != nil {
			log.Printf("[api] failed to save config on set-retention: %v", err)
		}

		if auditLog != nil {
			auditLog.Record("info", "admin", "Set MQ history retention days to: "+strconv.Itoa(days), "")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                     true,
			"history_retention_days": days,
		})
	}
}

func handleAdminMQMessages(mqStore *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.URL.Query().Get("urn")
		if urn == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"urn query parameter required"}`))
			return
		}

		status := r.URL.Query().Get("status")
		if status != "pending" && status != "history" {
			status = "pending"
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		details, err := mqStore.ListMessagesDetail(ctx, urn, status)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	}
}

