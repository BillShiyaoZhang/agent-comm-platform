package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

var startTime = time.Now()

// AdminHandler returns an http.Handler serving all admin APIs, wrapped with token auth.
func AdminHandler(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host, auditLog *AuditLog) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/admin/overview", handleOverview(cfg, regStore, mqStore, h))
	mux.HandleFunc("GET /api/v1/admin/registry", handleAdminRegistryList(regStore))
	mux.HandleFunc("DELETE /api/v1/admin/registry", handleAdminRegistryEvict(regStore, auditLog))
	mux.HandleFunc("GET /api/v1/admin/mq", handleAdminMQList(mqStore))
	mux.HandleFunc("DELETE /api/v1/admin/mq/clear", handleAdminMQClear(mqStore, auditLog))
	mux.HandleFunc("GET /api/v1/admin/config", handleAdminConfig(cfg))
	mux.HandleFunc("GET /api/v1/admin/peers", handleAdminPeers(h))
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

func handleOverview(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		urns, _ := regStore.ListURNs()
		mqStats, _ := mqStore.ListQueueStats(r.Context())

		totalPendingMessages := 0
		for _, stat := range mqStats {
			totalPendingMessages += stat.Count
		}

		addrs := []string{}
		for _, addr := range h.Addrs() {
			addrs = append(addrs, addr.String()+"/p2p/"+h.ID().String())
		}

		// Count inbound/outbound connections
		inbound := 0
		outbound := 0
		for _, peer := range h.Network().Peers() {
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
			"status":            "ok",
			"uptime_seconds":    int64(time.Since(startTime).Seconds()),
			"go_version":        runtime.Version(),
			"goroutines":        runtime.NumGoroutine(),
			"memory_alloc_mb":   float64(m.Alloc) / 1024 / 1024,
			"memory_sys_mb":     float64(m.Sys) / 1024 / 1024,
			"platform_mode":     cfg.Platform.Mode,
			"peer_id":           h.ID().String(),
			"listen_addrs":      addrs,
			"connected_peers":   len(h.Network().Peers()),
			"inbound_conns":     inbound,
			"outbound_conns":    outbound,
			"registry_count":    len(urns),
			"mq_queues_count":   len(mqStats),
			"mq_messages_count": totalPendingMessages,
		}

		json.NewEncoder(w).Encode(resp)
	}
}

func handleAdminRegistryList(regStore *registrypkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := regStore.ListEntries()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": entries,
			"count":   len(entries),
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

// PeerInfo represents information about a connected libp2p peer.
type PeerInfo struct {
	PeerID    string   `json:"peer_id"`
	Addrs     []string `json:"addrs"`
	Direction string   `json:"direction"` // "inbound", "outbound", "both"
	ConnCount int      `json:"conn_count"`
	Protocols []string `json:"protocols"`
}

func handleAdminPeers(h host.Host) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peers := h.Network().Peers()
		infos := make([]*PeerInfo, 0, len(peers))

		for _, pid := range peers {
			conns := h.Network().ConnsToPeer(pid)
			if len(conns) == 0 {
				continue
			}

			info := &PeerInfo{
				PeerID:    pid.String(),
				ConnCount: len(conns),
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
