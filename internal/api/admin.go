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
)

var startTime = time.Now()

// AdminHandler returns an http.Handler serving all admin APIs, wrapped with token auth.
func AdminHandler(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/admin/overview", handleOverview(cfg, regStore, mqStore, h))
	mux.HandleFunc("GET /api/v1/admin/registry", handleAdminRegistryList(regStore))
	mux.HandleFunc("DELETE /api/v1/admin/registry", handleAdminRegistryEvict(regStore))
	mux.HandleFunc("GET /api/v1/admin/mq", handleAdminMQList(mqStore))
	mux.HandleFunc("DELETE /api/v1/admin/mq/clear", handleAdminMQClear(mqStore))
	mux.HandleFunc("GET /api/v1/admin/config", handleAdminConfig(cfg))

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

func handleAdminRegistryEvict(regStore *registrypkg.Store) http.HandlerFunc {
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

func handleAdminMQClear(mqStore *mqpkg.Store) http.HandlerFunc {
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
