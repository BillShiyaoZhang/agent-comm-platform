package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
)

// Compliance history is exposed exclusively through the authenticated admin mux.
// A page contains metadata; the plaintext is loaded only for an explicit detail.
func handleAdminComplianceMessages(store *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		sender, recipient := query.Get("sender"), query.Get("recipient")
		for _, urn := range []string{sender, recipient} {
			if len(urn) > 512 || strings.TrimSpace(urn) != urn || strings.ContainsAny(urn, "\x00\r\n") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid sender or recipient filter"})
				return
			}
		}
		limit, offset := 25, 0
		if raw := query.Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 200 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "limit must be an integer from 1 to 200"})
				return
			}
		}
		if raw := query.Get("offset"); raw != "" {
			var err error
			offset, err = strconv.Atoi(raw)
			if err != nil || offset < 0 || offset > 1000000 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "offset must be an integer from 0 to 1000000"})
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		entries, total, err := store.ListComplianceMessagesPage(ctx, sender, recipient, limit, offset)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not load compliance history"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": entries, "total": total, "limit": limit, "offset": offset})
	}
}

func handleAdminComplianceMessageDetail(store *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := adminMessageID(r)
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "valid id query parameter required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		detail, err := store.GetComplianceMessage(ctx, id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not load compliance message"})
			return
		}
		if detail == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "compliance message not found or retention elapsed"})
			return
		}
		json.NewEncoder(w).Encode(detail)
	}
}

func handleSetComplianceRetention(cfg *config.Config, store *mqpkg.Store, policies *SecurityPolicies, auditLog *AuditLog, policyMu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Keep the existing retention endpoint's query/form contract, with a
		// bounded body and a single explicit value.
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if err := r.ParseForm(); err != nil || len(r.Form["days"]) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "exactly one days parameter required"})
			return
		}
		days, err := strconv.Atoi(r.Form.Get("days"))
		if err != nil || config.ValidateComplianceRetentionDays(days) != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "days must be an integer from 0 to 36500"})
			return
		}
		policyMu.Lock()
		defer policyMu.Unlock()
		if policies.RegistryResetPending.Load() || policies.ConfigRestartPending.Load() {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{"error": "configuration change is pending restart; wait before changing compliance retention", "restart_pending": true})
			return
		}
		updated := *cfg
		updated.Platform.StoreUserData = policies.StoreUserData.Load()
		updated.Platform.ForwardToStoragePlatforms = policies.ForwardToStoragePlatforms.Load()
		updated.Platform.HistoryRetentionDays = store.GetHistoryRetentionDays()
		updated.Platform.ComplianceRetentionDays = days
		updated.AdminRegistryResetPending = policies.RegistryResetPending.Load()
		if err := config.SaveAdminPolicies(&updated); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not persist compliance retention"})
			return
		}
		if err := store.SetComplianceRetentionDays(days); err != nil {
			// A failed cleanup leaves the live setting and plaintext intact.
			// Restore the persisted setting so a later restart agrees with it.
			updated.Platform.ComplianceRetentionDays = store.GetComplianceRetentionDays()
			message := "could not apply compliance retention; previous setting retained"
			if rollbackErr := config.SaveAdminPolicies(&updated); rollbackErr != nil {
				message = "could not apply compliance retention or restore persisted setting; reload and repair admin-policies.yaml before restarting"
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": message})
			return
		}
		if auditLog != nil {
			auditLog.Record("info", "admin", "Set compliance plaintext retention days to: "+strconv.Itoa(days), "")
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "compliance_retention_days": days})
	}
}
