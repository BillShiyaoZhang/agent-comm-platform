package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
)

func adminMailboxURN(r *http.Request) string {
	urn := r.URL.Query().Get("urn")
	if len(urn) > 512 || strings.TrimSpace(urn) != urn {
		return ""
	}
	return urn
}

func adminMessageID(r *http.Request) string {
	id := r.URL.Query().Get("id")
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "\x00\r\n") {
		return ""
	}
	return id
}

func handleAdminMQMessagesPage(store *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := adminMailboxURN(r)
		if urn == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "valid urn query parameter required"})
			return
		}
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "pending"
		}
		if status != "pending" && status != "history" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "status must be pending or history"})
			return
		}
		limit, offset := 25, 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 200 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "limit must be an integer from 1 to 200"})
				return
			}
		}
		if raw := r.URL.Query().Get("offset"); raw != "" {
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
		entries, total, err := store.ListMessagesPage(ctx, urn, status, limit, offset)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not load mailbox page"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": entries,
			"total":   total,
			"limit":   limit,
			"offset":  offset,
		})
	}
}

func handleAdminMQMessageDetail(store *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn, id := adminMailboxURN(r), adminMessageID(r)
		if urn == "" || id == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "valid urn and id query parameters required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		detail, err := store.GetMessageDetail(ctx, urn, id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not load message detail"})
			return
		}
		if detail == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "message not found in mailbox"})
			return
		}
		json.NewEncoder(w).Encode(detail)
	}
}

func handleAdminMQMessageDelete(store *mqpkg.Store, auditLog *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := adminMailboxURN(r)
		id := adminMessageID(r)
		if urn == "" || id == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "valid urn and id query parameters required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		deleted, err := store.DeleteMessage(ctx, urn, id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not delete message"})
			return
		}
		if deleted > 0 && auditLog != nil {
			auditLog.Record("warn", "mq", "Deleted MQ message "+id+" for: "+urn, "")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": deleted})
	}
}

func handleAdminMQSummary(store *mqpkg.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		summary, err := store.SummarizeMessages(ctx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not load MQ summary"})
			return
		}
		json.NewEncoder(w).Encode(summary)
	}
}
