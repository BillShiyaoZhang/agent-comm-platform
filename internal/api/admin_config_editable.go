package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/BillShiyaoZhang/agent-comm/v2"
	"github.com/libp2p/go-libp2p/core/host"
)

// Only startup settings with a real runtime effect and safe data-directory
// persistence are editable here. Identity, network listeners, credentials and
// currently unused config.yaml switches remain server-managed.
type editableField struct {
	Key             string   `json:"key"`
	Type            string   `json:"type"`
	Min             int      `json:"min,omitempty"`
	Max             int      `json:"max,omitempty"`
	Unit            string   `json:"unit,omitempty"`
	Options         []string `json:"options,omitempty"`
	RestartRequired bool     `json:"restart_required"`
	ImpactZH        string   `json:"impact_zh"`
	ImpactEN        string   `json:"impact_en"`
}

var editableFields = []editableField{
	{"registry.ttl_hours", "integer", 1, 8760, "hours", nil, true, "现有注册记录的到期时间不变；后续注册和续期使用新时长。", "Existing registration expiry timestamps stay unchanged; new registrations and renewals use the new duration."},
	{"mq.default_ttl_days", "integer", 1, 3650, "days", nil, true, "现有消息的到期时间不变；新消息的最长保留时间改变。", "Existing message expiry timestamps stay unchanged; the maximum lifetime of new messages changes."},
	{"mq.max_msgs_per_urn", "integer", 1, 100000, "messages/URN", nil, true, "现有消息不会删除；已满或超过新上限的信箱会拒绝新消息，直到数量降到上限以下。", "Existing messages are not deleted; mailboxes at or above the new limit reject new messages until their count falls below it."},
	{"relay.enabled", "boolean", 0, 0, "", nil, true, "关闭 Relay 会撤销中继服务和现有预约，依赖本节点中继的 NAT 后客户端可能暂时失联。", "Disabling Relay removes the relay service and existing reservations; NAT-bound clients depending on this node may lose connectivity."},
	{"relay.max_reservations", "integer", 1, 100000, "reservations", nil, true, "重启会断开现有中继连接并释放预约；新上限只约束之后的预约。", "Restart disconnects existing relay circuits and reservations; the new limit applies to subsequent reservations."},
	{"relay.max_circuit_duration", "duration", 0, 0, "", []string{"30s", "1m", "2m", "5m", "10m", "30m", "1h"}, true, "重启会断开现有中继连接；新时长只约束之后建立的中继线路。", "Restart disconnects existing relay circuits; the new duration applies to newly established circuits."},
}

type editableRequest struct {
	ExpectedRevision  string                     `json:"expected_revision"`
	Changes           map[string]json.RawMessage `json:"changes"`
	ConfirmationToken string                     `json:"confirmation_token,omitempty"`
}

type editableChange struct {
	Key      string `json:"key"`
	Current  any    `json:"current"`
	Target   any    `json:"target"`
	ImpactZH string `json:"impact_zh"`
	ImpactEN string `json:"impact_en"`
}

func editableSettings(cfg *config.Config) map[string]any {
	return map[string]any{
		"registry.ttl_hours":         cfg.Registry.TTLHours,
		"mq.default_ttl_days":        cfg.MQ.DefaultTTLDays,
		"mq.max_msgs_per_urn":        cfg.MQ.MaxMsgsPerURN,
		"relay.enabled":              cfg.Relay.Enabled,
		"relay.max_reservations":     cfg.Relay.MaxReservations,
		"relay.max_circuit_duration": cfg.Relay.MaxCircuitDuration,
	}
}

func editableRevision(settings map[string]any) string {
	data, _ := json.Marshal(settings)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

const editablePreviewLifetime = 5 * time.Minute

func editableRequestKeys(changes map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(changes))
	for key := range changes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func editableConfirmationToken(key []byte, revision string, settings map[string]any, changes map[string]json.RawMessage, expiresAt time.Time) string {
	data, _ := json.Marshal(settings)
	requestedKeys, _ := json.Marshal(editableRequestKeys(changes))
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(revision))
	mac.Write([]byte{0})
	mac.Write(data)
	mac.Write([]byte{0})
	mac.Write(requestedKeys)
	mac.Write([]byte{0})
	mac.Write([]byte(expiry))
	return expiry + "." + hex.EncodeToString(mac.Sum(nil))
}

func validEditableConfirmationToken(key []byte, revision string, settings map[string]any, changes map[string]json.RawMessage, token string, now time.Time) bool {
	expiryText, signature, found := strings.Cut(token, ".")
	if !found {
		return false
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil || expiry < now.Unix() || expiry > now.Add(editablePreviewLifetime).Unix() {
		return false
	}
	expected := editableConfirmationToken(key, revision, settings, changes, time.Unix(expiry, 0))
	return hmac.Equal([]byte(token), []byte(expected)) && len(signature) == sha256.Size*2
}

func decodeEditableRequest(w http.ResponseWriter, r *http.Request) (editableRequest, error) {
	var input editableRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid JSON request")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return input, fmt.Errorf("exactly one JSON object is required")
	}
	if input.ExpectedRevision == "" || len(input.Changes) == 0 || len(input.Changes) > len(editableFields) {
		return input, fmt.Errorf("expected_revision and one or more allowlisted changes are required")
	}
	return input, nil
}

func applyEditableChanges(cfg *config.Config, changes map[string]json.RawMessage, gateway *mqpkg.V2Gateway) error {
	wasRelayEnabled := cfg.Relay.Enabled
	for key, raw := range changes {
		switch key {
		case "registry.ttl_hours":
			var v int
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
			cfg.Registry.TTLHours = v
		case "mq.default_ttl_days":
			var v int
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
			cfg.MQ.DefaultTTLDays = v
		case "mq.max_msgs_per_urn":
			var v int
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
			cfg.MQ.MaxMsgsPerURN = v
		case "relay.enabled":
			var v *bool
			if err := json.Unmarshal(raw, &v); err != nil || v == nil {
				return fmt.Errorf("%s must be a boolean", key)
			}
			cfg.Relay.Enabled = *v
		case "relay.max_reservations":
			var v int
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
			cfg.Relay.MaxReservations = v
		case "relay.max_circuit_duration":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s must be a duration string", key)
			}
			cfg.Relay.MaxCircuitDuration = v
		default:
			return fmt.Errorf("%s is not editable", key)
		}
	}
	for key := range changes {
		if err := config.ValidateAdminEditableSetting(cfg, key); err != nil {
			return err
		}
	}
	if !wasRelayEnabled && cfg.Relay.Enabled {
		for _, key := range []string{"relay.max_reservations", "relay.max_circuit_duration"} {
			if err := config.ValidateAdminEditableSetting(cfg, key); err != nil {
				return err
			}
		}
	}
	// A signed compliance policy rejects transparent Relay at startup. Check
	// the already verified policy here so a console edit cannot cause a restart loop.
	if gateway != nil && gateway.Policy != nil && gateway.Policy.Mode == v2.ModeCompliance && cfg.Relay.Enabled {
		return fmt.Errorf("compliance v2 policy requires relay.enabled=false; transparent libp2p relay cannot inspect message frames")
	}
	return nil
}

func editableChanges(current, target map[string]any) []editableChange {
	result := make([]editableChange, 0)
	for _, field := range editableFields {
		if current[field.Key] == target[field.Key] {
			continue
		}
		impactZH, impactEN := field.ImpactZH, field.ImpactEN
		if field.Key == "relay.enabled" && target[field.Key] == true {
			impactZH = "重启会断开当前连接；启用 Relay 后，本节点会重新接受中继预约。"
			impactEN = "Restart disconnects current connections; enabling Relay lets this node accept new relay reservations."
		}
		result = append(result, editableChange{field.Key, current[field.Key], target[field.Key], impactZH, impactEN})
	}
	return result
}

func editableRestartPending(policies *SecurityPolicies) bool {
	return policies.RegistryResetPending.Load() || policies.ConfigRestartPending.Load()
}

func editableConflict(w http.ResponseWriter) {
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(map[string]any{"error": "a configuration change is pending restart; reload after the platform restarts", "restart_pending": true})
}

func handleEditableConfig(cfg *config.Config, policies *SecurityPolicies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings := editableSettings(cfg)
		json.NewEncoder(w).Encode(map[string]any{"revision": editableRevision(settings), "settings": settings, "fields": editableFields, "restart_pending": editableRestartPending(policies)})
	}
}

func handleEditableConfigPreview(cfg *config.Config, regStore *registrypkg.Store, mqStore *mqpkg.Store, h host.Host, policies *SecurityPolicies, policyMu *sync.Mutex, previewKey []byte, gateway *mqpkg.V2Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		input, err := decodeEditableRequest(w, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		policyMu.Lock()
		if editableRestartPending(policies) {
			policyMu.Unlock()
			editableConflict(w)
			return
		}
		current := editableSettings(cfg)
		revision := editableRevision(current)
		if input.ExpectedRevision != revision {
			policyMu.Unlock()
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "configuration changed; reload before previewing", "revision": revision})
			return
		}
		updated := *cfg
		if err := applyEditableChanges(&updated, input.Changes, gateway); err != nil {
			policyMu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		target := editableSettings(&updated)
		changes := editableChanges(current, target)
		expiresAt := time.Now().Add(editablePreviewLifetime)
		token := editableConfirmationToken(previewKey, revision, target, input.Changes, expiresAt)
		policyMu.Unlock()

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		entries, err := regStore.ListEntries()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not inspect registry impact"})
			return
		}
		queues, err := mqStore.ListQueueStats(ctx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not inspect MQ impact"})
			return
		}
		messages, atOrAboveLimit := 0, 0
		for _, queue := range queues {
			messages += queue.Count
			if updated.MQ.MaxMsgsPerURN > 0 && queue.Count >= updated.MQ.MaxMsgsPerURN {
				atOrAboveLimit++
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"expected_revision": revision, "changes": changes, "restart_required": len(changes) > 0,
			"confirmation_token": token, "confirmation_expires_at": expiresAt.Unix(),
			"restart_impact_zh": "保存后 Platform 自动重启，当前 HTTP、libp2p 和 Relay 连接会短暂中断；现有身份、注册和消息数据不会因此删除。",
			"restart_impact_en": "Saving restarts Platform and briefly interrupts current HTTP, libp2p, and Relay connections; existing identity, registration, and message data are not deleted by this restart.",
			"affected":          map[string]int{"registry_entries": len(entries), "mq_queues": len(queues), "mq_messages": messages, "connected_peers": len(h.Network().Peers()), "mq_queues_at_or_above_target_limit": atOrAboveLimit},
		})
	}
}

func handleEditableConfigSave(cfg *config.Config, mqStore *mqpkg.Store, policies *SecurityPolicies, auditLog *AuditLog, policyMu *sync.Mutex, previewKey []byte, gateway *mqpkg.V2Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		input, err := decodeEditableRequest(w, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if input.ConfirmationToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "confirmation_token is required"})
			return
		}
		policyMu.Lock()
		defer policyMu.Unlock()
		if editableRestartPending(policies) {
			editableConflict(w)
			return
		}
		current := editableSettings(cfg)
		revision := editableRevision(current)
		if input.ExpectedRevision != revision {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "configuration changed; reload before saving", "revision": revision})
			return
		}
		updated := *cfg
		if err := applyEditableChanges(&updated, input.Changes, gateway); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		target := editableSettings(&updated)
		if !validEditableConfirmationToken(previewKey, revision, target, input.Changes, input.ConfirmationToken, time.Now()) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "confirmation_token does not match current settings and requested changes"})
			return
		}
		changed := editableChanges(current, target)
		if len(changed) == 0 {
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "changed": false, "restart_pending": false, "settings": current})
			return
		}
		updated.Platform.StoreUserData = policies.StoreUserData.Load()
		updated.Platform.ForwardToStoragePlatforms = policies.ForwardToStoragePlatforms.Load()
		updated.Platform.HistoryRetentionDays = mqStore.GetHistoryRetentionDays()
		updated.AdminRegistryResetPending = policies.RegistryResetPending.Load()
		keys := make([]string, 0, len(changed))
		for _, change := range changed {
			keys = append(keys, change.Key)
		}
		if err := config.SaveAdminEditableSettings(&updated, keys); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "could not persist editable settings"})
			return
		}
		policies.ConfigRestartPending.Store(true)
		if auditLog != nil {
			keys := make([]string, 0, len(changed))
			for _, change := range changed {
				keys = append(keys, change.Key)
			}
			sort.Strings(keys)
			auditLog.Record("warn", "admin", "Changed startup settings: "+fmt.Sprint(keys), "restart scheduled")
		}
		restart := policies.restart
		if restart == nil {
			restart = func() { os.Exit(0) }
		}
		go func() { time.Sleep(500 * time.Millisecond); restart() }()
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "changed": true, "restart_pending": true, "settings": target})
	}
}
