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
	"strings"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	golibp2p "github.com/libp2p/go-libp2p"
)

type adminOperationsFixture struct {
	handler  http.Handler
	cfg      *config.Config
	cfgPath  string
	mq       *mqpkg.Store
	policies *SecurityPolicies
	audit    *AuditLog
}

func newAdminOperationsFixture(t *testing.T) *adminOperationsFixture {
	t.Helper()
	dir := t.TempDir()
	reg, err := registrypkg.NewStore(filepath.Join(dir, "registry.db"), 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	mq, err := mqpkg.NewStore(filepath.Join(dir, "mq.db"), 7, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mq.Close() })
	h, err := golibp2p.New(golibp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	audit, err := NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	cfg := config.DefaultConfig()
	cfg.Platform.DataDir = dir
	cfg.API.AdminToken = "test-secret-token"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	policies := &SecurityPolicies{restart: func() {}}
	policies.StoreUserData.Store(cfg.Platform.StoreUserData)
	policies.ForwardToStoragePlatforms.Store(cfg.Platform.ForwardToStoragePlatforms)
	mq.SetHistoryRetentionDays(cfg.Platform.HistoryRetentionDays)
	return &adminOperationsFixture{
		handler: AdminHandler(cfg, reg, mq, h, audit, policies, cfgPath),
		cfg:     cfg, cfgPath: cfgPath, mq: mq, policies: policies, audit: audit,
	}
}

func (f *adminOperationsFixture) request(t *testing.T, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("X-Admin-Token", f.cfg.API.AdminToken)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func TestAdminForwardingPersistsAcrossOtherPolicyUpdates(t *testing.T) {
	f := newAdminOperationsFixture(t)
	endpoint := "/api/v1/admin/config/forwarding"
	for _, body := range []string{"{}", `{"forward_to_storage_platforms":"false"}`, `{"unknown":false}`, `{"forward_to_storage_platforms":false} {}`} {
		w := f.request(t, http.MethodPut, endpoint, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid body %q: status %d: %s", body, w.Code, w.Body.String())
		}
	}
	if !f.policies.ForwardToStoragePlatforms.Load() {
		t.Fatal("invalid request changed forwarding policy")
	}
	unauthorized := httptest.NewRecorder()
	f.handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPut, endpoint, strings.NewReader(`{"forward_to_storage_platforms":false}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status %d", unauthorized.Code)
	}
	for i, wantChanged := range []bool{true, false} {
		w := f.request(t, http.MethodPut, endpoint, `{"forward_to_storage_platforms":false}`)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT forwarding %d: %d %s", i, w.Code, w.Body.String())
		}
		var got struct {
			Value   bool `json:"forward_to_storage_platforms"`
			Changed bool `json:"changed"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Value || got.Changed != wantChanged {
			t.Fatalf("PUT forwarding %d returned %+v", i, got)
		}
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-retention?days=5", ""); w.Code != http.StatusOK {
		t.Fatalf("retention status %d: %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/storage", `{"store_user_data":true}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":false`) {
		t.Fatalf("storage no-op status %d: %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/storage", `{"store_user_data":false}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":true`) {
		t.Fatalf("storage status %d: %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/overview", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"restart_pending":true`) {
		t.Fatalf("overview did not expose pending restart: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/storage", `{"store_user_data":false}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"restart_pending":true`) {
		t.Fatalf("storage during restart status %d: %s", w.Code, w.Body.String())
	}
	loaded, err := config.Load(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Platform.StoreUserData || loaded.Platform.ForwardToStoragePlatforms || loaded.Platform.HistoryRetentionDays != 5 || !loaded.AdminRegistryResetPending {
		t.Fatalf("interleaved policy writes lost settings: %+v", loaded)
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/toggle-forwarding", ""); w.Code != http.StatusOK {
		t.Fatalf("legacy forwarding toggle status %d: %s", w.Code, w.Body.String())
	}
	loaded, err = config.Load(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Platform.ForwardToStoragePlatforms || loaded.Platform.StoreUserData || loaded.Platform.HistoryRetentionDays != 5 || !loaded.AdminRegistryResetPending {
		t.Fatalf("legacy toggle lost other policy settings: %+v", loaded)
	}
}

func TestAdminForwardingWriteFailurePreservesLiveState(t *testing.T) {
	f := newAdminOperationsFixture(t)
	f.cfg.Platform.DataDir = filepath.Join(t.TempDir(), "missing-directory")
	w := f.request(t, http.MethodPut, "/api/v1/admin/config/forwarding", `{"forward_to_storage_platforms":false}`)
	if w.Code != http.StatusInternalServerError || !f.policies.ForwardToStoragePlatforms.Load() {
		t.Fatalf("persistence failure changed live state: %d %s", w.Code, w.Body.String())
	}
}

func TestAdminMQPageSummaryAndSelectiveDelete(t *testing.T) {
	f := newAdminOperationsFixture(t)
	key, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	urn := key.URN()
	ctx := coremq.WithAuthenticatedPublicKey(context.Background(), key.PublicKey)
	for _, id := range []string{"msg-a", "msg-b", "msg-c"} {
		env := signAdminTestEnvelope(t, key, &pb.EncryptedEnvelope{MessageId: id, Ciphertext: []byte(id)})
		if _, err := f.mq.StoreEnvelope(ctx, urn, env, time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/v1/admin/mq/messages/page?urn=" + url.QueryEscape(urn)
	for _, suffix := range []string{"&status=bad", "&limit=0", "&limit=201", "&offset=-1", "&offset=1000001"} {
		w := f.request(t, http.MethodGet, base+suffix, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid page %s: status %d", suffix, w.Code)
		}
	}
	w := f.request(t, http.MethodGet, base+"&limit=1&offset=1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("page status %d: %s", w.Code, w.Body.String())
	}
	var page struct {
		Entries []mqpkg.MessageDetail `json:"entries"`
		Total   int                   `json:"total"`
		Limit   int                   `json:"limit"`
		Offset  int                   `json:"offset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Limit != 1 || page.Offset != 1 || len(page.Entries) != 1 || page.Entries[0].ID != "msg-b" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Entries[0].Payload != "" || strings.Contains(w.Body.String(), `"payload"`) {
		t.Fatalf("paged list exposed ciphertext: %s", w.Body.String())
	}
	detailURL := fmt.Sprintf("/api/v1/admin/mq/messages/detail?urn=%s&id=msg-b", url.QueryEscape(urn))
	w = f.request(t, http.MethodGet, detailURL, "")
	var detail mqpkg.MessageDetail
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.ID != "msg-b" || detail.Payload != "6d73672d62" {
		t.Fatalf("single message detail: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/mq/messages/detail?urn=another-urn&id=msg-b", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-mailbox detail returned %d", w.Code)
	}
	w = f.request(t, http.MethodGet, "/api/v1/admin/mq/summary", "")
	var summary mqpkg.QueueSummary
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &summary) != nil || summary.Pending.Messages != 3 || summary.Pending.Queues != 1 || summary.History.Messages != 0 || summary.Expired.Messages != 0 {
		t.Fatalf("unexpected summary: %d %s", w.Code, w.Body.String())
	}
	deleteURL := fmt.Sprintf("/api/v1/admin/mq/messages?urn=%s&id=msg-b", url.QueryEscape(urn))
	wrongRecipient := fmt.Sprintf("/api/v1/admin/mq/messages?urn=%s&id=msg-b", url.QueryEscape("another-urn"))
	if w := f.request(t, http.MethodDelete, wrongRecipient, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"deleted":0`) {
		t.Fatalf("cross-mailbox delete returned %d %s", w.Code, w.Body.String())
	}
	for i, deleted := range []int{1, 0} {
		w := f.request(t, http.MethodDelete, deleteURL, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), fmt.Sprintf(`"deleted":%d`, deleted)) {
			t.Fatalf("delete %d returned %d %s", i, w.Code, w.Body.String())
		}
	}
	w = f.request(t, http.MethodGet, base, "")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 2 {
		t.Fatalf("delete not reflected in page: %d %s", w.Code, w.Body.String())
	}
	entries, total, err := f.audit.List(context.Background(), 10, 0, "warn", "mq", "Deleted MQ message")
	if err != nil || total != 1 || len(entries) != 1 || !strings.Contains(entries[0].Message, "msg-b") {
		t.Fatalf("selective deletion audit entries=%v total=%d err=%v", entries, total, err)
	}
}

func TestEditableConfigPreviewConfirmAndRestartPersistence(t *testing.T) {
	f := newAdminOperationsFixture(t)
	get := f.request(t, http.MethodGet, "/api/v1/admin/config/editable", "")
	if get.Code != http.StatusOK || strings.Contains(get.Body.String(), "test-secret-token") {
		t.Fatalf("editable GET: %d %s", get.Code, get.Body.String())
	}
	var current struct {
		Revision string         `json:"revision"`
		Settings map[string]any `json:"settings"`
		Fields   []struct {
			Key string `json:"key"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if current.Revision == "" || len(current.Fields) != 6 || current.Settings["registry.ttl_hours"] != float64(24) {
		t.Fatalf("editable metadata: %+v", current)
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+current.Revision+`","changes":{"registry.ttl_hours":48}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT without preview token: %d %s", w.Code, w.Body.String())
	}
	bad := []string{
		`{"registry.ttl_hours":0}`, `{"registry.ttl_hours":8761}`, `{"mq.default_ttl_days":0}`,
		`{"mq.max_msgs_per_urn":100001}`, `{"relay.max_reservations":0}`,
		`{"relay.max_circuit_duration":"bad"}`, `{"relay.max_circuit_duration":"25h"}`,
		`{"relay.enabled":null}`, `{"api.admin_token":"stolen"}`,
	}
	for _, changes := range bad {
		w := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", `{"expected_revision":"`+current.Revision+`","changes":`+changes+`}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid changes %s: %d %s", changes, w.Code, w.Body.String())
		}
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", `{"expected_revision":"stale","changes":{"registry.ttl_hours":48}}`); w.Code != http.StatusConflict {
		t.Fatalf("stale preview: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-retention?days=11", ""); w.Code != http.StatusOK {
		t.Fatalf("retention setup: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/forwarding", `{"forward_to_storage_platforms":false}`); w.Code != http.StatusOK {
		t.Fatalf("forwarding setup: %d %s", w.Code, w.Body.String())
	}
	previewBody := `{"expected_revision":"` + current.Revision + `","changes":{"registry.ttl_hours":48,"mq.default_ttl_days":7,"mq.max_msgs_per_urn":250,"relay.enabled":false}}`
	preview := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", previewBody)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	var impact struct {
		ConfirmationToken string `json:"confirmation_token"`
		Changes           []struct {
			Key     string `json:"key"`
			Current any    `json:"current"`
			Target  any    `json:"target"`
		} `json:"changes"`
		Affected        map[string]int `json:"affected"`
		RestartRequired bool           `json:"restart_required"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &impact); err != nil {
		t.Fatal(err)
	}
	if impact.ConfirmationToken == "" || len(impact.Changes) != 3 || !impact.RestartRequired || impact.Affected["registry_entries"] < 0 {
		t.Fatalf("preview impact: %+v", impact)
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+current.Revision+`","changes":{"registry.ttl_hours":49},"confirmation_token":"`+impact.ConfirmationToken+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("token accepted for different target: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+current.Revision+`","changes":{"registry.ttl_hours":48,"mq.max_msgs_per_urn":250,"relay.enabled":false},"confirmation_token":"`+impact.ConfirmationToken+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("token accepted for different request key set: %d %s", w.Code, w.Body.String())
	}
	saveBody := `{"expected_revision":"` + current.Revision + `","changes":{"registry.ttl_hours":48,"mq.default_ttl_days":7,"mq.max_msgs_per_urn":250,"relay.enabled":false},"confirmation_token":"` + impact.ConfirmationToken + `"}`
	saved := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", saveBody)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"restart_pending":true`) {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/overview", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"restart_pending":true`) {
		t.Fatalf("overview pending: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", saveBody); w.Code != http.StatusConflict {
		t.Fatalf("replay during pending restart: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", previewBody); w.Code != http.StatusConflict {
		t.Fatalf("preview during pending restart: %d %s", w.Code, w.Body.String())
	}
	// A legacy policy edit during the restart window must not erase staged values.
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/toggle-forwarding", ""); w.Code != http.StatusOK {
		t.Fatalf("legacy policy edit: %d %s", w.Code, w.Body.String())
	}
	loaded, err := config.Load(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Registry.TTLHours != 48 || loaded.MQ.MaxMsgsPerURN != 250 || loaded.Relay.Enabled || loaded.Platform.HistoryRetentionDays != 11 || !loaded.Platform.ForwardToStoragePlatforms {
		t.Fatalf("persisted settings or live policies lost: %+v", loaded)
	}
	if loaded.AdminRegistryResetPending {
		t.Fatal("ordinary editable settings must not purge registry on restart")
	}
	override, err := os.ReadFile(filepath.Join(f.cfg.Platform.DataDir, "admin-policies.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(override), "mq_default_ttl_days:") {
		t.Fatal("unchanged field unexpectedly pinned as an admin override")
	}
}

func TestEditableConfigNoopAndWriteFailure(t *testing.T) {
	f := newAdminOperationsFixture(t)
	get := f.request(t, http.MethodGet, "/api/v1/admin/config/editable", "")
	var state struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	preview := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":24}}`)
	var impact struct {
		ConfirmationToken string `json:"confirmation_token"`
		RestartRequired   bool   `json:"restart_required"`
	}
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &impact) != nil || impact.RestartRequired {
		t.Fatalf("no-op preview: %d %s", preview.Code, preview.Body.String())
	}
	w := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":24},"confirmation_token":"`+impact.ConfirmationToken+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":false`) || f.policies.ConfigRestartPending.Load() {
		t.Fatalf("no-op save: %d %s", w.Code, w.Body.String())
	}
	f.cfg.Platform.DataDir = filepath.Join(t.TempDir(), "missing-directory")
	preview = f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":48}}`)
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &impact) != nil {
		t.Fatalf("write-failure preview: %d %s", preview.Code, preview.Body.String())
	}
	w = f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":48},"confirmation_token":"`+impact.ConfirmationToken+`"}`)
	if w.Code != http.StatusInternalServerError || f.policies.ConfigRestartPending.Load() {
		t.Fatalf("write failure changed live state: %d %s", w.Code, w.Body.String())
	}
}

func TestEditablePreviewTokenExpiresAndBindsTarget(t *testing.T) {
	key := []byte("server-only-random-preview-key")
	settings := editableSettings(config.DefaultConfig())
	revision := editableRevision(settings)
	now := time.Now()
	changes := map[string]json.RawMessage{"registry.ttl_hours": json.RawMessage("24")}
	valid := editableConfirmationToken(key, revision, settings, changes, now.Add(editablePreviewLifetime))
	if !validEditableConfirmationToken(key, revision, settings, changes, valid, now) {
		t.Fatal("current preview token rejected")
	}
	if validEditableConfirmationToken(key, revision, settings, changes, valid, now.Add(editablePreviewLifetime+time.Second)) {
		t.Fatal("expired preview token accepted")
	}
	target := editableSettings(config.DefaultConfig())
	target["registry.ttl_hours"] = 48
	if validEditableConfirmationToken(key, revision, target, changes, valid, now) {
		t.Fatal("preview token accepted for a different target")
	}
	if validEditableConfirmationToken(key, "stale", settings, changes, valid, now) {
		t.Fatal("preview token accepted for a different revision")
	}
	if validEditableConfirmationToken([]byte("different-process-key"), revision, settings, changes, valid, now) {
		t.Fatal("preview token accepted after process restart")
	}
	moreKeys := map[string]json.RawMessage{"registry.ttl_hours": json.RawMessage("24"), "relay.enabled": json.RawMessage("true")}
	if validEditableConfirmationToken(key, revision, settings, moreKeys, valid, now) {
		t.Fatal("preview token accepted for a different requested key set")
	}
}

func TestEditableAPIAllowsLegacyUnlimitedMQBaseWhenEditingAnotherField(t *testing.T) {
	f := newAdminOperationsFixture(t)
	f.cfg.MQ.MaxMsgsPerURN = 0
	if err := config.Save(f.cfgPath, f.cfg); err != nil {
		t.Fatal(err)
	}
	get := f.request(t, http.MethodGet, "/api/v1/admin/config/editable", "")
	var state struct {
		Revision string `json:"revision"`
	}
	if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &state) != nil {
		t.Fatalf("GET: %d %s", get.Code, get.Body.String())
	}
	preview := f.request(t, http.MethodPost, "/api/v1/admin/config/editable/preview", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":48}}`)
	var impact struct {
		ConfirmationToken string `json:"confirmation_token"`
	}
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &impact) != nil {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	saved := f.request(t, http.MethodPut, "/api/v1/admin/config/editable", `{"expected_revision":"`+state.Revision+`","changes":{"registry.ttl_hours":48},"confirmation_token":"`+impact.ConfirmationToken+`"}`)
	if saved.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", saved.Code, saved.Body.String())
	}
	loaded, err := config.Load(f.cfgPath)
	if err != nil || loaded.MQ.MaxMsgsPerURN != 0 || loaded.Registry.TTLHours != 48 {
		t.Fatalf("legacy base changed: %+v %v", loaded, err)
	}
}
