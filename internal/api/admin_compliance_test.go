package api

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

func admitAdminComplianceMessage(t *testing.T) (*adminOperationsFixture, string, string, string) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPub, receiptPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	policy := &v2.Policy{Version: v2.Version, PlatformID: "admin-test-platform", Epoch: 1, NotBefore: now - 60, ExpiresAt: now + 3600,
		Mode: v2.ModeCompliance, Suite: v2.Suite, GatewayKeyID: "gateway-1", GatewayPublicKey: gate.PublicKey().Bytes(),
		ReceiptKeyID: "receipt-1", ReceiptPublicKey: receiptPub, ManagedIssuerPublicKey: issuerPub}
	if err := v2.SignPolicy(policy, rootPriv); err != nil {
		t.Fatal(err)
	}
	gateway := &mqpkg.V2Gateway{Policy: policy, Root: rootPub, GatewayPrivate: gate.Bytes(), ReceiptPrivate: receiptPriv}
	f := newAdminOperationsFixture(t, gateway)
	if err := f.mq.EnableV2Policy(context.Background(), 1, v2.PolicyHash(policy), policy.ExpiresAt, true, issuerPub); err != nil {
		t.Fatal(err)
	}
	sender, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	header := v2.Header{Version: v2.Version, PlatformID: policy.PlatformID, PolicyEpoch: 1, PolicyHash: v2.PolicyHash(policy),
		Mode: v2.ModeCompliance, Suite: v2.Suite, SenderURN: sender.URN(), RecipientURN: recipient.URN(), SessionID: "admin-session",
		Direction: "a_to_b", Sequence: 1, MessageID: "admin-compliance-1", Expiry: now + 1800, ContentType: "application/agent-comm+json", RecipientKeyID: "recipient-1"}
	body := `{"agent_comm":2,"text":"sensitive <script>body</script>"}`
	env, _, err := v2.SealCompliance(policy, header, []byte(body), recipientKey.PublicKey().Bytes(), sender.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v2.Canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := coremq.WithAuthenticatedPublicKey(context.Background(), sender.PublicKey)
	if _, _, err := gateway.AdmitV2(ctx, f.mq, sender.PublicKey, recipient.URN(), raw, header.Expiry); err != nil {
		t.Fatal(err)
	}
	return f, sender.URN(), recipient.URN(), body
}

func TestAdminComplianceHistoryRequiresTokenAndSurvivesQueueDeletion(t *testing.T) {
	f, sender, recipient, body := admitAdminComplianceMessage(t)
	for _, endpoint := range []string{"/api/v1/admin/compliance/messages", "/api/v1/admin/compliance/messages/detail?id=admin-compliance-1", "/api/v1/admin/config/set-compliance-retention?days=0"} {
		method := http.MethodGet
		if strings.Contains(endpoint, "set-compliance") {
			method = http.MethodPost
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, httptest.NewRequest(method, endpoint, nil))
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "sensitive") {
			t.Fatalf("unauthenticated archive access: %d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("admin history must not be cached")
		}
	}
	target := "/api/v1/admin/compliance/messages?sender=" + url.QueryEscape(sender) + "&recipient=" + url.QueryEscape(recipient) + "&limit=1&offset=0"
	w := f.request(t, http.MethodGet, target, "")
	var page struct {
		Entries []mqpkg.ComplianceMessage `json:"entries"`
		Total   int                       `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || page.Total != 1 || len(page.Entries) != 1 || page.Entries[0].Plaintext != "" || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatalf("metadata page: %d %s", w.Code, w.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages?sender=unknown", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatalf("filter: %s", w.Body.String())
	}
	if w := f.request(t, http.MethodGet, strings.Replace(target, "offset=0", "offset=1", 1), ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"entries":[]`) {
		t.Fatal("pagination did not skip the first entry: " + w.Body.String())
	}
	if _, err := f.mq.DeleteMessage(context.Background(), recipient, "admin-compliance-1"); err != nil {
		t.Fatal(err)
	}
	detail := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages/detail?id=admin-compliance-1", "")
	var got mqpkg.ComplianceMessage
	if err := json.Unmarshal(detail.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if detail.Code != 200 || got.Plaintext != body || got.Sender != sender || got.Recipient != recipient {
		t.Fatalf("history after queue deletion: %d %s", detail.Code, detail.Body.String())
	}
	overview := f.request(t, http.MethodGet, "/api/v1/admin/overview", "")
	if overview.Code != 200 || !strings.Contains(overview.Body.String(), `"v2_policy_mode":"compliance"`) || !strings.Contains(overview.Body.String(), `"compliance_messages_count":1`) {
		t.Fatalf("overview: %d %s", overview.Code, overview.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages/detail?id=missing", ""); w.Code != 404 {
		t.Fatal("missing history not 404")
	}
}

func TestAdminComplianceRetentionPersistsAndClearsWithoutRestart(t *testing.T) {
	f, _, _, _ := admitAdminComplianceMessage(t)
	f.policies.restart = func() { t.Error("live retention must not restart") }
	for _, invalid := range []string{"", "-1", "36501", "1.5", "nope", "7&days=8"} {
		w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days="+invalid, "")
		if w.Code != 400 || f.mq.GetComplianceRetentionDays() != 30 {
			t.Fatalf("invalid %q: %d %s", invalid, w.Code, w.Body.String())
		}
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=7", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-retention?days=5", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request(t, http.MethodPut, "/api/v1/admin/config/forwarding", `{"forward_to_storage_platforms":false}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cfg, err := config.Load(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform.ComplianceRetentionDays != 7 || cfg.Platform.HistoryRetentionDays != 5 || cfg.Platform.ForwardToStoragePlatforms {
		t.Fatalf("interleaved settings lost retention: %+v", cfg.Platform)
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=0", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages/detail?id=admin-compliance-1", ""); w.Code != 404 {
		t.Fatal("zero retention still reveals plaintext")
	}
	if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=30", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages", ""); !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatal("raising retention revived deleted plaintext")
	}
}

func TestAdminComplianceRetentionWriteAndApplyFailurePreserveSetting(t *testing.T) {
	t.Run("persist", func(t *testing.T) {
		f := newAdminOperationsFixture(t)
		f.cfg.Platform.DataDir = filepath.Join(t.TempDir(), "missing")
		w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=0", "")
		if w.Code != 500 || f.mq.GetComplianceRetentionDays() != 30 {
			t.Fatal("failed persistence changed live retention")
		}
	})
	t.Run("apply", func(t *testing.T) {
		f := newAdminOperationsFixture(t)
		f.mq.Close()
		w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=0", "")
		if w.Code != 500 || f.mq.GetComplianceRetentionDays() != 30 {
			t.Fatal("failed apply changed live retention")
		}
		cfg, err := config.Load(f.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Platform.ComplianceRetentionDays != 30 {
			t.Fatal("failed apply was not rolled back on disk")
		}
	})
	t.Run("pending", func(t *testing.T) {
		f := newAdminOperationsFixture(t)
		f.policies.ConfigRestartPending.Store(true)
		if w := f.request(t, http.MethodPost, "/api/v1/admin/config/set-compliance-retention?days=0", ""); w.Code != 409 {
			t.Fatal("retention modified pending configuration")
		}
	})
}

func TestAdminComplianceRejectsInvalidPages(t *testing.T) {
	f := newAdminOperationsFixture(t)
	for _, query := range []string{"limit=0", "limit=201", "limit=1.5", "offset=-1", "offset=1000001", "sender=%20urn", "recipient=%0Aurn", "sender=" + strings.Repeat("a", 513)} {
		if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages?"+query, ""); w.Code != 400 {
			t.Fatalf("invalid page %q: %d", query, w.Code)
		}
	}
	if w := f.request(t, http.MethodGet, "/api/v1/admin/compliance/messages/detail", ""); w.Code != 400 {
		t.Fatal("empty detail id accepted")
	}
}
