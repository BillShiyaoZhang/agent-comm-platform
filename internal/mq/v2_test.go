package mq

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	"github.com/BillShiyaoZhang/agent-comm/v2"
	goproto "google.golang.org/protobuf/proto"
)

func v2Fixture(t *testing.T, s *Store, mode string) (*V2Gateway, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPub, receiptPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	p := &v2.Policy{Version: v2.Version, PlatformID: "test-platform", Epoch: 1, NotBefore: now - 60, ExpiresAt: now + 3600,
		Mode: mode, Suite: v2.Suite, GatewayKeyID: "gateway-1", GatewayPublicKey: gatePriv.PublicKey().Bytes(),
		ReceiptKeyID: "receipt-1", ReceiptPublicKey: receiptPub, ManagedIssuerPublicKey: issuerPub}
	if err := v2.SignPolicy(p, rootPriv); err != nil {
		t.Fatal(err)
	}
	raw, err := v2.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableV2Policy(context.Background(), p.Epoch, v2.PolicyHash(p), p.ExpiresAt, mode == v2.ModeCompliance, issuerPub); err != nil {
		t.Fatal(err)
	}
	return &V2Gateway{Policy: p, RawPolicy: raw, Root: rootPub, GatewayPrivate: gatePriv.Bytes(), ReceiptPrivate: receiptPriv}, issuerPriv
}

func TestV2ComplianceGatewayAdmissionAndExactRetry(t *testing.T) {
	s := securityStore(t, 10)
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	a, b := securityKey(t), securityKey(t)
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header := v2.Header{Version: v2.Version, PlatformID: gateway.Policy.PlatformID, PolicyEpoch: gateway.Policy.Epoch,
		PolicyHash: v2.PolicyHash(gateway.Policy), Mode: v2.ModeCompliance, Suite: v2.Suite,
		SenderURN: a.URN(), RecipientURN: b.URN(), SessionID: "session-1", Direction: "a_to_b", Sequence: 1,
		MessageID: "v2-message-1", Expiry: time.Now().Add(time.Hour).Unix(), ContentType: "application/agent-comm+json", RecipientKeyID: "recipient-1"}
	env, _, err := v2.SealCompliance(gateway.Policy, header, []byte(`{"agent_comm":2,"text":"same exact body"}`), recipientKey.PublicKey().Bytes(), a.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v2.Canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	h := V2HTTPHandler(s, gateway)
	storeBody := map[string]any{"recipient_urn": b.URN(), "expiry_unix": header.Expiry, "envelope": raw}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v2/mq/store", storeBody))
	if w.Code != http.StatusOK {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	var stored struct {
		MessageID string `json:"message_id"`
		Receipt   []byte `json:"receipt"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.MessageID != header.MessageID {
		t.Fatal("wrong message ID")
	}
	receipt, err := v2.ParseReceipt(stored.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	cek, plaintext, err := v2.RecipientOpenCompliance(gateway.Policy, env, recipientKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != `{"agent_comm":2,"text":"same exact body"}` {
		t.Fatal("recipient received different plaintext")
	}
	if err := v2.VerifyReceipt(gateway.Policy, receipt, raw, cek, time.Now()); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v2/mq/store", storeBody))
	if w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}
	var retried struct {
		Receipt []byte `json:"receipt"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &retried); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retried.Receipt, stored.Receipt) {
		t.Fatal("retry changed admission receipt")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedRead(t, b, b.URN(), "/api/v2/mq/retrieve"))
	if w.Code != http.StatusOK {
		t.Fatalf("retrieve: %d %s", w.Code, w.Body.String())
	}
	var delivered struct {
		Messages []struct {
			Envelope []byte `json:"envelope"`
			Receipt  []byte `json:"receipt"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	if len(delivered.Messages) != 1 || !bytes.Equal(delivered.Messages[0].Envelope, raw) || !bytes.Equal(delivered.Messages[0].Receipt, stored.Receipt) {
		t.Fatal("MQ did not return original envelope and receipt")
	}
	bad := *env
	bad.Header.MessageID = "tampered-body"
	bad.Ciphertext = append([]byte{}, env.Ciphertext...)
	bad.Ciphertext[0] ^= 1
	if err := v2.SignEnvelope(&bad, a.PrivateKey); err != nil {
		t.Fatal(err)
	}
	badRaw, _ := v2.Canonical(&bad)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v2/mq/store", map[string]any{"recipient_urn": b.URN(), "expiry_unix": header.Expiry, "envelope": badRaw}))
	if w.Code == http.StatusOK {
		t.Fatal("gateway accepted tampered ciphertext")
	}
	opaqueHeader := header
	opaqueHeader.MessageID = "opaque-body"
	opaque, _, err := v2.SealCompliance(gateway.Policy, opaqueHeader, []byte("opaque binary"), recipientKey.PublicKey().Bytes(), a.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	opaqueRaw, _ := v2.Canonical(opaque)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v2/mq/store", map[string]any{"recipient_urn": b.URN(), "expiry_unix": header.Expiry, "envelope": opaqueRaw}))
	if w.Code == http.StatusOK {
		t.Fatal("gateway admitted opaque body under declared JSON content type")
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM v2_messages").Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed admission published a message: %d %v", count, err)
	}
	// A lost store response may be retried after an epoch cutover. The exact
	// stored bytes retrieve the original receipt without another admission.
	if err := s.EnableV2Policy(context.Background(), 2, v2.EnvelopeHash([]byte("next-policy")), time.Now().Add(time.Hour).Unix(), true,
		gateway.Policy.ManagedIssuerPublicKey); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v2/mq/store", storeBody))
	if w.Code != http.StatusOK {
		t.Fatalf("cross-epoch exact retry: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &retried); err != nil || !bytes.Equal(retried.Receipt, stored.Receipt) {
		t.Fatalf("cross-epoch retry changed original receipt: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM v2_messages").Scan(&count); err != nil || count != 1 {
		t.Fatalf("cross-epoch retry inserted a message: %d %v", count, err)
	}
	stats, err := s.ListQueueStats(context.Background())
	if err != nil || len(stats) != 1 || stats[0].Recipient != b.URN() || stats[0].Count != 1 {
		t.Fatalf("admin queue omitted v2 message: %v %v", stats, err)
	}
	details, total, err := s.ListMessagesPage(context.Background(), b.URN(), "pending", 10, 0)
	if err != nil || total != 1 || len(details) != 1 || details[0].Sender != a.URN() {
		t.Fatalf("admin list omitted v2 message: %v %d %v", details, total, err)
	}
	detail, err := s.GetMessageDetail(context.Background(), b.URN(), header.MessageID)
	if err != nil || detail == nil || detail.Payload == "" {
		t.Fatalf("admin detail omitted v2 ciphertext: %v %v", detail, err)
	}
	deleted, err := s.DeleteMessage(context.Background(), b.URN(), header.MessageID)
	if err != nil || deleted != 1 {
		t.Fatalf("admin delete omitted v2 message: %d %v", deleted, err)
	}
}

func TestV2ComplianceRejectsAndQuarantinesV1(t *testing.T) {
	s := securityStore(t, 10)
	a, b := securityKey(t), securityKey(t)
	old := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "old-v1"})
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), old, 0); err != nil {
		t.Fatal(err)
	}
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	newEnvelope := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "new-v1"})
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), newEnvelope, 0); err == nil {
		t.Fatal("v1 Agent-to-Agent store bypassed compliance policy")
	}
	protoBytes, err := goproto.Marshal(newEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	HTTPHandler(s, nil, nil, gateway).ServeHTTP(w, signedPost(t, a, "/api/v1/mq/store", storeReq{RecipientURN: b.URN(), PayloadProto: protoBytes}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("v1 HTTP route did not fail closed: %d %s", w.Code, w.Body.String())
	}
	var notice V1UpgradeNotice
	if err := json.Unmarshal(w.Body.Bytes(), &notice); err != nil {
		t.Fatalf("v1 rejection must be machine-readable JSON: %v", err)
	}
	if notice.Error != "upgrade_required" || notice.ConsentRequired == nil || !*notice.ConsentRequired || notice.PolicyURL != "/api/v2/policy" || notice.PolicyHash != v2.PolicyHash(gateway.Policy) || notice.PolicyEpoch != gateway.Policy.Epoch || notice.PolicyMode != v2.ModeCompliance || notice.PlatformID != gateway.Policy.PlatformID {
		t.Fatalf("incomplete v1 upgrade notice: %+v", notice)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("v1 rejection cache control = %q", got)
	}
	w = httptest.NewRecorder()
	V2HTTPHandler(s, gateway).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v2/policy", nil))
	if w.Code != http.StatusOK || w.Header().Get("ETag") != `"`+notice.PolicyHash+`"` {
		t.Fatalf("hint did not locate the pinned policy: %d %s", w.Code, w.Body.String())
	}
	var policyResponse struct {
		Policy []byte `json:"policy"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &policyResponse); err != nil || !bytes.Equal(policyResponse.Policy, gateway.RawPolicy) {
		t.Fatalf("policy endpoint did not return original signed bytes: %v", err)
	}
	rows, _, err := s.RetrieveEntry(securityCtx(b), b.URN())
	if err != nil || len(rows) != 0 {
		t.Fatalf("old private v1 message was delivered under compliance: %d %v", len(rows), err)
	}
}

func TestV1UpgradeHintWithoutActiveSignedPolicy(t *testing.T) {
	s := securityStore(t, 10)
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	a, b := securityKey(t), securityKey(t)
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "v1-policy-missing"})
	protoBytes, err := goproto.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	// A later pinned epoch makes the configured policy stale. V1 stays
	// blocked, but its error must not advertise that stale policy as current.
	if err := s.EnableV2Policy(context.Background(), 2, v2.EnvelopeHash([]byte("later")), time.Now().Add(time.Hour).Unix(), true, gateway.Policy.ManagedIssuerPublicKey); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	HTTPHandler(s, nil, nil, gateway).ServeHTTP(w, signedPost(t, a, "/api/v1/mq/store", storeReq{RecipientURN: b.URN(), PayloadProto: protoBytes}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("v1 reopened after policy switch: %d %s", w.Code, w.Body.String())
	}
	var notice V1UpgradeNotice
	if err := json.Unmarshal(w.Body.Bytes(), &notice); err != nil || notice.Error != "upgrade_required" || notice.ConsentRequired != nil || notice.PolicyURL != "" || notice.PolicyHash != "" {
		t.Fatalf("stale policy was advertised: %+v %v", notice, err)
	}
	w = httptest.NewRecorder()
	V2HTTPHandler(s, gateway).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v2/policy", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale policy endpoint returned %d", w.Code)
	}
}

func TestV2ManagedEnrollmentDoesNotRetroactivelyAuthorizeV1(t *testing.T) {
	s := securityStore(t, 10)
	console, b := securityKey(t), securityKey(t)
	old := signTestEnvelope(t, console, b.URN(), &pb.EncryptedEnvelope{MessageId: "old-console-v1"})
	if _, err := s.StoreEnvelope(securityCtx(console), b.URN(), old, 0); err != nil {
		t.Fatal(err)
	}
	gateway, issuerPrivate := v2Fixture(t, s, v2.ModeCompliance)
	newBefore := signTestEnvelope(t, console, b.URN(), &pb.EncryptedEnvelope{MessageId: "before-enrollment"})
	if _, err := s.StoreEnvelope(securityCtx(console), b.URN(), newBefore, 0); err == nil {
		t.Fatal("uncertified managed identity bypassed policy")
	}
	cert := &v2.ManagedIdentityCertificate{Version: v2.Version, Role: v2.ManagedConsoleRole,
		PlatformID: gateway.Policy.PlatformID, URN: console.URN(), IdentityPublicKey: console.PublicKey,
		NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), Serial: "console-cert-1"}
	if err := v2.SignManagedCertificate(cert, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	rawCert, _ := v2.Canonical(cert)
	h := V2HTTPHandler(s, gateway)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, console, "/api/v2/managed/identity", map[string]any{"certificate": rawCert}))
	if w.Code != http.StatusOK {
		t.Fatalf("managed enrollment: %d %s", w.Code, w.Body.String())
	}
	newEnvelope := signTestEnvelope(t, console, b.URN(), &pb.EncryptedEnvelope{MessageId: "new-console-v1"})
	if _, err := s.StoreEnvelope(securityCtx(console), b.URN(), newEnvelope, 0); err != nil {
		t.Fatalf("certified managed console rejected: %v", err)
	}
	rows, _, err := s.RetrieveEntry(securityCtx(b), b.URN())
	if err != nil || len(rows) != 1 || rows[0].MessageId != "new-console-v1" {
		t.Fatalf("historical v1 was retroactively admitted: %v %v", rows, err)
	}
	if err := s.RevokeManaged(context.Background(), cert.Serial); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StoreEnvelope(securityCtx(console), b.URN(), newEnvelope, 0); err == nil {
		t.Fatal("revoked certificate allowed v1 retry")
	}
	rows, _, err = s.RetrieveEntry(securityCtx(b), b.URN())
	if err != nil || len(rows) != 0 {
		t.Fatal("revoked managed route remained readable")
	}
}

func TestV2PinnedPolicySurvivesRestartWithoutGatewayConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mq.db")
	s, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = v2Fixture(t, s, v2.ModeCompliance)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	a, b := securityKey(t), securityKey(t)
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "restart-v1"})
	if _, err := restarted.StoreEnvelope(securityCtx(a), b.URN(), env, 0); err == nil {
		t.Fatal("v1 reopened after removing v2 gateway config")
	}
	if rows, _, err := restarted.RetrieveEntry(securityCtx(b), b.URN()); err != nil || len(rows) != 0 {
		t.Fatalf("restart exposed v1 rows: %v %v", rows, err)
	}
}

func TestV2AdminPurgeAlsoClearsHandshakeFrames(t *testing.T) {
	s := securityStore(t, 10)
	_, _ = v2Fixture(t, s, v2.ModeCompliance)
	recipient := "urn:agent-comm:agent:admin-purge-fixture"
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO v2_messages(id,recipient,envelope,receipt,policy_hash,expiry,stored_at)
		VALUES(?,?,?,?,?,?,?)`, "v2-purge", recipient, []byte("envelope"), []byte("receipt"), "fixture", now+3600, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO v2_handshake_frames(id,recipient,frame,expiry,stored_at)
		VALUES(?,?,?,?,?)`, "frame-purge", recipient, []byte("frame"), now+3600, now); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.PurgeQueue(context.Background(), recipient)
	if err != nil || deleted != 2 {
		t.Fatalf("purge left v2 rows: %d %v", deleted, err)
	}
	for _, table := range []string{"v2_messages", "v2_handshake_frames"} {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE recipient=?", recipient).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s not purged: %d %v", table, count, err)
		}
	}
}
