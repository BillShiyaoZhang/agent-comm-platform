package mq

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

func sealComplianceTestMessage(t *testing.T, gateway *V2Gateway, sender, recipient *crypto.IdentityKeyPair, id string, body []byte) ([]byte, v2.Header) {
	t.Helper()
	header := v2.Header{Version: v2.Version, PlatformID: gateway.Policy.PlatformID, PolicyEpoch: gateway.Policy.Epoch,
		PolicyHash: v2.PolicyHash(gateway.Policy), Mode: gateway.Policy.Mode, Suite: v2.Suite,
		SenderURN: sender.URN(), RecipientURN: recipient.URN(), SessionID: "session-" + id, Direction: "a_to_b", Sequence: 1,
		MessageID: id, Expiry: time.Now().Add(10 * time.Minute).Unix(), ContentType: v2.ContentTypeAgentJSON, RecipientKeyID: "recipient-1"}
	var env *v2.Envelope
	var err error
	if gateway.Policy.Mode == v2.ModeCompliance {
		recipientKey, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		env, _, err = v2.SealCompliance(gateway.Policy, header, body, recipientKey.PublicKey().Bytes(), sender.PrivateKey)
	} else {
		env, err = v2.SealPrivate(gateway.Policy, header, body, bytes.Repeat([]byte{7}, 32), sender.PrivateKey)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v2.Canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw, header
}

func admitComplianceTestMessage(t *testing.T, s *Store, gateway *V2Gateway, sender, recipient *crypto.IdentityKeyPair, id string) ([]byte, v2.Header, []byte) {
	t.Helper()
	raw, header := sealComplianceTestMessage(t, gateway, sender, recipient, id, []byte(`{"agent_comm":2,"text":"exact retained body"}`))
	gotID, receipt, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry)
	if err != nil || gotID != id {
		t.Fatalf("admit %s: %s %v", id, gotID, err)
	}
	return raw, header, receipt
}

func complianceTableCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestComplianceArchiveContainsOnlyVerifiedComplianceBodies(t *testing.T) {
	s := securityStore(t, 10)
	sender, recipient := securityKey(t), securityKey(t)
	legacy := signTestEnvelope(t, sender, recipient.URN(), &pb.EncryptedEnvelope{MessageId: "legacy-no-archive"})
	if _, err := s.StoreEnvelope(securityCtx(sender), recipient.URN(), legacy, 0); err != nil {
		t.Fatal(err)
	}
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	raw, header, receipt := admitComplianceTestMessage(t, s, gateway, sender, recipient, "verified")
	detail, err := s.GetComplianceMessage(context.Background(), header.MessageID)
	if err != nil || detail == nil {
		t.Fatalf("detail: %+v %v", detail, err)
	}
	if detail.Plaintext != `{"agent_comm":2,"text":"exact retained body"}` || detail.Sender != sender.URN() || detail.Recipient != recipient.URN() || detail.PolicyHash != header.PolicyHash || detail.PolicyEpoch != header.PolicyEpoch || detail.ContentType != header.ContentType || detail.Expiry != header.Expiry || detail.StoredAt == 0 {
		t.Fatalf("wrong retained body or metadata: %+v", detail)
	}
	rows, total, err := s.ListComplianceMessagesPage(context.Background(), "", "", 10, 0)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].Plaintext != "" {
		t.Fatalf("list leaked or omitted body: %+v %d %v", rows, total, err)
	}
	metadata, _ := json.Marshal(rows)
	if bytes.Contains(metadata, []byte("plaintext")) || bytes.Contains(metadata, []byte("exact retained body")) {
		t.Fatalf("metadata contains plaintext: %s", metadata)
	}
	_, retried, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry)
	if err != nil || !bytes.Equal(retried, receipt) {
		t.Fatalf("exact retry: %v", err)
	}
	again, _ := s.GetComplianceMessage(context.Background(), header.MessageID)
	if again.StoredAt != detail.StoredAt || complianceTableCount(t, s, "compliance_messages") != 1 {
		t.Fatal("retry changed archive clock or count")
	}
	// A real signed handshake stays metadata-only.
	frame, _, err := v2.NewInit(gateway.Policy, sender.URN(), recipient.URN(), "recipient-1", "handshake-no-archive", header.Expiry, sender.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	frameRaw, _ := v2.Canonical(frame)
	if err := s.StoreV2Frame(securityCtx(sender), sender.URN(), recipient.URN(), v2.FrameHash(frame), frameRaw, header.Expiry, gateway.Policy, sender.PublicKey); err != nil {
		t.Fatal(err)
	}
	// An opaque declared JSON body and a valid signature over broken AEAD fail.
	opaque, opaqueHeader := sealComplianceTestMessage(t, gateway, sender, recipient, "opaque", []byte("opaque binary"))
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), opaque, opaqueHeader.Expiry); err == nil {
		t.Fatal("opaque body admitted")
	}
	bad, _ := v2.ParseEnvelope(raw)
	bad.Header.MessageID = "broken-ciphertext"
	bad.Ciphertext[0] ^= 1
	if err := v2.SignEnvelope(bad, sender.PrivateKey); err != nil {
		t.Fatal(err)
	}
	badRaw, _ := v2.Canonical(bad)
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), badRaw, header.Expiry); err == nil {
		t.Fatal("broken AEAD admitted")
	}
	bad.Signature[0] ^= 1
	invalidRaw, _ := v2.Canonical(bad)
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), invalidRaw, header.Expiry); err == nil {
		t.Fatal("invalid signature admitted")
	}
	if complianceTableCount(t, s, "compliance_messages") != 1 {
		t.Fatal("failed admission, v1, or handshake wrote plaintext")
	}

	privateStore := securityStore(t, 10)
	privateGateway, _ := v2Fixture(t, privateStore, v2.ModePrivate)
	admitComplianceTestMessage(t, privateStore, privateGateway, sender, recipient, "private-no-archive")
	if complianceTableCount(t, privateStore, "compliance_messages") != 0 || complianceTableCount(t, privateStore, "v2_compliance_admissions") != 0 {
		t.Fatal("private mode retained compliance data")
	}
}

func TestComplianceArchiveAtomicFailures(t *testing.T) {
	s := securityStore(t, 1)
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	sender, recipient := securityKey(t), securityKey(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_archive BEFORE INSERT ON compliance_messages BEGIN SELECT RAISE(ABORT,'test archive failure'); END`); err != nil {
		t.Fatal(err)
	}
	raw, header := sealComplianceTestMessage(t, gateway, sender, recipient, "atomic", []byte(`{"agent_comm":2,"text":"must rollback"}`))
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry); err == nil {
		t.Fatal("archive write failure ignored")
	}
	for _, table := range []string{"v2_messages", "compliance_messages", "v2_compliance_admissions"} {
		if complianceTableCount(t, s, table) != 0 {
			t.Fatalf("%s published on failed archive write", table)
		}
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_archive"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry); err != nil {
		t.Fatal(err)
	}
	second, secondHeader := sealComplianceTestMessage(t, gateway, sender, recipient, "full", []byte(`{"agent_comm":2,"text":"queue full"}`))
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), second, secondHeader.Expiry); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("quota failure: %v", err)
	}
	for _, table := range []string{"v2_messages", "compliance_messages", "v2_compliance_admissions"} {
		if complianceTableCount(t, s, table) != 1 {
			t.Fatalf("%s changed on quota failure", table)
		}
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_retention BEFORE DELETE ON compliance_messages BEGIN SELECT RAISE(ABORT,'test cleanup failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetComplianceRetentionDays(0); err == nil {
		t.Fatal("retention clear failure ignored")
	}
	if s.GetComplianceRetentionDays() != 30 || complianceTableCount(t, s, "compliance_messages") != 1 {
		t.Fatal("failed duration update changed archive or runtime setting")
	}
}

func TestComplianceArchiveSurvivesDeliveryLifecycle(t *testing.T) {
	for _, operation := range []string{"ack", "expiry", "delete", "purge"} {
		t.Run(operation, func(t *testing.T) {
			s := securityStore(t, 10)
			gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
			sender, recipient := securityKey(t), securityKey(t)
			raw, header, receipt := admitComplianceTestMessage(t, s, gateway, sender, recipient, "keep-history")
			before, _ := s.GetComplianceMessage(context.Background(), header.MessageID)
			switch operation {
			case "ack":
				if n, err := s.AckV2(securityCtx(recipient), recipient.URN(), []string{header.MessageID}); err != nil || n != 1 {
					t.Fatalf("ack: %d %v", n, err)
				}
				s.SetHistoryRetentionDays(0)
				if err := s.cleanup(context.Background(), time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				if _, err := s.db.Exec("UPDATE v2_messages SET expiry=? WHERE id=?", time.Now().Unix()-1, header.MessageID); err != nil {
					t.Fatal(err)
				}
				if err := s.cleanup(context.Background(), time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if n, err := s.DeleteMessage(context.Background(), recipient.URN(), header.MessageID); err != nil || n != 1 {
					t.Fatalf("delete: %d %v", n, err)
				}
			case "purge":
				if n, err := s.PurgeQueue(context.Background(), recipient.URN()); err != nil || n != 1 {
					t.Fatalf("purge: %d %v", n, err)
				}
			}
			if complianceTableCount(t, s, "v2_messages") != 0 {
				t.Fatal("delivery row still present")
			}
			after, err := s.GetComplianceMessage(context.Background(), header.MessageID)
			if err != nil || after == nil || after.Plaintext != before.Plaintext || after.StoredAt != before.StoredAt {
				t.Fatalf("delivery lifecycle changed archive: %+v %v", after, err)
			}
			_, retried, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry)
			if err != nil || !bytes.Equal(retried, receipt) || complianceTableCount(t, s, "v2_messages") != 0 {
				t.Fatalf("deleted delivery retry republished: %v", err)
			}
			conflict, conflictHeader := sealComplianceTestMessage(t, gateway, sender, recipient, header.MessageID, []byte(`{"agent_comm":2,"text":"different"}`))
			if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), conflict, conflictHeader.Expiry); !errors.Is(err, ErrV2Conflict) {
				t.Fatalf("changed envelope escaped retained retry hash: %v", err)
			}
			if _, _, err := s.ExistingV2Receipt(context.Background(), "another recipient", header.MessageID, raw); !errors.Is(err, ErrV2Conflict) {
				t.Fatalf("changed recipient escaped retry hash: %v", err)
			}
		})
	}
}

func TestComplianceArchiveRetentionZeroAndRetry(t *testing.T) {
	s := securityStore(t, 10)
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	sender, recipient := securityKey(t), securityKey(t)
	raw, header, _ := admitComplianceTestMessage(t, s, gateway, sender, recipient, "expired-history")
	old := time.Now().Unix() - 31*24*3600
	if _, err := s.db.Exec("UPDATE compliance_messages SET stored_at=? WHERE id=?", old, header.MessageID); err != nil {
		t.Fatal(err)
	}
	if msg, err := s.GetComplianceMessage(context.Background(), header.MessageID); err != nil || msg != nil {
		t.Fatalf("detail exposed expired retention before cleanup: %+v %v", msg, err)
	}
	if rows, total, err := s.ListComplianceMessagesPage(context.Background(), "", "", 10, 0); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("list exposed expired retention: %d %v", total, err)
	}
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry); err != nil {
		t.Fatal(err)
	}
	var storedAt int64
	if err := s.db.QueryRow("SELECT stored_at FROM compliance_messages WHERE id=?", header.MessageID).Scan(&storedAt); err != nil || storedAt != old {
		t.Fatalf("retry reset retention clock: %d %v", storedAt, err)
	}
	if err := s.SetComplianceRetentionDays(30); err != nil {
		t.Fatal(err)
	}
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("duration update left expired bodies")
	}
	if err := s.SetComplianceRetentionDays(36500); err != nil {
		t.Fatal(err)
	}
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry); err != nil {
		t.Fatal(err)
	}
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("longer retention and retry revived deleted plaintext")
	}
	admitComplianceTestMessage(t, s, gateway, sender, recipient, "existing-before-zero")
	if err := s.SetComplianceRetentionDays(0); err != nil {
		t.Fatal(err)
	}
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("zero did not clear existing bodies immediately")
	}
	zeroRaw, zeroHeader, zeroReceipt := admitComplianceTestMessage(t, s, gateway, sender, recipient, "admitted-with-zero")
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("zero retained new body")
	}
	if _, err := s.PurgeQueue(context.Background(), recipient.URN()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetComplianceRetentionDays(30); err != nil {
		t.Fatal(err)
	}
	_, retried, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), zeroRaw, zeroHeader.Expiry)
	if err != nil || !bytes.Equal(retried, zeroReceipt) || complianceTableCount(t, s, "compliance_messages") != 0 || complianceTableCount(t, s, "v2_messages") != 0 {
		t.Fatalf("retry after zero revived body or delivery: %v", err)
	}
	for _, days := range []int{-1, 36501} {
		if err := s.SetComplianceRetentionDays(days); err == nil || s.GetComplianceRetentionDays() != 30 {
			t.Fatalf("invalid retention %d changed setting", days)
		}
	}
}

func TestComplianceArchivePaginationAndFilters(t *testing.T) {
	s := securityStore(t, 0)
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	sender, otherSender := securityKey(t), securityKey(t)
	recipient, otherRecipient := securityKey(t), securityKey(t)
	for i := 0; i < 6; i++ {
		who, to := sender, recipient
		if i == 4 {
			who = otherSender
		}
		if i == 5 {
			to = otherRecipient
		}
		admitComplianceTestMessage(t, s, gateway, who, to, fmt.Sprintf("page-%d", i))
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec("UPDATE compliance_messages SET stored_at=?", now); err != nil {
		t.Fatal(err)
	}
	rows, total, err := s.ListComplianceMessagesPage(context.Background(), sender.URN(), recipient.URN(), 2, 1)
	if err != nil || total != 4 || len(rows) != 2 || rows[0].ID != "page-2" || rows[1].ID != "page-1" {
		t.Fatalf("filter/page ordering: %+v %d %v", rows, total, err)
	}
	rows, total, err = s.ListComplianceMessagesPage(context.Background(), "", otherRecipient.URN(), 10, 0)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ID != "page-5" {
		t.Fatalf("recipient exact filter: %+v %d %v", rows, total, err)
	}
	rows, total, err = s.ListComplianceMessagesPage(context.Background(), sender.URN()+"suffix", "", 10, 0)
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("sender filter was not exact: %+v %d %v", rows, total, err)
	}
	if _, err := s.db.Exec("UPDATE compliance_messages SET stored_at=? WHERE id=?", now+1, "page-0"); err != nil {
		t.Fatal(err)
	}
	rows, total, err = s.ListComplianceMessagesPage(context.Background(), "", "", 1, 0)
	if err != nil || total != 6 || len(rows) != 1 || rows[0].ID != "page-0" {
		t.Fatalf("stored_at ordering: %+v %d %v", rows, total, err)
	}
	for _, page := range [][2]int{{0, 0}, {201, 0}, {1, -1}} {
		if _, _, err := s.ListComplianceMessagesPage(context.Background(), "", "", page[0], page[1]); err == nil {
			t.Fatal("invalid page accepted")
		}
	}
	if msg, err := s.GetComplianceMessage(context.Background(), "missing"); err != nil || msg != nil {
		t.Fatalf("missing detail: %+v %v", msg, err)
	}
	if _, err := s.db.Exec("UPDATE compliance_messages SET plaintext=? WHERE id=?", string(bytes.Repeat([]byte("x"), maxEnvelopeBytes+1)), "page-0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetComplianceMessage(context.Background(), "page-0"); err == nil {
		t.Fatal("oversized corrupt plaintext returned")
	}
	if err := s.SetComplianceRetentionDays(0); err != nil {
		t.Fatal(err)
	}
	if rows, total, err := s.ListComplianceMessagesPage(context.Background(), "", "", 10, 0); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("zero list: %+v %d %v", rows, total, err)
	}
	if msg, err := s.GetComplianceMessage(context.Background(), "page-0"); err != nil || msg != nil {
		t.Fatalf("zero detail: %+v %v", msg, err)
	}
}

func TestComplianceArchiveSurvivesReopenAndPolicyReapply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mq.db")
	s, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	sender, recipient := securityKey(t), securityKey(t)
	raw, header, receipt := admitComplianceTestMessage(t, s, gateway, sender, recipient, "reopen")
	before, _ := s.GetComplianceMessage(context.Background(), header.MessageID)
	if _, err := s.PurgeQueue(context.Background(), recipient.URN()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.GetComplianceRetentionDays() != 30 {
		t.Fatal("store default retention changed")
	}
	// Runtime policy belongs to admin-policies.yaml and is reapplied at boot.
	if err := reopened.SetComplianceRetentionDays(1); err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableV2Policy(context.Background(), gateway.Policy.Epoch, v2.PolicyHash(gateway.Policy), gateway.Policy.ExpiresAt, true, gateway.Policy.ManagedIssuerPublicKey); err != nil {
		t.Fatal(err)
	}
	after, err := reopened.GetComplianceMessage(context.Background(), header.MessageID)
	if err != nil || after == nil || after.Plaintext != before.Plaintext || after.StoredAt != before.StoredAt {
		t.Fatalf("reopen lost archive: %+v %v", after, err)
	}
	_, retried, err := gateway.AdmitV2(securityCtx(sender), reopened, sender.PublicKey, recipient.URN(), raw, header.Expiry)
	if err != nil || !bytes.Equal(retried, receipt) || complianceTableCount(t, reopened, "v2_messages") != 0 || complianceTableCount(t, reopened, "compliance_messages") != 1 {
		t.Fatalf("reopen retry changed retained rows: %v", err)
	}
	// Signed expiry bounds the hash/receipt ledger independently of body age.
	if err := reopened.cleanup(context.Background(), header.Expiry); err != nil {
		t.Fatal(err)
	}
	if complianceTableCount(t, reopened, "v2_compliance_admissions") != 0 || complianceTableCount(t, reopened, "compliance_messages") != 1 {
		t.Fatal("signed expiry did not bound retry metadata independently")
	}
}

func TestComplianceArchiveRetentionIncreaseAndStartupRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mq.db")
	s, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := v2Fixture(t, s, v2.ModeCompliance)
	sender, recipient := securityKey(t), securityKey(t)
	raw, header, _ := admitComplianceTestMessage(t, s, gateway, sender, recipient, "elapsed-before-increase")
	old := time.Now().Unix() - 30*24*3600 - 1
	if _, err := s.db.Exec("UPDATE compliance_messages SET stored_at=? WHERE id=?", old, header.MessageID); err != nil {
		t.Fatal(err)
	}
	if msg, err := s.GetComplianceMessage(context.Background(), header.MessageID); err != nil || msg != nil {
		t.Fatalf("expired body visible before increase: %+v %v", msg, err)
	}
	if err := s.SetComplianceRetentionDays(60); err != nil {
		t.Fatal(err)
	}
	if msg, err := s.GetComplianceMessage(context.Background(), header.MessageID); err != nil || msg != nil {
		t.Fatalf("live increase revived expired body before cleanup: %+v %v", msg, err)
	}
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("increase retained already expired body")
	}
	if _, _, err := gateway.AdmitV2(securityCtx(sender), s, sender.PublicKey, recipient.URN(), raw, header.Expiry); err != nil {
		t.Fatal(err)
	}
	if complianceTableCount(t, s, "compliance_messages") != 0 {
		t.Fatal("retry after increase revived deleted body")
	}

	// A 32-day row is valid under the now-configured 60-day policy. The next
	// process must restore that policy before applying its 30-day default.
	_, retainedHeader, _ := admitComplianceTestMessage(t, s, gateway, sender, recipient, "valid-under-sixty")
	storedAt := time.Now().Unix() - 32*24*3600
	if _, err := s.db.Exec("UPDATE compliance_messages SET stored_at=? WHERE id=?", storedAt, retainedHeader.MessageID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// Reading the runtime setting during boot is harmless; only archive use
	// or a successful policy application establishes a live retention clock.
	if reopened.GetComplianceRetentionDays() != 30 {
		t.Fatal("unexpected boot default")
	}
	if err := reopened.SetComplianceRetentionDays(60); err != nil {
		t.Fatal(err)
	}
	msg, err := reopened.GetComplianceMessage(context.Background(), retainedHeader.MessageID)
	if err != nil || msg == nil || msg.StoredAt != storedAt {
		t.Fatalf("boot default erased valid configured history: %+v %v", msg, err)
	}
}
