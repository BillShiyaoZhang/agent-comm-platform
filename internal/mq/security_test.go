package mq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	"github.com/libp2p/go-libp2p"
	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	goproto "google.golang.org/protobuf/proto"
)

func securityStore(t *testing.T, quota int) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "mq.db"), 7, quota)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func securityKey(t *testing.T) *crypto.IdentityKeyPair {
	t.Helper()
	k, err := crypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func securityCtx(k *crypto.IdentityKeyPair) context.Context {
	return coremq.WithAuthenticatedPublicKey(context.Background(), k.PublicKey)
}

func TestMQFullMailboxRejectsNewMessagesWithoutEviction(t *testing.T) {
	s := securityStore(t, 1)
	a, b := securityKey(t), securityKey(t)
	h := HTTPHandler(s, nil, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := coremq.NewHTTPClient(srv.URL, &crypto.IdentityKeys{Ed25519: a})
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "first"})
	if _, err := client.Store(context.Background(), b.URN(), env, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Store(context.Background(), b.URN(), env, 0); err != nil {
		t.Fatalf("duplicate should succeed at capacity: %v", err)
	}
	second := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "second"})
	data, _ := goproto.Marshal(second)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedPost(t, a, "/api/v1/mq/store", storeReq{RecipientURN: b.URN(), PayloadProto: data}))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("full queue did not produce retryable response: %d %s", w.Code, w.Body)
	}
	pending, _, err := s.RetrieveEntry(securityCtx(b), b.URN())
	if err != nil || len(pending) != 1 || pending[0].MessageId != "first" {
		t.Fatalf("full queue discarded accepted message: %v %v", pending, err)
	}
	if _, err := s.Ack(securityCtx(b), b.URN(), []string{"first"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Store(context.Background(), b.URN(), second, 0); err != nil {
		t.Fatalf("ACK did not release capacity: %v", err)
	}
	if _, err := s.db.Exec("UPDATE messages SET expiry=? WHERE id='second'", time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	third := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "third"})
	if _, err := client.Store(context.Background(), b.URN(), third, 0); err != nil {
		t.Fatalf("expired entry consumed capacity: %v", err)
	}
}

func TestMQServiceOwnershipAndDuplicateIsolation(t *testing.T) {
	s := securityStore(t, 2)
	a, b, attacker := securityKey(t), securityKey(t), securityKey(t)
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "stable-id", Ciphertext: []byte("cipher")})
	for _, ctx := range []context.Context{context.Background(), securityCtx(attacker)} {
		if _, err := s.StoreEnvelope(ctx, b.URN(), env, 0); err == nil {
			t.Fatal("unauthorized sender stored message")
		}
		if _, _, err := s.RetrieveEntry(ctx, b.URN()); err == nil {
			t.Fatal("unauthorized recipient retrieved mailbox")
		}
		if _, err := s.Ack(ctx, b.URN(), []string{env.MessageId}); err == nil {
			t.Fatal("unauthorized recipient acknowledged message")
		}
		if err := s.RegisterSubscriber(ctx, b.URN(), make(chan *pb.EncryptedEnvelope, 1)); err == nil {
			t.Fatal("unauthorized subscriber registered")
		}
	}
	ch := make(chan *pb.EncryptedEnvelope, 30)
	if err := s.RegisterSubscriber(securityCtx(b), b.URN(), ch); err != nil {
		t.Fatal(err)
	}
	defer s.UnregisterSubscriber(b.URN(), ch)
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), env, 0); err != nil {
		t.Fatal(err)
	}
	other := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "other-id", Ciphertext: []byte("other")})
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), other, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.StoreEnvelope(securityCtx(a), b.URN(), env, 0); errors <- err }()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(ch) != 2 {
		t.Fatalf("duplicate generated subscriber notifications: %d", len(ch))
	}
	pending, _, err := s.RetrieveEntry(securityCtx(b), b.URN())
	if err != nil || len(pending) != 2 {
		t.Fatalf("duplicate evicted queue entry: %v, %d", err, len(pending))
	}
	conflict := goproto.Clone(env).(*pb.EncryptedEnvelope)
	conflict.Ciphertext = []byte("replaced")
	if err := crypto.SignEnvelope(conflict, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), conflict, 0); err == nil {
		t.Fatal("conflicting message ID accepted")
	}
	conflict = signTestEnvelope(t, attacker, attacker.URN(), &pb.EncryptedEnvelope{MessageId: env.MessageId})
	if _, err := s.StoreEnvelope(securityCtx(attacker), attacker.URN(), conflict, 0); err == nil {
		t.Fatal("cross-recipient message ID accepted")
	}
	if n, err := s.Ack(securityCtx(attacker), attacker.URN(), []string{env.MessageId, other.MessageId}); err != nil || n != 0 {
		t.Fatalf("cross-mailbox ACK: %d, %v", n, err)
	}
	if n, err := s.Ack(securityCtx(b), b.URN(), []string{env.MessageId}); err != nil || n != 1 {
		t.Fatalf("owner ACK: %d, %v", n, err)
	}
	if _, err := s.StoreEnvelope(securityCtx(a), b.URN(), env, 0); err != nil {
		t.Fatal(err)
	}
	if len(ch) != 2 {
		t.Fatal("retry of acknowledged message notified subscriber")
	}
	if n, err := s.Ack(securityCtx(b), b.URN(), []string{env.MessageId}); err != nil || n != 0 {
		t.Fatalf("ACK retry not idempotent: %d, %v", n, err)
	}
}

func signedRead(t *testing.T, key *crypto.IdentityKeyPair, urn, endpoint string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", endpoint, nil)
	ts := time.Now().Unix()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	sig := ed25519.Sign(key.PrivateKey, append([]byte("mq-retrieve|"+urn+"|"), buf...))
	r.Header.Set("X-URN", urn)
	r.Header.Set("X-Timestamp", fmt.Sprint(ts))
	r.Header.Set("X-Pubkey", hex.EncodeToString(key.PublicKey))
	r.Header.Set("X-Signature", hex.EncodeToString(sig))
	return r
}

func signedPost(t *testing.T, key *crypto.IdentityKeyPair, endpoint string, body any) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", endpoint, bytes.NewReader(data))
	r.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(ed25519.Sign(key.PrivateKey, data))+":"+hex.EncodeToString(key.PublicKey))
	return r
}

func TestMQHTTPRejectsCrossIdentityAndAnonymousACK(t *testing.T) {
	s := securityStore(t, 10)
	a, b := securityKey(t), securityKey(t)
	h := HTTPHandler(s, nil, nil)
	for _, endpoint := range []string{"retrieve", "subscribe"} {
		r := signedRead(t, a, b.URN(), "/api/v1/mq/"+endpoint)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s accepted valid attacker signature: %d", endpoint, w.Code)
		}
	}
	for _, r := range []*http.Request{
		httptest.NewRequest("POST", "/api/v1/mq/ack", bytes.NewBufferString(`{"message_ids":["x"]}`)),
		signedPost(t, a, "/api/v1/mq/ack", ackReq{RecipientURN: b.URN(), Timestamp: time.Now().Unix(), MessageIDs: []string{"x"}}),
		signedPost(t, b, "/api/v1/mq/ack", ackReq{RecipientURN: b.URN(), Timestamp: time.Now().Add(-10 * time.Minute).Unix(), MessageIDs: []string{"x"}}),
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid ACK accepted: %d %s", w.Code, w.Body)
		}
	}
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "http-client-id", Ciphertext: []byte("cipher")})
	srv := httptest.NewServer(h)
	defer srv.Close()
	aClient := coremq.NewHTTPClient(srv.URL, &crypto.IdentityKeys{Ed25519: a})
	bClient := coremq.NewHTTPClient(srv.URL, &crypto.IdentityKeys{Ed25519: b})
	ctx := context.Background()
	if _, err := aClient.Store(ctx, b.URN(), env, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := aClient.Retrieve(ctx, b.URN()); err == nil {
		t.Fatal("attacker HTTP client retrieved recipient mailbox")
	}
	if n, err := aClient.Ack(ctx, []string{env.MessageId}); err != nil || n != 0 {
		t.Fatalf("attacker ACK: %d %v", n, err)
	}
	if envs, err := bClient.Retrieve(ctx, b.URN()); err != nil || len(envs) != 1 {
		t.Fatalf("owner retrieve: %d %v", len(envs), err)
	}
	if n, err := bClient.Ack(ctx, []string{env.MessageId}); err != nil || n != 1 {
		t.Fatalf("signed SDK ACK contract: %d %v", n, err)
	}
	for _, change := range []func(*pb.EncryptedEnvelope){
		func(e *pb.EncryptedEnvelope) { e.Signature = nil },
		func(e *pb.EncryptedEnvelope) { e.MessageId = "tampered" },
		func(e *pb.EncryptedEnvelope) { e.RecipientUrn = a.URN() },
	} {
		bad := goproto.Clone(env).(*pb.EncryptedEnvelope)
		change(bad)
		if _, err := aClient.Store(ctx, b.URN(), bad, 0); err == nil {
			t.Fatal("invalid signed envelope accepted")
		}
	}
}

func TestMQLibp2pAuthenticatedPeerCannotReadOrAckOthers(t *testing.T) {
	s := securityStore(t, 10)
	a, b := securityKey(t), securityKey(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	private, _ := lpcrypto.UnmarshalEd25519PrivateKey(a.PrivateKey)
	attacker, err := libp2p.New(libp2p.Identity(private), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	server, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := coremq.NewServer(server, s); err != nil {
		t.Fatal(err)
	}
	relay := peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}
	if err := attacker.Connect(ctx, relay); err != nil {
		t.Fatal(err)
	}
	client := coremq.NewClient(attacker)
	env := signTestEnvelope(t, a, b.URN(), &pb.EncryptedEnvelope{MessageId: "p2p-owned"})
	if _, err := client.Store(ctx, relay, b.URN(), env, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Retrieve(ctx, relay, b.URN()); err == nil {
		t.Fatal("authenticated unrelated peer retrieved mailbox")
	}
	if _, err := client.AckForRecipient(ctx, relay, b.URN(), []string{env.MessageId}); err == nil {
		t.Fatal("authenticated unrelated peer ACKed mailbox")
	}
	if n, err := client.Ack(ctx, relay, []string{env.MessageId}); err != nil || n != 0 {
		t.Fatalf("own-URN ACK changed another mailbox: %d %v", n, err)
	}
	forged := signTestEnvelope(t, b, a.URN(), &pb.EncryptedEnvelope{MessageId: "forged-p2p-sender"})
	if _, err := client.Store(ctx, relay, a.URN(), forged, 0); err == nil {
		t.Fatal("peer relayed envelope under another sender identity")
	}
	if pending, _, err := s.RetrieveEntry(securityCtx(b), b.URN()); err != nil || len(pending) != 1 {
		t.Fatalf("recipient message lost: %d %v", len(pending), err)
	}
	s.SetStoragePolicy(func() bool { return false }, nil)
	if _, err := client.Store(ctx, relay, b.URN(), env, 0); err == nil {
		t.Fatal("libp2p bypassed disabled storage policy")
	}
	s.SetStoragePolicy(func() bool { return true }, func(string) bool { return false })
	if _, err := client.Store(ctx, relay, b.URN(), env, 0); err == nil {
		t.Fatal("libp2p bypassed blocked-recipient policy")
	}
}
