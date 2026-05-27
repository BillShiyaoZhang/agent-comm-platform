package mq

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	goproto "google.golang.org/protobuf/proto"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
)

// Helper to write length-prefixed protocol data
func writePrefixedMessage(w io.Writer, msg goproto.Message) error {
	data, err := goproto.Marshal(msg)
	if err != nil {
		return err
	}
	sizeBuf := [4]byte{
		byte(len(data) >> 24),
		byte(len(data) >> 16),
		byte(len(data) >> 8),
		byte(len(data)),
	}
	if _, err := w.Write(sizeBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Helper to read length-prefixed protocol data
func readPrefixedMessage(r io.Reader, msg goproto.Message) error {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, sizeBuf); err != nil {
		return err
	}
	size := uint32(sizeBuf[0])<<24 | uint32(sizeBuf[1])<<16 | uint32(sizeBuf[2])<<8 | uint32(sizeBuf[3])
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return goproto.Unmarshal(data, msg)
}

func TestMQStore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mq-store-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "mq.db")
	// Set MaxMsgsPerURN to 3 for eviction test
	store, err := NewStore(dbPath, 1, 3)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	urn := "urn:hermes:agent:recipient1"

	env1 := &pb.EncryptedEnvelope{MessageId: "msg-1", Ciphertext: []byte("payload-1")}
	env2 := &pb.EncryptedEnvelope{MessageId: "msg-2", Ciphertext: []byte("payload-2")}
	env3 := &pb.EncryptedEnvelope{MessageId: "msg-3", Ciphertext: []byte("payload-3")}
	env4 := &pb.EncryptedEnvelope{MessageId: "msg-4", Ciphertext: []byte("payload-4")}

	// 1. Store Envelope
	id, err := store.StoreEnvelope(ctx, urn, env1, 0)
	if err != nil {
		t.Fatalf("StoreEnvelope error: %v", err)
	}
	if id != "msg-1" {
		t.Errorf("expected msg-1, got %s", id)
	}

	// 2. Retrieve Envelopes
	envs, ids, err := store.RetrieveEntry(ctx, urn)
	if err != nil {
		t.Fatalf("Retrieve error: %v", err)
	}
	if len(envs) != 1 || envs[0].MessageId != "msg-1" {
		t.Errorf("expected 1 envelope msg-1, got %+v", envs)
	}
	if len(ids) != 1 || ids[0] != "msg-1" {
		t.Errorf("expected 1 id msg-1, got %v", ids)
	}

	// 3. Quota Eviction (evicts msg-1 when msg-4 is added because max=3)
	store.StoreEnvelope(ctx, urn, env2, 0)
	time.Sleep(10 * time.Millisecond) // Make sure stored_at is sequential
	store.StoreEnvelope(ctx, urn, env3, 0)
	time.Sleep(10 * time.Millisecond)
	store.StoreEnvelope(ctx, urn, env4, 0)

	envs, _, err = store.RetrieveEntry(ctx, urn)
	if err != nil {
		t.Fatalf("Retrieve after quota error: %v", err)
	}
	if len(envs) != 3 {
		t.Fatalf("expected 3 envelopes, got %d", len(envs))
	}
	// msg-1 should be evicted, msg-2, msg-3, msg-4 should remain
	for _, env := range envs {
		if env.MessageId == "msg-1" {
			t.Error("msg-1 should have been evicted")
		}
	}

	// 4. Acknowledgment (Ack)
	deleted, err := store.Ack(ctx, []string{"msg-2", "msg-3"})
	if err != nil {
		t.Fatalf("Ack error: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted messages, got %d", deleted)
	}

	envs, _, err = store.RetrieveEntry(ctx, urn)
	if err != nil {
		t.Fatalf("Retrieve after ack error: %v", err)
	}
	if len(envs) != 1 || envs[0].MessageId != "msg-4" {
		t.Errorf("expected only msg-4 to remain, got %+v", envs)
	}

	// 5. Expiration
	expiredEnv := &pb.EncryptedEnvelope{MessageId: "expired-msg", Ciphertext: []byte("expired")}
	pastExpiry := time.Now().Unix() - 10
	store.StoreEnvelope(ctx, urn, expiredEnv, pastExpiry)

	envs, _, err = store.RetrieveEntry(ctx, urn)
	if err != nil {
		t.Fatalf("Retrieve with expired error: %v", err)
	}
	// Only msg-4 should be returned since expired-msg is expired
	if len(envs) != 1 || envs[0].MessageId != "msg-4" {
		t.Errorf("expected only msg-4, got %v", envs)
	}
}

func TestMQStreamServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tempDir, err := os.MkdirTemp("", "mq-libp2p-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "mq.db")
	store, err := NewStore(dbPath, 1, 10)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	// 1. Setup Server Host
	hSrv, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create server host: %v", err)
	}
	defer hSrv.Close()

	_, err = coremq.NewServer(hSrv, store)
	if err != nil {
		t.Fatalf("failed to start mq server: %v", err)
	}

	// 2. Setup Client Host
	hCli, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create client host: %v", err)
	}
	defer hCli.Close()
	hCli.Peerstore().AddAddrs(hSrv.ID(), hSrv.Addrs(), peerstore.PermanentAddrTTL)

	// 3. Test Store Envelope via Stream
	streamStore, err := hCli.NewStream(ctx, hSrv.ID(), protocol.ID(coremq.ProtoID))
	if err != nil {
		t.Fatalf("open store stream: %v", err)
	}
	defer streamStore.Close()

	urn := "urn:hermes:agent:stream-recipient"
	env := &pb.EncryptedEnvelope{
		MessageId:  "msg-stream-id",
		Ciphertext: []byte("ciphertext bytes over stream"),
	}

	reqStore := &pb.MQRequest{
		Op: &pb.MQRequest_Store{
			Store: &pb.StoreRequest{
				RecipientUrn: urn,
				Payload:      env,
			},
		},
	}

	if err := writePrefixedMessage(streamStore, reqStore); err != nil {
		t.Fatalf("write store request: %v", err)
	}

	var respStore pb.MQResponse
	if err := readPrefixedMessage(streamStore, &respStore); err != nil {
		t.Fatalf("read store response: %v", err)
	}

	storeRes := respStore.GetStore()
	if storeRes == nil {
		t.Fatalf("expected StoreResponse, got %v", respStore.GetOp())
	}
	if !storeRes.Ok {
		t.Errorf("StoreResponse failed: %s", storeRes.MessageId)
	}

	// 4. Test Retrieve via Stream
	streamRetrieve, err := hCli.NewStream(ctx, hSrv.ID(), protocol.ID(coremq.ProtoID))
	if err != nil {
		t.Fatalf("open retrieve stream: %v", err)
	}
	defer streamRetrieve.Close()

	reqRetrieve := &pb.MQRequest{
		Op: &pb.MQRequest_Retrieve{
			Retrieve: &pb.RetrieveRequest{
				RecipientUrn: urn,
			},
		},
	}

	if err := writePrefixedMessage(streamRetrieve, reqRetrieve); err != nil {
		t.Fatalf("write retrieve request: %v", err)
	}

	var respRetrieve pb.MQResponse
	if err := readPrefixedMessage(streamRetrieve, &respRetrieve); err != nil {
		t.Fatalf("read retrieve response: %v", err)
	}

	retrieveRes := respRetrieve.GetRetrieve()
	if retrieveRes == nil {
		t.Fatalf("expected RetrieveResponse, got %v", respRetrieve.GetOp())
	}
	if len(retrieveRes.Payloads) != 1 || retrieveRes.Payloads[0].MessageId != "msg-stream-id" {
		t.Errorf("expected payloads [msg-stream-id], got %v", retrieveRes.Payloads)
	}

	// 5. Test Ack via Stream
	streamAck, err := hCli.NewStream(ctx, hSrv.ID(), protocol.ID(coremq.ProtoID))
	if err != nil {
		t.Fatalf("open ack stream: %v", err)
	}
	defer streamAck.Close()

	reqAck := &pb.MQRequest{
		Op: &pb.MQRequest_Ack{
			Ack: &pb.AckRequest{
				MessageIds: []string{"msg-stream-id"},
			},
		},
	}

	if err := writePrefixedMessage(streamAck, reqAck); err != nil {
		t.Fatalf("write ack request: %v", err)
	}

	var respAck pb.MQResponse
	if err := readPrefixedMessage(streamAck, &respAck); err != nil {
		t.Fatalf("read ack response: %v", err)
	}

	ackRes := respAck.GetAck()
	if ackRes == nil {
		t.Fatalf("expected AckResponse, got %v", respAck.GetOp())
	}
	if !ackRes.Ok || ackRes.DeletedCount != 1 {
		t.Errorf("expected Ok=true, DeletedCount=1, got ok=%t, count=%d", ackRes.Ok, ackRes.DeletedCount)
	}
}

func TestMQHTTPHandlers(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mq-http-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "mq.db")
	store, err := NewStore(dbPath, 1, 10)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	handler := HTTPHandler(store, func() bool { return true }, func(recipientURN string) bool { return true })
	srv := httptest.NewServer(handler)
	defer srv.Close()

	senderPubKey, senderPrivKey, _ := ed25519.GenerateKey(nil)
	kp := &crypto.IdentityKeyPair{PublicKey: senderPubKey, PrivateKey: senderPrivKey}
	senderURN := kp.URN()

	urn := "urn:hermes:agent:http-recipient"
	env := &pb.EncryptedEnvelope{
		MessageId:  "msg-http-id",
		Ciphertext: []byte("ciphertext bytes over http"),
		SenderUrn:  senderURN,
	}
	envBytes, _ := goproto.Marshal(env)

	// 1. POST /api/v1/mq/store
	storeReqObj := storeReq{
		RecipientURN: urn,
		PayloadProto: envBytes,
	}
	bodyBytes, _ := json.Marshal(storeReqObj)
	reqStore, _ := http.NewRequest("POST", srv.URL+"/api/v1/mq/store", strings.NewReader(string(bodyBytes)))
	reqStore.Header.Set("Content-Type", "application/json")
	payloadSig := ed25519.Sign(senderPrivKey, bodyBytes)
	reqStore.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(payloadSig)+":"+hex.EncodeToString(senderPubKey))

	client := &http.Client{}
	respStore, err := client.Do(reqStore)
	if err != nil {
		t.Fatalf("POST store error: %v", err)
	}
	defer respStore.Body.Close()

	if respStore.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respStore.Body)
		t.Errorf("expected store status 200, got %d, body: %s", respStore.StatusCode, string(b))
	}

	var storeRespObj map[string]interface{}
	json.NewDecoder(respStore.Body).Decode(&storeRespObj)
	if storeRespObj["ok"] != true || storeRespObj["message_id"] != "msg-http-id" {
		t.Errorf("unexpected store response: %v", storeRespObj)
	}

	// 2. GET /api/v1/mq/retrieve (With signature auth validation)
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	timestamp := time.Now().Unix()

	// Generate valid signature over "mq-retrieve|<urn>|<timestamp 8 bytes big-endian>"
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(timestamp))
	msg := append([]byte("mq-retrieve|"+urn+"|"), tsBuf...)
	sig := ed25519.Sign(privKey, msg)

	reqRetrieve, _ := http.NewRequest("GET", srv.URL+"/api/v1/mq/retrieve", nil)
	reqRetrieve.Header.Set("X-URN", urn)
	reqRetrieve.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	reqRetrieve.Header.Set("X-Pubkey", hex.EncodeToString(pubKey))
	reqRetrieve.Header.Set("X-Signature", hex.EncodeToString(sig))

	respRetrieve, err := client.Do(reqRetrieve)
	if err != nil {
		t.Fatalf("GET retrieve with auth error: %v", err)
	}
	defer respRetrieve.Body.Close()

	if respRetrieve.StatusCode != http.StatusOK {
		// Read body to debug
		b, _ := io.ReadAll(respRetrieve.Body)
		t.Fatalf("expected retrieve status 200, got %d, body: %s", respRetrieve.StatusCode, string(b))
	}

	var retrieveRespObj map[string]interface{}
	json.NewDecoder(respRetrieve.Body).Decode(&retrieveRespObj)
	countVal, ok := retrieveRespObj["count"].(float64)
	if !ok || countVal != 1 {
		t.Errorf("expected retrieve count=1, got %v", retrieveRespObj["count"])
	}

	// 3. GET /api/v1/mq/retrieve (With INVALID signature)
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	if len(badSig) > 0 {
		badSig[0] ^= 0xFF
	}
	reqRetrieveBad, _ := http.NewRequest("GET", srv.URL+"/api/v1/mq/retrieve", nil)
	reqRetrieveBad.Header.Set("X-URN", urn)
	reqRetrieveBad.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	reqRetrieveBad.Header.Set("X-Pubkey", hex.EncodeToString(pubKey))
	reqRetrieveBad.Header.Set("X-Signature", hex.EncodeToString(badSig))

	respRetrieveBad, err := client.Do(reqRetrieveBad)
	if err != nil {
		t.Fatalf("GET retrieve with bad auth error: %v", err)
	}
	defer respRetrieveBad.Body.Close()
	if respRetrieveBad.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected retrieve with bad auth status 401, got %d", respRetrieveBad.StatusCode)
	}

	// 3.5. GET /api/v1/mq/retrieve (With MISSING signature headers)
	reqRetrieveNoHeaders, _ := http.NewRequest("GET", srv.URL+"/api/v1/mq/retrieve", nil)
	reqRetrieveNoHeaders.Header.Set("X-URN", urn)
	respRetrieveNoHeaders, err := client.Do(reqRetrieveNoHeaders)
	if err != nil {
		t.Fatalf("GET retrieve with missing headers error: %v", err)
	}
	defer respRetrieveNoHeaders.Body.Close()
	if respRetrieveNoHeaders.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected retrieve with missing headers status 401, got %d", respRetrieveNoHeaders.StatusCode)
	}

	// 4. POST /api/v1/mq/ack
	ackReqObj := ackReq{
		MessageIDs: []string{"msg-http-id"},
	}
	bodyAckBytes, _ := json.Marshal(ackReqObj)
	respAck, err := http.Post(srv.URL+"/api/v1/mq/ack", "application/json", strings.NewReader(string(bodyAckBytes)))
	if err != nil {
		t.Fatalf("POST ack error: %v", err)
	}
	defer respAck.Body.Close()

	if respAck.StatusCode != http.StatusOK {
		t.Errorf("expected ack status 200, got %d", respAck.StatusCode)
	}

	var ackRespObj map[string]interface{}
	json.NewDecoder(respAck.Body).Decode(&ackRespObj)
	if ackRespObj["ok"] != true || ackRespObj["deleted"].(float64) != 1 {
		t.Errorf("unexpected ack response: %v", ackRespObj)
	}
}

func TestMQStoragePolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mq-policy-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "mq.db")
	store, err := NewStore(dbPath, 1, 10)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	// 1. Test isStoreAllowed = false
	handler1 := HTTPHandler(store, func() bool { return false }, func(recipientURN string) bool { return true })
	srv1 := httptest.NewServer(handler1)
	defer srv1.Close()

	senderPubKey, senderPrivKey, _ := ed25519.GenerateKey(nil)
	kp := &crypto.IdentityKeyPair{PublicKey: senderPubKey, PrivateKey: senderPrivKey}
	senderURN := kp.URN()

	urn := "urn:hermes:agent:recipient-policy"
	env := &pb.EncryptedEnvelope{
		MessageId:  "msg-policy-1",
		Ciphertext: []byte("ciphertext"),
		SenderUrn:  senderURN,
	}
	envBytes, _ := goproto.Marshal(env)

	storeReqObj := storeReq{
		RecipientURN: urn,
		PayloadProto: envBytes,
	}
	bodyBytes, _ := json.Marshal(storeReqObj)

	req1, _ := http.NewRequest("POST", srv1.URL+"/api/v1/mq/store", strings.NewReader(string(bodyBytes)))
	req1.Header.Set("Content-Type", "application/json")
	payloadSig := ed25519.Sign(senderPrivKey, bodyBytes)
	req1.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(payloadSig)+":"+hex.EncodeToString(senderPubKey))

	client := &http.Client{}
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("POST store when store disabled error: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when store is disabled, got %d", resp1.StatusCode)
	}

	// 2. Test isForwardAllowed = false for specific URN
	handler2 := HTTPHandler(store, func() bool { return true }, func(recipientURN string) bool {
		return recipientURN != "urn:hermes:agent:blocked-recipient"
	})
	srv2 := httptest.NewServer(handler2)
	defer srv2.Close()

	// Store to non-blocked recipient: should succeed (200)
	req2Ok, _ := http.NewRequest("POST", srv2.URL+"/api/v1/mq/store", strings.NewReader(string(bodyBytes)))
	req2Ok.Header.Set("Content-Type", "application/json")
	req2Ok.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(payloadSig)+":"+hex.EncodeToString(senderPubKey))
	resp2Ok, err := client.Do(req2Ok)
	if err != nil {
		t.Fatalf("POST store non-blocked error: %v", err)
	}
	defer resp2Ok.Body.Close()
	if resp2Ok.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for allowed recipient, got %d", resp2Ok.StatusCode)
	}

	// Store to blocked recipient: should fail with 403
	blockedReqObj := storeReq{
		RecipientURN: "urn:hermes:agent:blocked-recipient",
		PayloadProto: envBytes,
	}
	blockedBodyBytes, _ := json.Marshal(blockedReqObj)
	req2Blocked, _ := http.NewRequest("POST", srv2.URL+"/api/v1/mq/store", strings.NewReader(string(blockedBodyBytes)))
	req2Blocked.Header.Set("Content-Type", "application/json")
	blockedPayloadSig := ed25519.Sign(senderPrivKey, blockedBodyBytes)
	req2Blocked.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(blockedPayloadSig)+":"+hex.EncodeToString(senderPubKey))
	resp2Blocked, err := client.Do(req2Blocked)
	if err != nil {
		t.Fatalf("POST store blocked error: %v", err)
	}
	defer resp2Blocked.Body.Close()
	if resp2Blocked.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for blocked recipient, got %d", resp2Blocked.StatusCode)
	}
}

