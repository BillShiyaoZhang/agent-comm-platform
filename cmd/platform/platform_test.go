package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	golibp2p "github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	goproto "google.golang.org/protobuf/proto"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/api"
	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	relaypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/relay"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	"github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/registry"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
)

// Helper to write length-prefixed protocol data
func writePrefixed(w io.Writer, msg goproto.Message) error {
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
func readPrefixed(r io.Reader, msg goproto.Message) error {
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

func TestPlatformFullIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tempDir, err := os.MkdirTemp("", "platform-integration-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create directories
	keysDir := filepath.Join(tempDir, "keys")
	dataDir := filepath.Join(tempDir, "data")
	os.MkdirAll(keysDir, 0755)
	os.MkdirAll(dataDir, 0755)

	// Setup Config
	cfg := config.DefaultConfig()
	cfg.Platform.DataDir = dataDir
	cfg.Identity.KeysDir = keysDir
	cfg.Registry.PersistDB = filepath.Join(dataDir, "registry.db")
	cfg.MQ.DBPath = filepath.Join(dataDir, "mq.db")
	cfg.API.ListenAddr = "127.0.0.1:0" // Random free port
	cfg.Libp2p.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}

	// 1. Identity
	id, err := crypto.LoadOrCreateIdentity(cfg.Identity.KeysDir)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}

	// 2. libp2p Host
	libp2pPrivKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(id.Ed25519.PrivateKey)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	h, err := golibp2p.New(
		golibp2p.ListenAddrStrings(cfg.Libp2p.ListenAddrs...),
		golibp2p.Identity(libp2pPrivKey),
	)
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer h.Close()

	// 3. Registry
	regStore, err := registrypkg.NewStore(cfg.Registry.PersistDB, cfg.Registry.TTLHours)
	if err != nil {
		t.Fatalf("registry store: %v", err)
	}
	defer regStore.Close()
	registry.NewServer(h, regStore).Register()

	// Self-register
	err = regStore.RegisterWithSignature(id.Ed25519.URN(), h.ID().String(), hostAddrs(h), nil,
		id.X25519PK, id.Ed25519.PublicKey, nil, 0)
	if err != nil {
		t.Fatalf("self register: %v", err)
	}

	// 4. Relay
	relayCfg := relaypkg.DefaultConfig()
	rs, err := relaypkg.Start(h, relayCfg)
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	defer rs.Close()

	// 5. MQ
	mqStore, err := mqpkg.NewStore(cfg.MQ.DBPath, cfg.MQ.DefaultTTLDays, cfg.MQ.MaxMsgsPerURN)
	if err != nil {
		t.Fatalf("mq store: %v", err)
	}
	defer mqStore.Close()
	_, err = mq.NewServer(h, mqStore)
	if err != nil {
		t.Fatalf("create mq server: %v", err)
	}

	// 6. HTTP API
	apiSrv := api.New(cfg.API.ListenAddr, regStore, mqStore, h.ID().String())
	
	// We need to resolve the actual port bound to the HTTP server
	// We can listen on a TCP port first to get a random port, close it, and bind the server,
	// but api.Start binds internally. To get around this and find the port, we can listen ourselves and pass the listener,
	// however api.Start does: `ln, err := net.Listen("tcp", s.srv.Addr)`.
	// Since api.Start doesn't expose the listener or address easily, let's write a small helper or just start it on an actual port.
	// Actually, we can listen on a free port ourselves, close it, and immediately use it. There is a tiny race condition but it is usually fine for testing.
	// Let's find a free port:
	freePort := 1024 + (time.Now().UnixNano() % 50000)
	cfg.API.ListenAddr = fmt.Sprintf("127.0.0.1:%d", freePort)
	apiSrv = api.New(cfg.API.ListenAddr, regStore, mqStore, h.ID().String())

	go func() {
		apiSrv.Start(ctx)
	}()
	time.Sleep(100 * time.Millisecond) // Give HTTP server a moment to start

	// 7. Setup Client Host
	hCli, err := golibp2p.New(golibp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create client host: %v", err)
	}
	defer hCli.Close()
	hCli.Peerstore().AddAddrs(h.ID(), h.Addrs(), peerstore.PermanentAddrTTL)

	// --- VERIFICATION 1: HTTP Healthcheck ---
	respHealth, err := http.Get(fmt.Sprintf("http://%s/healthz", cfg.API.ListenAddr))
	if err != nil {
		t.Fatalf("GET healthz error: %v", err)
	}
	defer respHealth.Body.Close()
	if respHealth.StatusCode != http.StatusOK {
		t.Errorf("healthz returned status %d", respHealth.StatusCode)
	}
	var healthMap map[string]string
	json.NewDecoder(respHealth.Body).Decode(&healthMap)
	if healthMap["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", healthMap["status"])
	}

	// --- VERIFICATION 2: HTTP status/metrics ---
	respStatus, err := http.Get(fmt.Sprintf("http://%s/api/v1/status", cfg.API.ListenAddr))
	if err != nil {
		t.Fatalf("GET status error: %v", err)
	}
	defer respStatus.Body.Close()
	var statusMap map[string]interface{}
	json.NewDecoder(respStatus.Body).Decode(&statusMap)
	if statusMap["registry_urns"] == nil {
		t.Errorf("expected registry_urns in status response, got %v", statusMap)
	}

	// --- VERIFICATION 3: libp2p Registry (Register & Resolve) ---
	streamReg, err := hCli.NewStream(ctx, h.ID(), protocol.ID(registry.ProtoID))
	if err != nil {
		t.Fatalf("open reg stream: %v", err)
	}
	clientURN := "urn:hermes:agent:client-urn"
	reqReg := &pb.URNRegistryRequest{
		Op: &pb.URNRegistryRequest_Register{
			Register: &pb.RegisterRequest{
				Urn:          clientURN,
				PeerId:       hCli.ID().String(),
				Addrs:        []string{"/ip4/127.0.0.1/tcp/9999"},
				X25519Pubkey: []byte("client_x25519_pk_bytes_dummy_32b"),
			},
		},
	}
	reqBytes, _ := goproto.Marshal(reqReg)
	streamReg.Write(reqBytes)
	streamReg.CloseWrite()

	respRegBytes, err := io.ReadAll(streamReg)
	if err != nil {
		t.Fatalf("read register response: %v", err)
	}
	streamReg.Close()

	var respReg pb.URNRegistryResponse
	goproto.Unmarshal(respRegBytes, &respReg)
	if !respReg.GetRegister().Ok {
		t.Errorf("libp2p register failed: %s", respReg.GetRegister().Info)
	}

	// Resolve the URN over libp2p
	streamRes, err := hCli.NewStream(ctx, h.ID(), protocol.ID(registry.ProtoID))
	if err != nil {
		t.Fatalf("open resolve stream: %v", err)
	}
	reqRes := &pb.URNRegistryRequest{
		Op: &pb.URNRegistryRequest_Resolve{
			Resolve: &pb.ResolveRequest{
				Urn: clientURN,
			},
		},
	}
	reqResBytes, _ := goproto.Marshal(reqRes)
	streamRes.Write(reqResBytes)
	streamRes.CloseWrite()

	respResBytes, err := io.ReadAll(streamRes)
	if err != nil {
		t.Fatalf("read resolve response: %v", err)
	}
	streamRes.Close()

	var respRes pb.URNRegistryResponse
	goproto.Unmarshal(respResBytes, &respRes)
	if !respRes.GetResolve().Found || respRes.GetResolve().PeerId != hCli.ID().String() {
		t.Errorf("libp2p resolve failed or mismatch: %+v", respRes.GetResolve())
	}

	// --- VERIFICATION 4: libp2p MQ (Store, Retrieve & Ack) ---
	streamMQ, err := hCli.NewStream(ctx, h.ID(), protocol.ID(mq.ProtoID))
	if err != nil {
		t.Fatalf("open MQ stream: %v", err)
	}
	defer streamMQ.Close()

	env := &pb.EncryptedEnvelope{
		MessageId:  "msg-id-123",
		Ciphertext: []byte("encrypted message"),
	}

	reqStore := &pb.MQRequest{
		Op: &pb.MQRequest_Store{
			Store: &pb.StoreRequest{
				RecipientUrn: clientURN,
				Payload:      env,
			},
		},
	}

	if err := writePrefixed(streamMQ, reqStore); err != nil {
		t.Fatalf("write MQ store request: %v", err)
	}

	var respStore pb.MQResponse
	if err := readPrefixed(streamMQ, &respStore); err != nil {
		t.Fatalf("read MQ store response: %v", err)
	}
	if !respStore.GetStore().Ok || respStore.GetStore().MessageId != "msg-id-123" {
		t.Errorf("MQ store failed: %+v", respStore.GetStore())
	}

	// Retrieve over libp2p
	streamMQ2, err := hCli.NewStream(ctx, h.ID(), protocol.ID(mq.ProtoID))
	if err != nil {
		t.Fatalf("open MQ retrieve stream: %v", err)
	}
	defer streamMQ2.Close()

	reqRetrieve := &pb.MQRequest{
		Op: &pb.MQRequest_Retrieve{
			Retrieve: &pb.RetrieveRequest{
				RecipientUrn: clientURN,
			},
		},
	}
	if err := writePrefixed(streamMQ2, reqRetrieve); err != nil {
		t.Fatalf("write MQ retrieve request: %v", err)
	}

	var respRetrieve pb.MQResponse
	if err := readPrefixed(streamMQ2, &respRetrieve); err != nil {
		t.Fatalf("read MQ retrieve response: %v", err)
	}
	payloads := respRetrieve.GetRetrieve().Payloads
	if len(payloads) != 1 || payloads[0].MessageId != "msg-id-123" {
		t.Errorf("MQ retrieve failed, got: %+v", payloads)
	}

	// Ack over libp2p
	streamMQ3, err := hCli.NewStream(ctx, h.ID(), protocol.ID(mq.ProtoID))
	if err != nil {
		t.Fatalf("open MQ ack stream: %v", err)
	}
	defer streamMQ3.Close()

	reqAck := &pb.MQRequest{
		Op: &pb.MQRequest_Ack{
			Ack: &pb.AckRequest{
				MessageIds: []string{"msg-id-123"},
			},
		},
	}
	if err := writePrefixed(streamMQ3, reqAck); err != nil {
		t.Fatalf("write MQ ack request: %v", err)
	}

	var respAck pb.MQResponse
	if err := readPrefixed(streamMQ3, &respAck); err != nil {
		t.Fatalf("read MQ ack response: %v", err)
	}
	if !respAck.GetAck().Ok || respAck.GetAck().DeletedCount != 1 {
		t.Errorf("MQ ack failed: %+v", respAck.GetAck())
	}

	// --- VERIFICATION 5: HTTP MQ Retrieve with Auth ---
	// Store one envelope first
	_, err = mqStore.StoreEnvelope(ctx, clientURN, env, 0)
	if err != nil {
		t.Fatalf("store envelope: %v", err)
	}

	// Generate signature
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	timestamp := time.Now().Unix()
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(timestamp))
	msg := append([]byte("mq-retrieve|"+clientURN+"|"), tsBuf...)
	sig := ed25519.Sign(privKey, msg)

	httpCli := &http.Client{}
	reqHTTPRetrieve, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/v1/mq/retrieve", cfg.API.ListenAddr), nil)
	reqHTTPRetrieve.Header.Set("X-URN", clientURN)
	reqHTTPRetrieve.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	reqHTTPRetrieve.Header.Set("X-Pubkey", hex.EncodeToString(pubKey))
	reqHTTPRetrieve.Header.Set("X-Signature", hex.EncodeToString(sig))

	respHTTPRetrieve, err := httpCli.Do(reqHTTPRetrieve)
	if err != nil {
		t.Fatalf("GET HTTP retrieve error: %v", err)
	}
	defer respHTTPRetrieve.Body.Close()

	if respHTTPRetrieve.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respHTTPRetrieve.Body)
		t.Fatalf("GET HTTP retrieve auth failed, status: %d, body: %s", respHTTPRetrieve.StatusCode, string(b))
	}
	var httpRetMap map[string]interface{}
	json.NewDecoder(respHTTPRetrieve.Body).Decode(&httpRetMap)
	if httpRetMap["count"].(float64) != 1 {
		t.Errorf("expected count 1, got %v", httpRetMap["count"])
	}
}
