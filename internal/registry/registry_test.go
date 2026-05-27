package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	goproto "google.golang.org/protobuf/proto"

	coreregistry "github.com/BillShiyaoZhang/agent-comm/registry"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
)

// Helper to create a signature
func makeRegistrySig(t *testing.T, urn, peerID string, timestamp int64, privKey ed25519.PrivateKey) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	msg := []byte(urn + "|" + peerID + "|")
	msg = append(msg, ts...)
	return ed25519.Sign(privKey, msg)
}

func TestRegistryStore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "registry-store-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "registry.db")
	store, err := NewStore(dbPath, 1) // 1 hour TTL
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	urn := "urn:hermes:agent:test1"
	peerID := "12D3KooWJsz...dummy"
	addrs := []string{"/ip4/127.0.0.1/tcp/4001"}
	xPK := []byte("X25519_PUBKEY_32_BYTES_0000000000") // 32 bytes dummy
	if len(xPK) < 32 {
		xPK = append(xPK, make([]byte, 32-len(xPK))...)
	}

	// 1. Basic Register & Resolve (no signature)
	err = store.RegisterWithSignature(urn, peerID, addrs, nil, xPK, nil, nil, 0)
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}

	entry, err := store.ResolveEntry(urn)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.URN != urn || entry.PeerID != peerID || entry.Addrs[0] != addrs[0] {
		t.Errorf("entry mismatch: %+v", entry)
	}

	// 2. Resolve non-existent URN
	entry, err = store.ResolveEntry("urn:hermes:agent:nonexistent")
	if err != nil {
		t.Fatalf("Resolve nonexistent error: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry, got %+v", entry)
	}

	// 3. List URNs
	urns, err := store.ListURNs()
	if err != nil {
		t.Fatalf("ListURNs error: %v", err)
	}
	if len(urns) != 1 || urns[0] != urn {
		t.Errorf("expected URNs list [\"%s\"], got %v", urn, urns)
	}

	// 4. Test Signature Verification
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	sigURN := "urn:hermes:agent:signed"
	sigPeerID := "12D3KooWJsz...dummy2"
	timestamp := time.Now().Unix()

	// Valid signature
	sig := makeRegistrySig(t, sigURN, sigPeerID, timestamp, privKey)
	err = store.RegisterWithSignature(sigURN, sigPeerID, addrs, nil, xPK, pubKey, sig, timestamp)
	if err != nil {
		t.Errorf("expected valid signature to succeed, got: %v", err)
	}

	// Invalid signature (modified message or bad key)
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	if len(badSig) > 0 {
		badSig[0] ^= 0xFF
	}
	err = store.RegisterWithSignature(sigURN, sigPeerID, addrs, nil, xPK, pubKey, badSig, timestamp)
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected registration with bad signature to fail, got: %v", err)
	}

	// Expired/Out of window timestamp
	oldTimestamp := time.Now().Unix() - 600
	oldSig := makeRegistrySig(t, sigURN, sigPeerID, oldTimestamp, privKey)
	err = store.RegisterWithSignature(sigURN, sigPeerID, addrs, nil, xPK, pubKey, oldSig, oldTimestamp)
	if err == nil || !strings.Contains(err.Error(), "timestamp out of window") {
		t.Errorf("expected registration with expired timestamp to fail, got: %v", err)
	}
}

func TestRegistryLibp2pServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tempDir, err := os.MkdirTemp("", "registry-libp2p-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "registry.db")
	store, err := NewStore(dbPath, 1)
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

	coreregistry.NewServer(hSrv, store).Register()

	// 2. Setup Client Host
	hCli, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create client host: %v", err)
	}
	defer hCli.Close()

	// Add server to client's peerstore
	hCli.Peerstore().AddAddrs(hSrv.ID(), hSrv.Addrs(), peerstore.PermanentAddrTTL)

	// 3. Test Register via libp2p stream
	streamReg, err := hCli.NewStream(ctx, hSrv.ID(), protocol.ID(coreregistry.ProtoID))
	if err != nil {
		t.Fatalf("open register stream: %v", err)
	}

	urn := "urn:hermes:agent:libp2p-test"
	peerID := hCli.ID().String()
	addrs := []string{"/ip4/192.168.1.100/tcp/5000"}
	xPK := make([]byte, 32)
	copy(xPK, []byte("x25519-public-key-32-bytes-long"))

	reqReg := &pb.URNRegistryRequest{
		Op: &pb.URNRegistryRequest_Register{
			Register: &pb.RegisterRequest{
				Urn:          urn,
				PeerId:       peerID,
				Addrs:        addrs,
				X25519Pubkey: xPK,
			},
		},
	}

	reqRegBytes, err := goproto.Marshal(reqReg)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	if _, err := streamReg.Write(reqRegBytes); err != nil {
		t.Fatalf("write register request: %v", err)
	}
	streamReg.CloseWrite() // Signal EOF to Server

	respRegBytes, err := io.ReadAll(streamReg)
	if err != nil {
		t.Fatalf("read register response: %v", err)
	}
	streamReg.Close()

	var respReg pb.URNRegistryResponse
	if err := goproto.Unmarshal(respRegBytes, &respReg); err != nil {
		t.Fatalf("unmarshal register response: %v", err)
	}

	regRes := respReg.GetRegister()
	if regRes == nil {
		t.Fatalf("expected RegisterResponse in oneof, got nil")
	}
	if !regRes.Ok {
		t.Errorf("RegisterResponse failed: %s", regRes.Info)
	}

	// 4. Test Resolve via libp2p stream
	streamRes, err := hCli.NewStream(ctx, hSrv.ID(), protocol.ID(coreregistry.ProtoID))
	if err != nil {
		t.Fatalf("open resolve stream: %v", err)
	}

	reqResQuery := &pb.URNRegistryRequest{
		Op: &pb.URNRegistryRequest_Resolve{
			Resolve: &pb.ResolveRequest{
				Urn: urn,
			},
		},
	}

	reqResBytes, err := goproto.Marshal(reqResQuery)
	if err != nil {
		t.Fatalf("marshal resolve request: %v", err)
	}

	if _, err := streamRes.Write(reqResBytes); err != nil {
		t.Fatalf("write resolve request: %v", err)
	}
	streamRes.CloseWrite() // Signal EOF

	respResBytes, err := io.ReadAll(streamRes)
	if err != nil {
		t.Fatalf("read resolve response: %v", err)
	}
	streamRes.Close()

	var respRes pb.URNRegistryResponse
	if err := goproto.Unmarshal(respResBytes, &respRes); err != nil {
		t.Fatalf("unmarshal resolve response: %v", err)
	}

	resolveRes := respRes.GetResolve()
	if resolveRes == nil {
		t.Fatalf("expected ResolveResponse, got nil")
	}
	if !resolveRes.Found {
		t.Error("expected URN to be found")
	}
	if resolveRes.PeerId != peerID {
		t.Errorf("expected PeerID %s, got %s", peerID, resolveRes.PeerId)
	}
	if len(resolveRes.Addrs) != 1 || resolveRes.Addrs[0] != addrs[0] {
		t.Errorf("expected addrs %v, got %v", addrs, resolveRes.Addrs)
	}
	if string(resolveRes.X25519Pubkey) != string(xPK) {
		t.Errorf("expected pubkey %v, got %v", xPK, resolveRes.X25519Pubkey)
	}
}

func TestRegistryHTTPHandlers(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "registry-http-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "registry.db")
	store, err := NewStore(dbPath, 1)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	handler := HTTPHandler(store)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 1. POST /api/v1/registry/register
	urn := "urn:hermes:agent:http-test"
	peerID := "12D3KooWJszDummyPeerID"
	addrs := []string{"/ip4/127.0.0.1/tcp/45041"}
	xPK := []byte("x25519-public-key-32-bytes-long")
	if len(xPK) < 32 {
		xPK = append(xPK, make([]byte, 32-len(xPK))...)
	}

	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	timestamp := time.Now().Unix()
	sig := makeRegistrySig(t, urn, peerID, timestamp, privKey)

	regReq := registerReq{
		URN:           urn,
		PeerID:        peerID,
		Addrs:         addrs,
		X25519Pubkey:  xPK,
		Ed25519Pubkey: pubKey,
		Signature:     sig,
		Timestamp:     timestamp,
	}

	bodyBytes, _ := json.Marshal(regReq)
	resp, err := http.Post(srv.URL+"/api/v1/registry/register", "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		t.Fatalf("POST register error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var regResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&regResp)
	if regResp["ok"] != true {
		t.Errorf("expected ok=true, got %v", regResp)
	}

	// 1.5. POST /api/v1/registry/register without signature (should fail with 401)
	regReqNoSig := registerReq{
		URN:          urn + "-no-sig",
		PeerID:       peerID,
		Addrs:        addrs,
		X25519Pubkey: xPK,
	}
	bodyBytesNoSig, _ := json.Marshal(regReqNoSig)
	respNoSig, err := http.Post(srv.URL+"/api/v1/registry/register", "application/json", strings.NewReader(string(bodyBytesNoSig)))
	if err != nil {
		t.Fatalf("POST register no sig error: %v", err)
	}
	defer respNoSig.Body.Close()
	if respNoSig.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 for unsigned register, got %d", respNoSig.StatusCode)
	}

	// 2. GET /api/v1/registry/resolve?urn=...
	respResolve, err := http.Get(srv.URL + "/api/v1/registry/resolve?urn=" + urn)
	if err != nil {
		t.Fatalf("GET resolve error: %v", err)
	}
	defer respResolve.Body.Close()

	if respResolve.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", respResolve.StatusCode)
	}

	var resolveResp map[string]interface{}
	json.NewDecoder(respResolve.Body).Decode(&resolveResp)
	if resolveResp["found"] != true {
		t.Errorf("expected found=true, got %v", resolveResp)
	}
	if resolveResp["peer_id"] != peerID {
		t.Errorf("expected peer_id %q, got %q", peerID, resolveResp["peer_id"])
	}

	// 3. GET /api/v1/registry/list
	respList, err := http.Get(srv.URL + "/api/v1/registry/list")
	if err != nil {
		t.Fatalf("GET list error: %v", err)
	}
	defer respList.Body.Close()

	if respList.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", respList.StatusCode)
	}

	var listResp map[string]interface{}
	json.NewDecoder(respList.Body).Decode(&listResp)
	countVal, ok := listResp["count"].(float64)
	if !ok || countVal != 1 {
		t.Errorf("expected count=1, got %v", listResp["count"])
	}
	urnsList, ok := listResp["urns"].([]interface{})
	if !ok || len(urnsList) != 1 || urnsList[0] != urn {
		t.Errorf("expected urns [%q], got %v", urn, listResp["urns"])
	}
}

// Dummy resolve checking for peer.Decode validation in server.go line 85
func TestRegistryResolveInvalidPeer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "registry-invalid-peer-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "registry.db")
	store, err := NewStore(dbPath, 1)
	if err != nil {
		t.Fatalf("NewStore error: %v", err)
	}
	defer store.Close()

	// Register with an invalid peer ID string (won't decode using peer.Decode)
	err = store.RegisterWithSignature("urn:hermes:agent:invalid", "invalid-peer-id-format", []string{"/ip4/127.0.0.1"}, nil, nil, nil, nil, 0)
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}

	// Test the libp2p server resolve behavior for this invalid entry
	hSrv, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	defer hSrv.Close()
	coreregistry.NewServer(hSrv, store).Register()

	hCli, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	defer hCli.Close()
	hCli.Peerstore().AddAddrs(hSrv.ID(), hSrv.Addrs(), peerstore.PermanentAddrTTL)

	stream, err := hCli.NewStream(context.Background(), hSrv.ID(), protocol.ID(coreregistry.ProtoID))
	if err != nil {
		t.Fatalf("open resolve stream: %v", err)
	}

	req := &pb.URNRegistryRequest{
		Op: &pb.URNRegistryRequest_Resolve{
			Resolve: &pb.ResolveRequest{
				Urn: "urn:hermes:agent:invalid",
			},
		},
	}
	b, _ := goproto.Marshal(req)
	stream.Write(b)
	stream.CloseWrite()

	respBytes, _ := io.ReadAll(stream)
	stream.Close()

	var resp pb.URNRegistryResponse
	goproto.Unmarshal(respBytes, &resp)

	resolveRes := resp.GetResolve()
	if resolveRes == nil {
		t.Fatal("expected resolve response")
	}
	if resolveRes.Found {
		t.Error("expected found=false for invalid peer ID (since peer.Decode should fail in stream handler)")
	}
}
