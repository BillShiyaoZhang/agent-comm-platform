package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	coreregistry "github.com/BillShiyaoZhang/agent-comm/registry"
)

func TestRegistryStore(t *testing.T) {
	store := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	if err := registerTestRecord(store, req); err != nil {
		t.Fatal(err)
	}
	entry, err := store.ResolveEntry(req.URN)
	if err != nil || entry == nil {
		t.Fatalf("resolve registered owner: entry=%+v err=%v", entry, err)
	}
	if entry.URN != req.URN || entry.PeerID != req.PeerID || !reflect.DeepEqual(entry.Addrs, req.Addrs) {
		t.Fatalf("entry mismatch: %+v", entry)
	}
	if entry, err := store.ResolveEntry("urn:hermes:agent:nonexistent"); err != nil || entry != nil {
		t.Fatalf("resolve nonexistent: entry=%+v err=%v", entry, err)
	}
	urns, err := store.ListURNs()
	if err != nil || !reflect.DeepEqual(urns, []string{req.URN}) {
		t.Fatalf("list URNs: %v, %v", urns, err)
	}
	entries, err := store.ListEntries()
	if err != nil || len(entries) != 1 || !reflect.DeepEqual(entries[0], entry) {
		t.Fatalf("list entries must include the authenticated record: %+v, %v", entries, err)
	}
}

func TestRegistryLibp2pServer(t *testing.T) {
	store := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	exchange := newRegistryTestPeer(t, store, owner)
	req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	response := exchange(t, registryProtoRequest(req)).GetRegister()
	if response == nil || !response.Ok {
		t.Fatalf("register failed: %+v", response)
	}
	resolved := exchange(t, &pb.URNRegistryRequest{Op: &pb.URNRegistryRequest_Resolve{
		Resolve: &pb.ResolveRequest{Urn: req.URN},
	}}).GetResolve()
	if resolved == nil || !resolved.Found || resolved.PeerId != req.PeerID ||
		!reflect.DeepEqual(resolved.Addrs, req.Addrs) || !reflect.DeepEqual(resolved.X25519Pubkey, req.X25519Pubkey) {
		t.Fatalf("resolve mismatch: %+v", resolved)
	}
	if err := coreregistry.VerifyRegistration(req.URN, resolved.PeerId, resolved.X25519Pubkey,
		resolved.Ed25519Pubkey, resolved.Signature, resolved.StoresUserData, resolved.Timestamp); err != nil {
		t.Fatalf("resolved record is not authenticated: %v", err)
	}
}

func TestRegistryHTTPHandlers(t *testing.T) {
	store := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	server := httptest.NewServer(HTTPHandler(store, func(string) bool { return true }))
	t.Cleanup(server.Close)
	req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	if err := postRegistryRecord(t, server, owner, req); err != nil {
		t.Fatal(err)
	}
	unsigned, err := http.Post(server.URL+"/api/v1/registry/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned request status: %d", unsigned.StatusCode)
	}
	var resolved struct {
		Found  bool   `json:"found"`
		PeerID string `json:"peer_id"`
	}
	getRegistryJSON(t, server.URL+"/api/v1/registry/resolve?urn="+url.QueryEscape(req.URN), http.StatusOK, &resolved)
	if !resolved.Found || resolved.PeerID != req.PeerID {
		t.Fatalf("resolve mismatch: %+v", resolved)
	}
	var listed struct {
		Count int      `json:"count"`
		URNs  []string `json:"urns"`
	}
	getRegistryJSON(t, server.URL+"/api/v1/registry/list", http.StatusOK, &listed)
	if listed.Count != 1 || !reflect.DeepEqual(listed.URNs, []string{req.URN}) {
		t.Fatalf("list mismatch: %+v", listed)
	}
}

func getRegistryJSON(t *testing.T, target string, status int, result any) {
	t.Helper()
	response, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("GET status=%d, want %d", response.StatusCode, status)
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryResolveInvalidPeer(t *testing.T) {
	store := newRegistryTestStore(t)
	// Simulate historical pollution directly: the public write API must never
	// accept this unsigned record merely to create a test fixture.
	_, err := store.db.Exec(`INSERT INTO registry (urn, peer_id, expires_at, updated_at) VALUES (?, ?, ?, ?)`,
		"urn:hermes:agent:invalid", "invalid-peer-id-format", time.Now().Add(time.Hour).Unix(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	exchange := newRegistryTestPeer(t, store, newRegistryTestIdentity(t))
	resolved := exchange(t, &pb.URNRegistryRequest{Op: &pb.URNRegistryRequest_Resolve{
		Resolve: &pb.ResolveRequest{Urn: "urn:hermes:agent:invalid"},
	}}).GetResolve()
	if resolved == nil || resolved.Found {
		t.Fatalf("historical invalid peer must not resolve: %+v", resolved)
	}
}

func TestRegistryHTTPForwardingPolicy(t *testing.T) {
	store := newRegistryTestStore(t)
	storing, safe := newRegistryTestIdentity(t), newRegistryTestIdentity(t)
	for _, owner := range []*registryTestIdentity{storing, safe} {
		req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
		req.StoresUserData = owner == storing
		signRegistryRecord(owner, &req)
		if err := registerTestRecord(store, req); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(HTTPHandler(store, func(urn string) bool {
		entry, err := store.ResolveEntry(urn)
		return err != nil || entry == nil || !entry.StoresUserData
	}))
	t.Cleanup(server.Close)
	var allowed struct {
		Found bool `json:"found"`
	}
	getRegistryJSON(t, server.URL+"/api/v1/registry/resolve?urn="+url.QueryEscape(safe.Ed25519.URN()), http.StatusOK, &allowed)
	if !allowed.Found {
		t.Fatal("safe agent must resolve")
	}
	var blocked struct {
		Found bool   `json:"found"`
		Error string `json:"error"`
	}
	getRegistryJSON(t, server.URL+"/api/v1/registry/resolve?urn="+url.QueryEscape(storing.Ed25519.URN()), http.StatusForbidden, &blocked)
	if blocked.Found || !strings.Contains(blocked.Error, "forwarding to storage platforms is disabled") {
		t.Fatalf("unexpected policy response: %+v", blocked)
	}
}
