package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/agent"
	agentcrypto "github.com/BillShiyaoZhang/agent-comm/crypto"
	"github.com/BillShiyaoZhang/agent-comm/mq"
	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	coreregistry "github.com/BillShiyaoZhang/agent-comm/registry"
	"github.com/BillShiyaoZhang/agent-comm/session"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	goproto "google.golang.org/protobuf/proto"
)

type registryTestIdentity = agentcrypto.IdentityKeys

func newRegistryTestIdentity(t *testing.T) *registryTestIdentity {
	t.Helper()
	ed, err := agentcrypto.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk, pk, err := agentcrypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &registryTestIdentity{Ed25519: ed, X25519SK: sk, X25519PK: pk}
}

func newRegistryTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "registry.db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func signedRegistryRequest(t *testing.T, owner *registryTestIdentity, urn string) registerReq {
	t.Helper()
	pid, err := owner.PeerID()
	if err != nil {
		t.Fatal(err)
	}
	req := registerReq{
		URN: urn, PeerID: pid,
		Addrs:         []string{"/ip4/127.0.0.1/tcp/4001"},
		RelayAddrs:    []string{"/ip4/127.0.0.1/tcp/4002"},
		X25519Pubkey:  append([]byte(nil), owner.X25519PK...),
		Ed25519Pubkey: append([]byte(nil), owner.Ed25519.PublicKey...),
		Timestamp:     time.Now().Unix(),
	}
	signRegistryRecord(owner, &req)
	return req
}

func signRegistryRecord(owner *registryTestIdentity, req *registerReq) {
	req.Signature = ed25519.Sign(owner.Ed25519.PrivateKey,
		coreregistry.BuildSignedMsg(req.URN, req.PeerID, req.X25519Pubkey, req.StoresUserData, req.Timestamp))
}

func registerTestRecord(store *Store, req registerReq) error {
	return store.RegisterWithSignature(req.URN, req.PeerID, req.Addrs, req.RelayAddrs,
		req.X25519Pubkey, req.Ed25519Pubkey, req.Signature, req.StoresUserData, req.Timestamp)
}

func postRegistryRecord(t *testing.T, server *httptest.Server, signer *registryTestIdentity, req registerReq) error {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/registry/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Ed25519 "+hex.EncodeToString(ed25519.Sign(signer.Ed25519.PrivateKey, body))+":"+hex.EncodeToString(signer.Ed25519.PublicKey))
	response, err := server.Client().Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode < 400 || response.StatusCode >= 500 {
			t.Fatalf("registration must fail explicitly with a client error: HTTP %d: %s", response.StatusCode, responseBody)
		}
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, responseBody)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("HTTP success without ok: %s", responseBody)
	}
	return nil
}

func registryProtoRequest(req registerReq) *pb.URNRegistryRequest {
	return &pb.URNRegistryRequest{Op: &pb.URNRegistryRequest_Register{Register: &pb.RegisterRequest{
		Urn: req.URN, PeerId: req.PeerID, Addrs: req.Addrs, RelayAddrs: req.RelayAddrs,
		X25519Pubkey: req.X25519Pubkey, Ed25519Pubkey: req.Ed25519Pubkey,
		Signature: req.Signature, Timestamp: req.Timestamp, StoresUserData: req.StoresUserData,
	}}}
}

// Use real loopback libp2p hosts and protobuf streams, including authenticated
// transport identities. A publisher can carry another owner's signed record.
func newRegistryTestPeer(t *testing.T, store *Store, publisher *registryTestIdentity) func(*testing.T, *pb.URNRegistryRequest) *pb.URNRegistryResponse {
	t.Helper()
	server, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	coreregistry.NewServer(server, store).Register()
	privateKey, err := p2pcrypto.UnmarshalEd25519PrivateKey(publisher.Ed25519.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := libp2p.New(libp2p.Identity(privateKey), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.Peerstore().AddAddrs(server.ID(), server.Addrs(), peerstore.PermanentAddrTTL)
	return func(t *testing.T, req *pb.URNRegistryRequest) *pb.URNRegistryResponse {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stream, err := client.NewStream(ctx, server.ID(), protocol.ID(coreregistry.ProtoID))
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		body, err := goproto.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		result, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		var response pb.URNRegistryResponse
		if err := goproto.Unmarshal(result, &response); err != nil {
			t.Fatal(err)
		}
		return &response
	}
}

type registryRowSnapshot struct {
	URN, PeerID, Addrs, RelayAddrs                  string
	X25519, Ed25519, Signature                      []byte
	StoresUserData, Timestamp, ExpiresAt, UpdatedAt int64
}

func registrySnapshot(t *testing.T, store *Store, urn string) *registryRowSnapshot {
	t.Helper()
	var row registryRowSnapshot
	err := store.db.QueryRow(`SELECT urn, peer_id, addrs, relay_addrs, x25519_pubkey, ed25519_pubkey, signature,
		stores_user_data, timestamp, expires_at, updated_at FROM registry WHERE urn=?`, urn).Scan(
		&row.URN, &row.PeerID, &row.Addrs, &row.RelayAddrs, &row.X25519, &row.Ed25519, &row.Signature,
		&row.StoresUserData, &row.Timestamp, &row.ExpiresAt, &row.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return &row
}

func shortenRegistryLease(t *testing.T, store *Store, urn string) {
	t.Helper()
	// Distinct values detect an illicit TTL/update refresh even within the same
	// clock second, without sleeping or replacing the production clock.
	_, err := store.db.Exec(`UPDATE registry SET expires_at=?, updated_at=? WHERE urn=?`,
		time.Now().Add(2*time.Minute).Unix(), time.Now().Add(-time.Minute).Unix(), urn)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegistryOwnershipAcrossWritePaths(t *testing.T) {
	for _, transport := range []string{"store", "http", "libp2p"} {
		t.Run(transport, func(t *testing.T) {
			store := newRegistryTestStore(t)
			owner, attacker := newRegistryTestIdentity(t), newRegistryTestIdentity(t)
			server := httptest.NewServer(HTTPHandler(store, nil))
			t.Cleanup(server.Close)
			submit := func(t *testing.T, signer *registryTestIdentity, req registerReq) error {
				return registerTestRecord(store, req)
			}
			if transport == "http" {
				submit = func(t *testing.T, signer *registryTestIdentity, req registerReq) error {
					return postRegistryRecord(t, server, signer, req)
				}
			} else if transport == "libp2p" {
				exchange := newRegistryTestPeer(t, store, attacker)
				submit = func(t *testing.T, signer *registryTestIdentity, req registerReq) error {
					response := exchange(t, registryProtoRequest(req)).GetRegister()
					if response == nil {
						t.Fatal("missing register response")
					}
					if !response.Ok {
						if response.Info == "" {
							t.Fatal("rejection must explain the failure")
						}
						return fmt.Errorf("%s", response.Info)
					}
					return nil
				}
			}

			for _, namespace := range []string{agentcrypto.DefaultURNPrefix, "urn:custom-company:agent"} {
				t.Run("owner_lifecycle/"+namespace, func(t *testing.T) {
					owner.Ed25519.URNPrefix = namespace
					req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
					if err := submit(t, owner, req); err != nil {
						t.Fatalf("first registration: %v", err)
					}
					req.Addrs = []string{"/ip4/127.0.0.1/tcp/5001"}
					req.RelayAddrs = []string{"/ip4/127.0.0.1/tcp/5002"}
					req.X25519Pubkey = newRegistryTestIdentity(t).X25519PK
					req.StoresUserData = true
					signRegistryRecord(owner, &req)
					if err := submit(t, owner, req); err != nil {
						t.Fatalf("owner update: %v", err)
					}
					entry, err := store.ResolveEntry(req.URN)
					if err != nil || entry == nil || !reflect.DeepEqual(entry.Addrs, req.Addrs) ||
						!reflect.DeepEqual(entry.RelayAddrs, req.RelayAddrs) || !bytes.Equal(entry.X25519Pubkey, req.X25519Pubkey) || !entry.StoresUserData {
						t.Fatalf("owner update not stored: %+v, %v", entry, err)
					}
					shortenRegistryLease(t, store, req.URN)
					before := registrySnapshot(t, store, req.URN)
					if err := submit(t, owner, req); err != nil {
						t.Fatalf("owner renewal: %v", err)
					}
					after := registrySnapshot(t, store, req.URN)
					if after.ExpiresAt <= before.ExpiresAt || after.UpdatedAt <= before.UpdatedAt {
						t.Fatal("renewal did not extend the lease")
					}
				})
			}
			owner.Ed25519.URNPrefix = ""
			urn := owner.Ed25519.URN()
			mutations := []struct {
				name   string
				mutate func(*registerReq)
			}{
				{"wrong_owner", func(r *registerReq) { *r = signedRegistryRequest(t, attacker, urn) }},
				{"missing_ed25519_key", func(r *registerReq) { r.Ed25519Pubkey = nil }},
				{"short_ed25519_key", func(r *registerReq) { r.Ed25519Pubkey = r.Ed25519Pubkey[:31] }},
				{"long_ed25519_key", func(r *registerReq) { r.Ed25519Pubkey = append(r.Ed25519Pubkey, 0) }},
				{"corrupt_ed25519_key", func(r *registerReq) { r.Ed25519Pubkey[0] ^= 0xff }},
				{"missing_x25519_key", func(r *registerReq) { r.X25519Pubkey = nil; signRegistryRecord(owner, r) }},
				{"short_x25519_key", func(r *registerReq) { r.X25519Pubkey = r.X25519Pubkey[:31]; signRegistryRecord(owner, r) }},
				{"long_x25519_key", func(r *registerReq) { r.X25519Pubkey = append(r.X25519Pubkey, 0); signRegistryRecord(owner, r) }},
				{"substituted_x25519_key", func(r *registerReq) { r.X25519Pubkey[0] ^= 0xff }},
				{"missing_signature", func(r *registerReq) { r.Signature = nil }},
				{"short_signature", func(r *registerReq) { r.Signature = r.Signature[:63] }},
				{"long_signature", func(r *registerReq) { r.Signature = append(r.Signature, 0) }},
				{"corrupt_signature", func(r *registerReq) { r.Signature[0] ^= 0xff }},
				{"mismatched_peer_id", func(r *registerReq) { r.PeerID, _ = attacker.PeerID(); signRegistryRecord(owner, r) }},
				{"invalid_peer_id", func(r *registerReq) { r.PeerID = "invalid-peer"; signRegistryRecord(owner, r) }},
				{"missing_peer_id", func(r *registerReq) { r.PeerID = ""; signRegistryRecord(owner, r) }},
			}
			for _, timestampCase := range []struct {
				name      string
				timestamp int64
			}{
				{"zero", 0}, {"negative", -1}, {"expired", time.Now().Add(-10 * time.Minute).Unix()},
				{"future", time.Now().Add(10 * time.Minute).Unix()}, {"minimum", math.MinInt64}, {"maximum", math.MaxInt64},
			} {
				mutations = append(mutations, struct {
					name   string
					mutate func(*registerReq)
				}{
					"timestamp_" + timestampCase.name, func(r *registerReq) { r.Timestamp = timestampCase.timestamp; signRegistryRecord(owner, r) },
				})
			}
			for _, test := range mutations {
				t.Run(test.name, func(t *testing.T) {
					for _, existing := range []bool{false, true} {
						t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
							if err := store.EvictEntry(urn); err != nil {
								t.Fatal(err)
							}
							if existing {
								if err := submit(t, owner, signedRegistryRequest(t, owner, urn)); err != nil {
									t.Fatal(err)
								}
								shortenRegistryLease(t, store, urn)
							}
							before := registrySnapshot(t, store, urn)
							bad := signedRegistryRequest(t, owner, urn)
							bad.Addrs, bad.RelayAddrs = []string{"/ip4/127.0.0.1/tcp/6666"}, []string{"/ip4/127.0.0.1/tcp/6667"}
							bad.StoresUserData = true
							signRegistryRecord(owner, &bad)
							test.mutate(&bad)
							signer := owner
							if test.name == "wrong_owner" {
								signer = attacker
							}
							if err := submit(t, signer, bad); err == nil {
								t.Fatal("invalid registration accepted")
							}
							after := registrySnapshot(t, store, urn)
							if !reflect.DeepEqual(after, before) {
								t.Fatalf("rejected write changed persisted content/lease:\nbefore=%+v\nafter=%+v", before, after)
							}
							if existing {
								entry, err := store.ResolveEntry(urn)
								if err != nil || entry == nil || !bytes.Equal(entry.Ed25519Pubkey, owner.Ed25519.PublicKey) {
									t.Fatalf("owner no longer resolves: %+v %v", entry, err)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestRegistryLegacyRegisterCannotBypassOwnership(t *testing.T) {
	store := newRegistryTestStore(t)
	owner, attacker := newRegistryTestIdentity(t), newRegistryTestIdentity(t)
	urn := owner.Ed25519.URN()
	for _, existing := range []bool{false, true} {
		if existing {
			if err := registerTestRecord(store, signedRegistryRequest(t, owner, urn)); err != nil {
				t.Fatal(err)
			}
			shortenRegistryLease(t, store, urn)
		}
		before := registrySnapshot(t, store, urn)
		pid, err := attacker.PeerID()
		if err != nil {
			t.Fatal(err)
		}
		if ok, reason := store.Register(urn, pid, []string{"/ip4/127.0.0.1/tcp/6666"}, attacker.X25519PK); ok || reason == "" {
			t.Fatalf("legacy registration accepted: ok=%t reason=%q", ok, reason)
		}
		if after := registrySnapshot(t, store, urn); !reflect.DeepEqual(before, after) {
			t.Fatal("legacy registration changed the database")
		}
	}
}

func TestRegistryHTTPAttackPreservesPrepareMessage(t *testing.T) {
	store := newRegistryTestStore(t)
	server := httptest.NewServer(HTTPHandler(store, nil))
	t.Cleanup(server.Close)
	owner, attacker, sender := newRegistryTestIdentity(t), newRegistryTestIdentity(t), newRegistryTestIdentity(t)
	urn := owner.Ed25519.URN()
	if agentcrypto.URNMatchesPublicKey(urn, attacker.Ed25519.PublicKey) {
		t.Fatal("test identities unexpectedly match")
	}
	if err := postRegistryRecord(t, server, owner, signedRegistryRequest(t, owner, urn)); err != nil {
		t.Fatal(err)
	}
	senderAgent := &agent.Agent{Keys: sender, Session: session.NewManager(nil, sender), MQHTTPClient: mq.NewHTTPClient(server.URL, sender)}
	prepare := func(id string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := senderAgent.PrepareMessage(ctx, urn, "local regression only; never delivered", id); err != nil {
			t.Fatalf("PrepareMessage %s: %v", id, err)
		}
	}
	prepare("before-attack")
	shortenRegistryLease(t, store, urn)
	before := registrySnapshot(t, store, urn)
	if err := postRegistryRecord(t, server, attacker, signedRegistryRequest(t, attacker, urn)); err == nil {
		t.Fatal("attacker's valid signatures overwrote owner's URN")
	}
	if after := registrySnapshot(t, store, urn); !reflect.DeepEqual(before, after) {
		t.Fatal("attack changed record contents or TTL")
	}
	prepare("after-attack")
}

func TestRegistryHistoricalRecordsAreIsolatedAndRecoverable(t *testing.T) {
	store := newRegistryTestStore(t)
	owner, attacker := newRegistryTestIdentity(t), newRegistryTestIdentity(t)
	urn := owner.Ed25519.URN()
	server := httptest.NewServer(HTTPHandler(store, nil))
	t.Cleanup(server.Close)
	for _, kind := range []string{"unsigned", "wrong_owner"} {
		t.Run(kind, func(t *testing.T) {
			if err := registerTestRecord(store, signedRegistryRequest(t, owner, urn)); err != nil {
				t.Fatal(err)
			}
			polluted := signedRegistryRequest(t, attacker, urn)
			if kind == "unsigned" {
				polluted.Ed25519Pubkey, polluted.Signature, polluted.Timestamp = nil, nil, 0
			}
			_, err := store.db.Exec(`UPDATE registry SET peer_id=?, x25519_pubkey=?, ed25519_pubkey=?, signature=?, timestamp=? WHERE urn=?`,
				polluted.PeerID, polluted.X25519Pubkey, polluted.Ed25519Pubkey, polluted.Signature, polluted.Timestamp, urn)
			if err != nil {
				t.Fatal(err)
			}
			before := registrySnapshot(t, store, urn)
			var audit bytes.Buffer
			previousLogOutput := log.Writer()
			log.SetOutput(&audit)
			defer log.SetOutput(previousLogOutput)
			if entry, err := store.ResolveEntry(urn); err != nil || entry != nil {
				t.Fatalf("polluted entry exposed: %+v, %v", entry, err)
			}
			if _, _, _, found := store.Resolve(urn); found {
				t.Fatal("Resolve exposed polluted record")
			}
			if _, _, _, _, _, _, _, _, found := store.ResolveExtended(urn); found {
				t.Fatal("ResolveExtended exposed polluted record")
			}
			if urns, err := store.ListURNs(); err != nil || len(urns) != 0 {
				t.Fatalf("polluted URN listed: %v, %v", urns, err)
			}
			if entries, err := store.ListEntries(); err != nil || len(entries) != 0 {
				t.Fatalf("polluted entry listed: %+v, %v", entries, err)
			}
			var response struct {
				Found bool `json:"found"`
			}
			getRegistryJSON(t, server.URL+"/api/v1/registry/resolve?urn="+url.QueryEscape(urn), http.StatusNotFound, &response)
			if response.Found {
				t.Fatal("HTTP exposed polluted record")
			}
			if !strings.Contains(audit.String(), urn) {
				t.Fatalf("quarantine lacks an identifying audit log: %q", audit.String())
			}
			if after := registrySnapshot(t, store, urn); !reflect.DeepEqual(before, after) {
				t.Fatal("quarantine destroyed or changed historical evidence")
			}
			if err := postRegistryRecord(t, server, owner, signedRegistryRequest(t, owner, urn)); err != nil {
				t.Fatalf("real owner could not recover polluted record: %v", err)
			}
			if entry, err := store.ResolveEntry(urn); err != nil || entry == nil || !bytes.Equal(entry.Ed25519Pubkey, owner.Ed25519.PublicKey) {
				t.Fatalf("owner recovery failed: %+v %v", entry, err)
			}
		})
	}
}

func TestRegistryValidStoredSignatureSurvivesWriteFreshnessWindow(t *testing.T) {
	store := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	req := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	if err := registerTestRecord(store, req); err != nil {
		t.Fatal(err)
	}
	req.Timestamp = time.Now().Add(-10 * time.Minute).Unix()
	signRegistryRecord(owner, &req)
	// Model natural aging without making the test wait ten minutes. The record
	// remains inside its one-hour lease, while a new write would be stale.
	if _, err := store.db.Exec(`UPDATE registry SET signature=?, timestamp=? WHERE urn=?`, req.Signature, req.Timestamp, req.URN); err != nil {
		t.Fatal(err)
	}
	if entry, err := store.ResolveEntry(req.URN); err != nil || entry == nil {
		t.Fatalf("valid leased record aged out early: %+v %v", entry, err)
	}
	if urns, err := store.ListURNs(); err != nil || !reflect.DeepEqual(urns, []string{req.URN}) {
		t.Fatalf("valid aged record omitted: %v %v", urns, err)
	}
	if entries, err := store.ListEntries(); err != nil || len(entries) != 1 {
		t.Fatalf("valid aged record omitted: %+v %v", entries, err)
	}
	before := registrySnapshot(t, store, req.URN)
	if err := registerTestRecord(store, req); err == nil {
		t.Fatal("stale record accepted as a fresh registration")
	}
	if after := registrySnapshot(t, store, req.URN); !reflect.DeepEqual(before, after) {
		t.Fatal("stale registration refreshed the lease")
	}
}
