// Package registry provides URN→PeerID/Addrs resolution with SQLite persistence,
// Ed25519 signature verification, TTL-based expiry, and HTTP REST API.
package registry

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/BillShiyaoZhang/agent-comm/registry"
)

// Entry holds the full registration info for a URN.
type Entry struct {
	URN            string
	PeerID         string
	Addrs          []string // JSON-encoded
	RelayAddrs     []string
	X25519Pubkey   []byte
	Ed25519Pubkey   []byte
	StoresUserData bool
	ExpiresAt      int64 // Unix timestamp
}

// Store is the SQLite-backed registry store.
type Store struct {
	mu  sync.RWMutex
	db  *sql.DB
	ttl time.Duration
}

var _ registry.Store = (*Store)(nil)


const schema = `
CREATE TABLE IF NOT EXISTS registry (
  urn              TEXT PRIMARY KEY,
  peer_id          TEXT NOT NULL,
  addrs            TEXT NOT NULL DEFAULT '[]',
  relay_addrs      TEXT NOT NULL DEFAULT '[]',
  x25519_pubkey    BLOB,
  ed25519_pubkey   BLOB,
  stores_user_data INTEGER NOT NULL DEFAULT 0,
  expires_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_expires ON registry(expires_at);
`

// NewStore opens (or creates) the SQLite registry database.
func NewStore(dbPath string, ttlHours int) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Migration: add stores_user_data column if it doesn't exist
	_, _ = db.Exec("ALTER TABLE registry ADD COLUMN stores_user_data INTEGER NOT NULL DEFAULT 0")

	s := &Store{db: db, ttl: time.Duration(ttlHours) * time.Hour}
	go s.cleanupLoop()
	return s, nil
}

// Register satisfies the registry.Store interface from the core SDK.
func (s *Store) Register(urn, peerID string, addrs []string, x25519PubKey []byte) (bool, string) {
	err := s.RegisterWithSignature(urn, peerID, addrs, nil, x25519PubKey, nil, nil, false, 0)
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

// Resolve satisfies the registry.Store interface from the core SDK.
func (s *Store) Resolve(urn string) (string, []string, []byte, bool) {
	entry, err := s.ResolveEntry(urn)
	if err != nil || entry == nil {
		return "", nil, nil, false
	}
	if _, err := peer.Decode(entry.PeerID); err != nil {
		return "", nil, nil, false
	}
	return entry.PeerID, entry.Addrs, entry.X25519Pubkey, true
}

// RegisterWithSignature upserts a URN entry. If ed25519Pubkey+signature are provided,
// the signature is verified before storing. signature covers: urn||peer_id||stores_user_data||timestamp (big-endian int64).
func (s *Store) RegisterWithSignature(urn, peerID string, addrs, relayAddrs []string,
	x25519PK, ed25519PK, signature []byte, storesUserData bool, timestamp int64) error {

	// Replay-attack guard: reject if timestamp is >5 min old
	now := time.Now().Unix()
	if timestamp != 0 && (now-timestamp > 300 || timestamp-now > 60) {
		return fmt.Errorf("timestamp out of window")
	}

	// Verify signature if pubkey provided
	if len(ed25519PK) == ed25519.PublicKeySize && len(signature) > 0 {
		msg := buildSignedMsg(urn, peerID, storesUserData, timestamp)
		if !ed25519.Verify(ed25519.PublicKey(ed25519PK), msg, signature) {
			return fmt.Errorf("invalid signature")
		}
	}

	addrsJSON := encodeStringSlice(addrs)
	relayJSON := encodeStringSlice(relayAddrs)
	expiresAt := now + int64(s.ttl.Seconds())
	storesUserDataInt := 0
	if storesUserData {
		storesUserDataInt = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO registry (urn, peer_id, addrs, relay_addrs, x25519_pubkey, ed25519_pubkey, stores_user_data, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(urn) DO UPDATE SET
		  peer_id=excluded.peer_id, addrs=excluded.addrs, relay_addrs=excluded.relay_addrs,
		  x25519_pubkey=excluded.x25519_pubkey, ed25519_pubkey=excluded.ed25519_pubkey,
		  stores_user_data=excluded.stores_user_data, expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		urn, peerID, addrsJSON, relayJSON, x25519PK, ed25519PK, storesUserDataInt, expiresAt, now)
	return err
}

// ResolveEntry looks up a URN. Returns nil if not found or expired.
func (s *Store) ResolveEntry(urn string) (*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT urn, peer_id, addrs, relay_addrs, x25519_pubkey, ed25519_pubkey, stores_user_data, expires_at
		FROM registry WHERE urn=? AND expires_at > ?`, urn, time.Now().Unix())

	var e Entry
	var addrsJSON, relayJSON string
	var storesUserDataInt int
	if err := row.Scan(&e.URN, &e.PeerID, &addrsJSON, &relayJSON,
		&e.X25519Pubkey, &e.Ed25519Pubkey, &storesUserDataInt, &e.ExpiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	e.Addrs = decodeStringSlice(addrsJSON)
	e.RelayAddrs = decodeStringSlice(relayJSON)
	e.StoresUserData = (storesUserDataInt != 0)
	return &e, nil
}

// ListURNs returns all non-expired URNs.
func (s *Store) ListURNs() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT urn FROM registry WHERE expires_at > ?", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var urns []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urns = append(urns, u)
		}
	}
	return urns, nil
}

// ListEntries returns all non-expired entries in the registry.
func (s *Store) ListEntries() ([]*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT urn, peer_id, addrs, relay_addrs, x25519_pubkey, ed25519_pubkey, stores_user_data, expires_at FROM registry WHERE expires_at > ?", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []*Entry
	for rows.Next() {
		var e Entry
		var addrsJSON, relayJSON string
		var storesUserDataInt int
		if err := rows.Scan(&e.URN, &e.PeerID, &addrsJSON, &relayJSON, &e.X25519Pubkey, &e.Ed25519Pubkey, &storesUserDataInt, &e.ExpiresAt); err != nil {
			continue
		}
		e.Addrs = decodeStringSlice(addrsJSON)
		e.RelayAddrs = decodeStringSlice(relayJSON)
		e.StoresUserData = (storesUserDataInt != 0)
		entries = append(entries, &e)
	}
	return entries, nil
}

// EvictEntry deletes a URN entry from the database.
func (s *Store) EvictEntry(urn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM registry WHERE urn = ?", urn)
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ClearAllEntries() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM registry")
	return err
}

func (s *Store) cleanupLoop() {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		if _, err := s.db.Exec("DELETE FROM registry WHERE expires_at > 0 AND expires_at < ?", time.Now().Unix()); err != nil {
			log.Printf("[registry] cleanup error: %v", err)
		}
	}
}

// buildSignedMsg constructs the canonical message that must be signed during registration.
func buildSignedMsg(urn, peerID string, storesUserData bool, timestamp int64) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	flag := "0"
	if storesUserData {
		flag = "1"
	}
	msg := []byte(urn + "|" + peerID + "|" + flag + "|")
	return append(msg, ts...)
}

// encodeStringSlice encodes a string slice as a simple hex-delimited string for SQLite storage.
func encodeStringSlice(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ","
		}
		result += hex.EncodeToString([]byte(s))
	}
	return result
}

func decodeStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			if b, err := hex.DecodeString(part); err == nil {
				result = append(result, string(b))
			}
			start = i + 1
		}
	}
	return result
}
