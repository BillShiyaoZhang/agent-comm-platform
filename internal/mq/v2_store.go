package mq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

const v2Schema = `
CREATE TABLE IF NOT EXISTS v2_messages (
  id          TEXT PRIMARY KEY,
  recipient   TEXT NOT NULL,
  envelope    BLOB NOT NULL,
  receipt     BLOB NOT NULL,
  policy_hash TEXT NOT NULL,
  expiry      INTEGER NOT NULL,
  stored_at   INTEGER NOT NULL,
  read_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_v2_recipient ON v2_messages(recipient, read_at, stored_at);
CREATE INDEX IF NOT EXISTS idx_v2_expiry ON v2_messages(expiry);
CREATE TABLE IF NOT EXISTS v2_policy_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  epoch INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0,
  require_v2 INTEGER NOT NULL DEFAULT 0,
  issuer_pubkey BLOB
);
CREATE TABLE IF NOT EXISTS v2_handshake_frames (
  id TEXT PRIMARY KEY,
  recipient TEXT NOT NULL,
  frame BLOB NOT NULL,
  expiry INTEGER NOT NULL,
  stored_at INTEGER NOT NULL,
  read_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_v2_handshake_recipient ON v2_handshake_frames(recipient, read_at, stored_at);
CREATE INDEX IF NOT EXISTS idx_v2_handshake_expiry ON v2_handshake_frames(expiry);
CREATE TABLE IF NOT EXISTS v2_managed_identities (
  urn TEXT PRIMARY KEY,
  identity_pubkey BLOB NOT NULL,
  issuer_pubkey BLOB NOT NULL,
  serial TEXT NOT NULL UNIQUE,
  not_before INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  enrolled_at_ns INTEGER NOT NULL,
  certificate BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS v2_managed_revocations (
  serial TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);
CREATE VIEW IF NOT EXISTS all_messages AS
  SELECT id,recipient,payload,LENGTH(payload) AS stored_size,expiry,stored_at,read_at FROM messages
  UNION ALL
  SELECT id,recipient,envelope AS payload,LENGTH(envelope)+LENGTH(receipt) AS stored_size,expiry,stored_at,read_at FROM v2_messages;
`

var ErrV2Policy = errors.New("v2 policy mismatch")
var ErrV2Conflict = errors.New("v2 message ID conflict")

type V2Message struct {
	ID       string
	Envelope []byte
	Receipt  []byte
}

// EnableV2Policy persists the highest signed policy epoch before serving any
// v2 request. A restart cannot silently roll back a policy the platform has
// already admitted. The caller must verify the policy signature first.
func (s *Store) EnableV2Policy(ctx context.Context, epoch uint64, hash string, expiresAt int64, requireV2 bool, managedIssuer []byte) error {
	if epoch == 0 || len(hash) != 64 || expiresAt <= time.Now().Unix() {
		return fmt.Errorf("%w: invalid epoch or hash", ErrV2Policy)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldEpoch uint64
	var oldHash string
	err = tx.QueryRowContext(ctx, "SELECT epoch, policy_hash FROM v2_policy_state WHERE singleton=1").Scan(&oldEpoch, &oldHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (epoch < oldEpoch || epoch == oldEpoch && hash != oldHash) {
		return fmt.Errorf("%w: signed policy epoch rollback or equivocation", ErrV2Policy)
	}
	required := 0
	if requireV2 {
		required = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_policy_state(singleton,epoch,policy_hash,expires_at,require_v2,issuer_pubkey) VALUES(1,?,?,?,?,?)
		ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,policy_hash=excluded.policy_hash,
		expires_at=excluded.expires_at,require_v2=excluded.require_v2,issuer_pubkey=excluded.issuer_pubkey`, epoch, hash, expiresAt, required, managedIssuer); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.v2Required = requireV2
	s.v2PolicyHash = hash
	s.v2PolicyExpiry = expiresAt
	s.v2ManagedIssuer = append([]byte(nil), managedIssuer...)
	return nil
}

// ExistingV2Receipt returns the original receipt only for an identical raw
// envelope and recipient. Callers authenticate the sender first.
func (s *Store) ExistingV2Receipt(ctx context.Context, recipient, id string, envelope []byte) ([]byte, bool, error) {
	var storedRecipient string
	var storedEnvelope, receipt []byte
	err := s.db.QueryRowContext(ctx, "SELECT recipient,envelope,receipt FROM v2_messages WHERE id=?", id).Scan(&storedRecipient, &storedEnvelope, &receipt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if storedRecipient != recipient || !bytes.Equal(storedEnvelope, envelope) {
		return nil, false, ErrV2Conflict
	}
	return receipt, true, nil
}

// StoreV2 atomically publishes an already verified envelope and signed
// admission receipt. The transaction also checks quota and cross-version IDs.
func (s *Store) StoreV2(ctx context.Context, recipient, id, policyHash string, envelope, receipt []byte, expiry int64) ([]byte, error) {
	if id == "" || len(id) > 256 || recipient == "" || len(envelope) == 0 || len(envelope) > maxEnvelopeBytes || len(receipt) == 0 || len(receipt) > 8192 {
		return nil, fmt.Errorf("%w: v2 envelope or receipt exceeds limit", ErrInvalidMessage)
	}
	s.mu.RLock()
	policyMatches := s.v2PolicyHash != "" && s.v2PolicyHash == policyHash
	storeAllowed, forwardAllowed := s.storeAllowed, s.forwardAllowed
	s.mu.RUnlock()
	if !policyMatches {
		return nil, ErrV2Policy
	}
	if storeAllowed != nil && !storeAllowed() {
		return nil, fmt.Errorf("message queue storage is disabled")
	}
	if forwardAllowed != nil && !forwardAllowed(recipient) {
		return nil, fmt.Errorf("recipient blocked by storage policy")
	}
	now := time.Now().Unix()
	if expiry <= now || expiry > time.Now().Add(s.defaultTTL).Unix() {
		return nil, fmt.Errorf("%w: v2 expiry must be within configured TTL", ErrInvalidMessage)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var currentPolicyHash string
	var policyExpiry int64
	if err := tx.QueryRowContext(ctx, "SELECT policy_hash,expires_at FROM v2_policy_state WHERE singleton=1").Scan(&currentPolicyHash, &policyExpiry); err != nil {
		return nil, err
	}
	if currentPolicyHash != policyHash || time.Now().Unix() >= policyExpiry {
		return nil, ErrV2Policy
	}
	var v1Collision int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages WHERE id=?", id).Scan(&v1Collision); err != nil {
		return nil, err
	}
	if v1Collision != 0 {
		return nil, ErrV2Conflict
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO v2_messages(id,recipient,envelope,receipt,policy_hash,expiry,stored_at)
		VALUES(?,?,?,?,?,?,?)`, id, recipient, envelope, receipt, policyHash, expiry, now)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		var existingRecipient string
		var existingEnvelope, existingReceipt []byte
		if err := tx.QueryRowContext(ctx, "SELECT recipient,envelope,receipt FROM v2_messages WHERE id=?", id).Scan(&existingRecipient, &existingEnvelope, &existingReceipt); err != nil {
			return nil, err
		}
		if existingRecipient != recipient || !bytes.Equal(existingEnvelope, envelope) {
			return nil, ErrV2Conflict
		}
		return existingReceipt, nil
	}
	if s.maxPerURN > 0 {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?)) + (SELECT COUNT(*) FROM v2_messages WHERE recipient=? AND read_at=0 AND expiry>?)`, recipient, now, recipient, now).Scan(&pending); err != nil {
			return nil, err
		}
		if pending > s.maxPerURN {
			return nil, ErrQueueFull
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return receipt, nil
}

func (s *Store) RetrieveV2(ctx context.Context, recipient string) ([]V2Message, error) {
	if err := coremq.AuthorizeRecipient(ctx, recipient); err != nil {
		return nil, err
	}
	s.mu.RLock()
	policyHash := s.v2PolicyHash
	s.mu.RUnlock()
	if policyHash == "" {
		return nil, ErrV2Policy
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,envelope,receipt FROM v2_messages
		WHERE recipient=? AND policy_hash=? AND read_at=0 AND expiry>? ORDER BY stored_at,id LIMIT 500`, recipient, policyHash, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []V2Message
	total := 0
	for rows.Next() {
		var msg V2Message
		if err := rows.Scan(&msg.ID, &msg.Envelope, &msg.Receipt); err != nil {
			return nil, err
		}
		if total+len(msg.Envelope)+len(msg.Receipt) > maxRetrieveBytes && len(out) > 0 {
			break
		}
		total += len(msg.Envelope) + len(msg.Receipt)
		out = append(out, msg)
	}
	return out, rows.Err()
}

func (s *Store) AckV2(ctx context.Context, recipient string, ids []string) (int, error) {
	if err := coremq.AuthorizeRecipient(ctx, recipient); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > maxAckIDs {
		return 0, fmt.Errorf("%w: too many ACK IDs", ErrInvalidMessage)
	}
	args := make([]any, len(ids)+2)
	args[0], args[1] = time.Now().Unix(), recipient
	for i, id := range ids {
		args[i+2] = id
	}
	res, err := s.db.ExecContext(ctx, "UPDATE v2_messages SET read_at=? WHERE recipient=? AND read_at=0 AND id IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// StoreV2Frame is a bounded metadata-only delivery channel for the signed
// handshake transcript. A frame retry cannot replace bytes under the same ID.
func (s *Store) StoreV2Frame(ctx context.Context, sender, recipient, id string, frame []byte, expiry int64, policy *v2.Policy, senderPub ed25519.PublicKey) error {
	if err := coremq.AuthorizeRecipient(ctx, sender); err != nil {
		return err
	}
	parsed, err := v2.ParseFrame(frame)
	if err != nil {
		return err
	}
	if parsed.SenderURN != sender || parsed.RecipientURN != recipient || v2.FrameHash(parsed) != id || policy == nil {
		return ErrInvalidMessage
	}
	if !crypto.URNMatchesPublicKey(sender, senderPub) {
		return ErrInvalidMessage
	}
	if err := v2.VerifyFrame(parsed, senderPub); err != nil {
		return err
	}
	if err := v2.ValidateFrameForRelay(policy, parsed, time.Now()); err != nil {
		return err
	}
	switch parsed.Type {
	case v2.FrameInit:
		var payload v2.InitPayload
		if err := json.Unmarshal(parsed.Payload, &payload); err != nil || expiry > payload.Expiry {
			return ErrInvalidMessage
		}
	case v2.FrameAccept:
		var payload v2.AcceptPayload
		if err := json.Unmarshal(parsed.Payload, &payload); err != nil || expiry > payload.Expiry {
			return ErrInvalidMessage
		}
	}
	s.mu.RLock()
	activePolicyHash := s.v2PolicyHash
	s.mu.RUnlock()
	if activePolicyHash == "" || activePolicyHash != v2.PolicyHash(policy) {
		return ErrV2Policy
	}
	if id == "" || len(id) > 256 || len(frame) == 0 || len(frame) > 8192 || expiry <= time.Now().Unix() || expiry > time.Now().Add(24*time.Hour).Unix() {
		return ErrInvalidMessage
	}
	s.mu.RLock()
	storeAllowed, forwardAllowed := s.storeAllowed, s.forwardAllowed
	s.mu.RUnlock()
	if storeAllowed != nil && !storeAllowed() || forwardAllowed != nil && !forwardAllowed(recipient) {
		return ErrV2Policy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentPolicyHash string
	var policyExpiry int64
	if err := tx.QueryRowContext(ctx, "SELECT policy_hash,expires_at FROM v2_policy_state WHERE singleton=1").Scan(&currentPolicyHash, &policyExpiry); err != nil {
		return err
	}
	if currentPolicyHash != v2.PolicyHash(policy) || time.Now().Unix() >= policyExpiry {
		return ErrV2Policy
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO v2_handshake_frames(id,recipient,frame,expiry,stored_at) VALUES(?,?,?,?,?)`, id, recipient, frame, expiry, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var oldRecipient string
		var oldFrame []byte
		if err := tx.QueryRowContext(ctx, "SELECT recipient,frame FROM v2_handshake_frames WHERE id=?", id).Scan(&oldRecipient, &oldFrame); err != nil {
			return err
		}
		if oldRecipient != recipient || !bytes.Equal(oldFrame, frame) {
			return ErrV2Conflict
		}
		return nil
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_handshake_frames WHERE recipient=? AND read_at=0 AND expiry>?`, recipient, time.Now().Unix()).Scan(&pending); err != nil {
		return err
	}
	if pending > 100 {
		return ErrQueueFull
	}
	return tx.Commit()
}

type V2Frame struct {
	ID    string
	Frame []byte
}

func (s *Store) RetrieveV2Frames(ctx context.Context, recipient string) ([]V2Frame, error) {
	if err := coremq.AuthorizeRecipient(ctx, recipient); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,frame FROM v2_handshake_frames WHERE recipient=? AND read_at=0 AND expiry>? ORDER BY stored_at,id LIMIT 100`, recipient, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []V2Frame
	for rows.Next() {
		var f V2Frame
		if err := rows.Scan(&f.ID, &f.Frame); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) AckV2Frames(ctx context.Context, recipient string, ids []string) (int, error) {
	if err := coremq.AuthorizeRecipient(ctx, recipient); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > 100 {
		return 0, ErrInvalidMessage
	}
	args := make([]any, len(ids)+2)
	args[0], args[1] = time.Now().Unix(), recipient
	for i, id := range ids {
		args[i+2] = id
	}
	res, err := s.db.ExecContext(ctx, "UPDATE v2_handshake_frames SET read_at=? WHERE recipient=? AND read_at=0 AND id IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// EnrollManaged verifies issuer signature and proof of console-key possession
// again at the storage boundary. A revoked serial cannot be resurrected.
func (s *Store) EnrollManaged(ctx context.Context, policy *v2.Policy, certificate []byte) error {
	cert, err := v2.ParseManagedCertificate(certificate)
	if err != nil {
		return err
	}
	if err := v2.VerifyManagedCertificate(cert, policy, time.Now()); err != nil {
		return err
	}
	if err := coremq.AuthorizeRecipient(ctx, cert.URN); err != nil {
		return err
	}
	urn, pubkey, issuer := cert.URN, cert.IdentityPublicKey, policy.ManagedIssuerPublicKey
	serial, notBefore, expiresAt := cert.Serial, cert.NotBefore, cert.ExpiresAt
	if len(serial) > 128 || len(certificate) > 8192 {
		return ErrInvalidMessage
	}
	s.mu.RLock()
	issuerMatches := len(s.v2ManagedIssuer) == 32 && bytes.Equal(s.v2ManagedIssuer, issuer)
	s.mu.RUnlock()
	if !issuerMatches {
		return ErrV2Policy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var policyHash string
	var policyExpiry int64
	if err := tx.QueryRowContext(ctx, "SELECT policy_hash,expires_at FROM v2_policy_state WHERE singleton=1").Scan(&policyHash, &policyExpiry); err != nil {
		return err
	}
	if policyHash != v2.PolicyHash(policy) || time.Now().Unix() >= policyExpiry {
		return ErrV2Policy
	}
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM v2_managed_revocations WHERE serial=?", serial).Scan(&revoked); err != nil {
		return err
	}
	if revoked != 0 {
		return ErrV2Policy
	}
	var oldPubkey, oldIssuer []byte
	var oldExpiry, oldEnrolledNS int64
	var oldRevoked int
	err = tx.QueryRowContext(ctx, "SELECT identity_pubkey,issuer_pubkey,expires_at,enrolled_at_ns,revoked FROM v2_managed_identities WHERE urn=?", urn).Scan(&oldPubkey, &oldIssuer, &oldExpiry, &oldEnrolledNS, &oldRevoked)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && !bytes.Equal(oldPubkey, pubkey) {
		return ErrV2Conflict
	}
	enrolledAtNS := time.Now().UnixNano()
	if err == nil && oldRevoked == 0 && oldExpiry > time.Now().Unix() && bytes.Equal(oldIssuer, issuer) && oldEnrolledNS > 0 {
		enrolledAtNS = oldEnrolledNS
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v2_managed_identities(urn,identity_pubkey,issuer_pubkey,serial,not_before,expires_at,enrolled_at_ns,certificate,revoked)
		VALUES(?,?,?,?,?,?,?,?,0) ON CONFLICT(urn) DO UPDATE SET issuer_pubkey=excluded.issuer_pubkey,serial=excluded.serial,
		not_before=excluded.not_before,expires_at=excluded.expires_at,enrolled_at_ns=excluded.enrolled_at_ns,certificate=excluded.certificate,revoked=0`,
		urn, pubkey, issuer, serial, notBefore, expiresAt, enrolledAtNS, certificate); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeManaged(ctx context.Context, serial string) error {
	if serial == "" || len(serial) > 128 {
		return ErrInvalidMessage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO v2_managed_revocations(serial,revoked_at) VALUES(?,?)", serial, time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v2_managed_identities SET revoked=1 WHERE serial=?", serial); err != nil {
		return err
	}
	return tx.Commit()
}

// IsManagedAt checks both current validity and validity when a v1 message was
// originally stored. This prevents retroactive certification of old v1 rows.
func (s *Store) IsManagedAt(ctx context.Context, urn string, pubkey []byte, storedAtNS int64) (bool, error) {
	s.mu.RLock()
	issuer := append([]byte(nil), s.v2ManagedIssuer...)
	policyExpiry := s.v2PolicyExpiry
	s.mu.RUnlock()
	return s.isManagedAtIssuer(ctx, issuer, policyExpiry, urn, pubkey, storedAtNS)
}

// isManagedAtIssuer is also used while callers hold s.mu.RLock across a
// complete read/notification so policy switches cannot interleave delivery.
func (s *Store) isManagedAtIssuer(ctx context.Context, issuer []byte, policyExpiry int64, urn string, pubkey []byte, storedAtNS int64) (bool, error) {
	if len(issuer) != 32 || time.Now().Unix() >= policyExpiry {
		return false, nil
	}
	var identityPubkey []byte
	var notBefore, expiresAt, enrolledAtNS int64
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT identity_pubkey,not_before,expires_at,enrolled_at_ns,revoked FROM v2_managed_identities
		WHERE urn=? AND issuer_pubkey=?`, urn, issuer).Scan(&identityPubkey, &notBefore, &expiresAt, &enrolledAtNS, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	if revoked != 0 || storedAtNS == 0 || storedAtNS < notBefore*1e9 || storedAtNS < enrolledAtNS || storedAtNS >= expiresAt*1e9 || now >= expiresAt || pubkey != nil && !bytes.Equal(pubkey, identityPubkey) {
		return false, nil
	}
	return true, nil
}
