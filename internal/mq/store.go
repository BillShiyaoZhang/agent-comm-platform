// Package mq provides the high-availability async message queue (mailbox) for offline agents.
package mq

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	"github.com/BillShiyaoZhang/agent-comm/mq"
	proto "github.com/BillShiyaoZhang/agent-comm/proto"
	"github.com/BillShiyaoZhang/agent-comm/v2"
	goproto "google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS messages (
  id           TEXT PRIMARY KEY,
  recipient    TEXT NOT NULL,
  payload      BLOB NOT NULL,
  expiry       INTEGER NOT NULL,
  stored_at    INTEGER NOT NULL,
  stored_at_ns INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient);
CREATE INDEX IF NOT EXISTS idx_expiry    ON messages(expiry);
`

// Store is the SQLite-backed MQ store.
type Store struct {
	db                   *sql.DB
	done                 chan struct{}
	closeOnce            sync.Once
	defaultTTL           time.Duration
	maxPerURN            int
	historyRetentionDays int32

	mu              sync.RWMutex
	subscribers     map[string][]chan *proto.EncryptedEnvelope
	storeAllowed    func() bool
	forwardAllowed  func(string) bool
	subscriberCount int
	v2Required      bool
	v2PolicyHash    string
	v2PolicyExpiry  int64
	v2ManagedIssuer []byte
}

var _ mq.Store = (*Store)(nil)

var ErrQueueFull = errors.New("recipient mailbox is full; retry later")
var ErrSubscriberLimit = errors.New("subscriber limit reached; retry later")
var ErrInvalidMessage = errors.New("invalid message")

// The legacy libp2p MQ response has only a free-form error string. Keep a
// stable prefix for older clients that surface it, while HTTP uses typed JSON.
var ErrV1Policy = errors.New("upgrade_required: v1 delivery prohibited by signed v2 policy; see platform HTTPS /api/v2/policy")

const (
	maxEnvelopeBytes     = 1 << 20
	maxRetrieveBytes     = 4 << 20
	maxSubscribersPerURN = 4
	maxSubscribers       = 1024
	maxAckIDs            = 1000
)

// NewStore opens (or creates) the MQ database.
func NewStore(dbPath string, defaultTTLDays, maxPerURN int) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open mq db: %w", err)
	}
	db.SetMaxOpenConns(1)
	// Enable WAL journal mode and busy timeout to avoid database locks (SQLITE_BUSY) under concurrent loads
	_, _ = db.Exec("PRAGMA journal_mode=WAL;")
	_, _ = db.Exec("PRAGMA busy_timeout=5000;")

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create mq schema: %w", err)
	}
	// Existing v1 databases may lack these fields; the all_messages view below
	// is created only after they are present.
	_, _ = db.Exec("ALTER TABLE messages ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE messages ADD COLUMN stored_at_ns INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_read_at ON messages(read_at)")
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_v1_retrieve_cursor ON messages(recipient,read_at,stored_at,id)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create mq retrieval index: %w", err)
	}
	if _, err := db.Exec(v2Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create v2 mq schema: %w", err)
	}
	// Safe for databases from early v2 development; duplicate-column errors
	// mean the schema already has these fields.
	_, _ = db.Exec("ALTER TABLE v2_policy_state ADD COLUMN require_v2 INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE v2_policy_state ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE v2_policy_state ADD COLUMN issuer_pubkey BLOB")
	_, _ = db.Exec("ALTER TABLE v2_managed_identities ADD COLUMN enrolled_at_ns INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("UPDATE v2_managed_identities SET enrolled_at_ns=? WHERE enrolled_at_ns=0", time.Now().UnixNano())
	s := &Store{
		db:                   db,
		done:                 make(chan struct{}),
		defaultTTL:           time.Duration(defaultTTLDays) * 24 * time.Hour,
		maxPerURN:            maxPerURN,
		historyRetentionDays: 30,
		subscribers:          make(map[string][]chan *proto.EncryptedEnvelope),
	}
	// A previously pinned no-v1 policy remains fail-closed even if an operator
	// accidentally disables v2 configuration on the next process start. Only
	// EnableV2Policy with a valid signed policy reopens managed exceptions.
	var priorRequired int
	err = db.QueryRow("SELECT require_v2 FROM v2_policy_state WHERE singleton=1").Scan(&priorRequired)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		db.Close()
		return nil, fmt.Errorf("load pinned v2 policy state: %w", err)
	}
	s.v2Required = priorRequired != 0
	go s.cleanupLoop()
	return s, nil
}

// StoreEnvelope saves an EncryptedEnvelope for a recipient. Full queues reject
// new messages so their senders can retain them in durable outboxes for retry.
func (s *Store) StoreEnvelope(ctx context.Context, recipientURN string, env *proto.EncryptedEnvelope, expiryUnix int64) (string, error) {
	if env == nil || len(env.MessageId) > 256 || goproto.Size(env) > maxEnvelopeBytes {
		return "", fmt.Errorf("%w: envelope exceeds size limit", ErrInvalidMessage)
	}
	s.mu.RLock()
	v2Required := s.v2Required
	s.mu.RUnlock()
	if v2Required {
		managedSender, err := s.IsManagedAt(ctx, env.SenderUrn, env.SenderEd25519Pubkey, time.Now().UnixNano())
		if err != nil {
			return "", err
		}
		managedRecipient, err := s.IsManagedAt(ctx, recipientURN, nil, time.Now().UnixNano())
		if err != nil {
			return "", err
		}
		if !managedSender && !managedRecipient {
			return "", ErrV1Policy
		}
	}
	s.mu.RLock()
	storeAllowed, forwardAllowed := s.storeAllowed, s.forwardAllowed
	s.mu.RUnlock()
	if storeAllowed != nil && !storeAllowed() {
		return "", fmt.Errorf("message queue storage is disabled")
	}
	if forwardAllowed != nil && !forwardAllowed(recipientURN) {
		return "", fmt.Errorf("recipient blocked by storage policy")
	}
	if err := crypto.VerifyEnvelope(env, recipientURN); err != nil {
		return "", err
	}
	if err := mq.AuthorizeRecipient(ctx, env.SenderUrn); err != nil {
		return "", err
	}
	msgID := env.MessageId
	now := time.Now()
	maxExpiry := now.Add(s.defaultTTL).Unix()
	if expiryUnix < 0 || (expiryUnix != 0 && expiryUnix <= now.Unix()) {
		return "", fmt.Errorf("%w: expiry must be in the future", ErrInvalidMessage)
	}
	if expiryUnix == 0 || expiryUnix > maxExpiry {
		expiryUnix = maxExpiry
	}
	storedAt := time.Now()
	payload, err := goproto.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	// Insert, duplicate detection, and quota checks are one atomic operation.
	// A retry must not consume another slot or notify subscribers twice.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Recheck the active policy in the same SQLite transaction as insertion.
	// A policy switch cannot race a v1 insert after the initial fast check.
	var required int
	var issuer []byte
	var policyExpiry int64
	policyErr := tx.QueryRowContext(ctx, "SELECT require_v2,issuer_pubkey,expires_at FROM v2_policy_state WHERE singleton=1").Scan(&required, &issuer, &policyExpiry)
	if policyErr != nil && !errors.Is(policyErr, sql.ErrNoRows) {
		return "", policyErr
	}
	if policyErr == nil && time.Now().Unix() >= policyExpiry {
		return "", ErrV1Policy
	}
	if required != 0 {
		var managed int
		nowUnix := time.Now().Unix()
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v2_managed_identities WHERE issuer_pubkey=? AND revoked=0
			AND not_before<=? AND enrolled_at_ns<=? AND expires_at>?
			AND ((urn=? AND identity_pubkey=?) OR urn=?)`, issuer, nowUnix, time.Now().UnixNano(), nowUnix,
			env.SenderUrn, env.SenderEd25519Pubkey, recipientURN).Scan(&managed)
		if err != nil {
			return "", err
		}
		if managed == 0 {
			return "", ErrV1Policy
		}
	}
	var v2Collision int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM v2_messages WHERE id=?", msgID).Scan(&v2Collision); err != nil {
		return "", err
	}
	if v2Collision != 0 {
		return "", fmt.Errorf("message ID conflict")
	}
	res, err := tx.ExecContext(ctx,
		"INSERT OR IGNORE INTO messages (id, recipient, payload, expiry, stored_at, stored_at_ns) VALUES (?, ?, ?, ?, ?, ?)",
		msgID, recipientURN, payload, expiryUnix, storedAt.Unix(), storedAt.UnixNano())
	if err != nil {
		return "", fmt.Errorf("insert message: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if inserted == 0 {
		var existingRecipient string
		var existingPayload []byte
		if err := tx.QueryRowContext(ctx, "SELECT recipient, payload FROM messages WHERE id=?", msgID).Scan(&existingRecipient, &existingPayload); err != nil {
			return "", err
		}
		if existingRecipient != recipientURN || !bytes.Equal(existingPayload, payload) {
			return "", fmt.Errorf("message ID conflict")
		}
		return msgID, nil
	}
	if s.maxPerURN > 0 {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?)) + (SELECT COUNT(*) FROM v2_messages WHERE recipient=? AND read_at=0 AND expiry>?)`, recipientURN, time.Now().Unix(), recipientURN, time.Now().Unix()).Scan(&pending); err != nil {
			return "", fmt.Errorf("quota check: %w", err)
		}
		if pending > s.maxPerURN {
			return "", ErrQueueFull
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.NotifySubscribers(recipientURN, env, storedAt.UnixNano())
	return msgID, nil
}

// SetStoragePolicy applies the same dynamic platform policy to HTTP and libp2p.
func (s *Store) SetStoragePolicy(storeAllowed func() bool, forwardAllowed func(string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeAllowed, s.forwardAllowed = storeAllowed, forwardAllowed
}

// RegisterSubscriber adds a new subscriber channel for a URN.
func (s *Store) RegisterSubscriber(ctx context.Context, urn string, ch chan *proto.EncryptedEnvelope) error {
	if err := mq.AuthorizeRecipient(ctx, urn); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = make(map[string][]chan *proto.EncryptedEnvelope)
	}
	if len(s.subscribers[urn]) >= maxSubscribersPerURN || s.subscriberCount >= maxSubscribers {
		return ErrSubscriberLimit
	}
	s.subscribers[urn] = append(s.subscribers[urn], ch)
	s.subscriberCount++
	return nil
}

// UnregisterSubscriber removes a subscriber channel for a URN.
func (s *Store) UnregisterSubscriber(urn string, ch chan *proto.EncryptedEnvelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chans, ok := s.subscribers[urn]
	if !ok {
		return
	}
	for i, c := range chans {
		if c == ch {
			s.subscribers[urn] = append(chans[:i], chans[i+1:]...)
			s.subscriberCount--
			break
		}
	}
	if len(s.subscribers[urn]) == 0 {
		delete(s.subscribers, urn)
	}
}

// NotifySubscribers sends an envelope to all subscribers of a URN.
func (s *Store) NotifySubscribers(urn string, env *proto.EncryptedEnvelope, storedAtNS int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	required := s.v2Required
	if required {
		managedSender, senderErr := s.isManagedAtIssuer(context.Background(), s.v2ManagedIssuer, s.v2PolicyExpiry, env.SenderUrn, env.SenderEd25519Pubkey, storedAtNS)
		managedRecipient, recipientErr := s.isManagedAtIssuer(context.Background(), s.v2ManagedIssuer, s.v2PolicyExpiry, urn, nil, storedAtNS)
		if senderErr != nil || recipientErr != nil || !managedSender && !managedRecipient {
			return
		}
	}
	chans, ok := s.subscribers[urn]
	if !ok || len(chans) == 0 {
		return
	}
	chansCopy := make([]chan *proto.EncryptedEnvelope, len(chans))
	copy(chansCopy, chans)

	for _, ch := range chansCopy {
		select {
		case ch <- env:
		default:
			// Non-blocking write to avoid blocking on slow readers
		}
	}
}

// Retrieve satisfies the mq.Store interface from the core SDK.
func (s *Store) Retrieve(ctx context.Context, recipientURN string) ([]*proto.EncryptedEnvelope, error) {
	envs, _, err := s.RetrieveEntry(ctx, recipientURN)
	return envs, err
}

// RetrieveEntry returns a bounded batch of pending envelopes and their IDs
// (oldest first). ACK this batch before retrieving the next one.
func (s *Store) RetrieveEntry(ctx context.Context, recipientURN string) ([]*proto.EncryptedEnvelope, []string, error) {
	if err := mq.AuthorizeRecipient(ctx, recipientURN); err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v2Required := s.v2Required
	grantCache := make(map[string]managedGrant)
	managedAt := func(urn string, pubkey []byte, storedAtNS int64) (bool, error) {
		now := time.Now().Unix()
		if len(s.v2ManagedIssuer) != 32 || now >= s.v2PolicyExpiry {
			return false, nil
		}
		grant, ok := grantCache[urn]
		if !ok {
			var err error
			grant, err = s.loadManagedGrant(ctx, s.v2ManagedIssuer, urn)
			if err != nil {
				return false, err
			}
			if len(grantCache) < 1024 {
				grantCache[urn] = grant
			}
		}
		return grant.permits(pubkey, storedAtNS, s.v2PolicyExpiry, now), nil
	}
	type pendingV1 struct {
		id         string
		data       []byte
		storedAt   int64
		storedAtNS int64
	}
	var envs []*proto.EncryptedEnvelope
	var ids []string
	totalBytes := 0
	// Filter each small SQL page before applying the 500-message/4 MiB
	// delivery limits. Hidden old v1 rows must not mask later managed traffic.
	scanPageSize := 16
	if !v2Required {
		scanPageSize = 500 // Preserve the legacy one-query retrieval path.
	}
	cursorTime, cursorID := int64(-1<<63), ""
	for len(envs) < 500 {
		rows, err := s.db.QueryContext(ctx,
			"SELECT id,payload,stored_at,stored_at_ns FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) AND (stored_at>? OR (stored_at=? AND id>?)) ORDER BY stored_at,id LIMIT ?",
			recipientURN, time.Now().Unix(), cursorTime, cursorTime, cursorID, scanPageSize)
		if err != nil {
			return nil, nil, err
		}
		var pending []pendingV1
		for rows.Next() {
			var item pendingV1
			if err := rows.Scan(&item.id, &item.data, &item.storedAt, &item.storedAtNS); err != nil {
				rows.Close()
				return nil, nil, err
			}
			pending = append(pending, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
		if len(pending) == 0 {
			break
		}
		for _, item := range pending {
			cursorTime, cursorID = item.storedAt, item.id
			var env proto.EncryptedEnvelope
			if err := goproto.Unmarshal(item.data, &env); err != nil {
				continue
			}
			if v2Required {
				managedRecipient, err := managedAt(recipientURN, nil, item.storedAtNS)
				if err != nil {
					return nil, nil, err
				}
				if !managedRecipient {
					managedSender, err := managedAt(env.SenderUrn, env.SenderEd25519Pubkey, item.storedAtNS)
					if err != nil {
						return nil, nil, err
					}
					if !managedSender {
						continue
					}
				}
			}
			if totalBytes+len(item.data) > maxRetrieveBytes && len(envs) > 0 {
				return envs, ids, nil
			}
			totalBytes += len(item.data)
			envs = append(envs, &env)
			ids = append(ids, item.id)
			if len(envs) == 500 {
				return envs, ids, nil
			}
		}
		if len(pending) < scanPageSize {
			break
		}
	}
	return envs, ids, nil
}

// Ack updates read_at for the given message IDs, marking them as read history.
func (s *Store) Ack(ctx context.Context, recipientURN string, ids []string) (int, error) {
	if err := mq.AuthorizeRecipient(ctx, recipientURN); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > maxAckIDs {
		return 0, fmt.Errorf("%w: too many ACK IDs", ErrInvalidMessage)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.v2Required {
		// A signed recipient may ACK only v1 rows that the current policy
		// would deliver. Without this filter, an old Agent or a revoked Web
		// console can silently consume messages hidden by the v2 boundary.
		type pendingAck struct {
			id         string
			payload    []byte
			storedAtNS int64
		}
		type ackIdentity struct {
			id         string
			storedAtNS int64
		}
		const ackBatchSize = 16 // Keep payload memory bounded even for 1,000 large IDs.
		allowed := make([]ackIdentity, 0, len(ids))
		for start := 0; start < len(ids); start += ackBatchSize {
			end := start + ackBatchSize
			if end > len(ids) {
				end = len(ids)
			}
			batch := ids[start:end]
			args := make([]interface{}, len(batch)+2)
			args[0], args[1] = recipientURN, time.Now().Unix()
			for i, id := range batch {
				args[i+2] = id
			}
			rows, err := s.db.QueryContext(ctx, "SELECT id,payload,stored_at_ns FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) AND id IN (?"+strings.Repeat(",?", len(batch)-1)+")", args...)
			if err != nil {
				return 0, err
			}
			var pending []pendingAck
			for rows.Next() {
				var item pendingAck
				if err := rows.Scan(&item.id, &item.payload, &item.storedAtNS); err != nil {
					rows.Close()
					return 0, err
				}
				pending = append(pending, item)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return 0, err
			}
			if err := rows.Close(); err != nil {
				return 0, err
			}
			for _, item := range pending {
				var env proto.EncryptedEnvelope
				if err := goproto.Unmarshal(item.payload, &env); err != nil {
					continue
				}
				managedRecipient, err := s.isManagedAtIssuer(ctx, s.v2ManagedIssuer, s.v2PolicyExpiry, recipientURN, nil, item.storedAtNS)
				if err != nil {
					return 0, err
				}
				managedSender := false
				if !managedRecipient {
					managedSender, err = s.isManagedAtIssuer(ctx, s.v2ManagedIssuer, s.v2PolicyExpiry, env.SenderUrn, env.SenderEd25519Pubkey, item.storedAtNS)
					if err != nil {
						return 0, err
					}
				}
				if managedRecipient || managedSender {
					allowed = append(allowed, ackIdentity{item.id, item.storedAtNS})
				}
			}
		}
		if len(allowed) == 0 {
			return 0, nil
		}
		// Match the exact rows inspected above. An admin may delete a row
		// while ACK runs, and a new store may reuse its message ID.
		updateArgs := make([]interface{}, 0, len(allowed)*2+3)
		updateArgs = append(updateArgs, time.Now().Unix(), recipientURN, time.Now().Unix())
		for _, item := range allowed {
			updateArgs = append(updateArgs, item.id, item.storedAtNS)
		}
		pairs := strings.TrimSuffix(strings.Repeat("(?,?),", len(allowed)), ",")
		res, err := s.db.ExecContext(ctx, "UPDATE messages SET read_at=? WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) AND (id,stored_at_ns) IN ("+pairs+")", updateArgs...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}
	args := make([]interface{}, len(ids)+3)
	args[0], args[1], args[2] = time.Now().Unix(), recipientURN, time.Now().Unix()
	for i, id := range ids {
		args[i+3] = id
	}
	res, err := s.db.ExecContext(ctx, "UPDATE messages SET read_at=? WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) AND id IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// QueueStat represents statistics about a recipient's message queue.
type QueueStat struct {
	Recipient string `json:"recipient"`
	Count     int    `json:"count"`
	TotalSize int64  `json:"total_size"`
	OldestAt  int64  `json:"oldest_at"`
	NewestAt  int64  `json:"newest_at"`
}

// ListQueueStats returns statistics about active unread message queues in the system.
func (s *Store) ListQueueStats(ctx context.Context) ([]*QueueStat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT recipient, COUNT(*), SUM(stored_size), MIN(stored_at), MAX(stored_at)
		FROM all_messages
		WHERE read_at = 0 AND (expiry = 0 OR expiry > ?)
		GROUP BY recipient
		ORDER BY COUNT(*) DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []*QueueStat
	for rows.Next() {
		var qs QueueStat
		if err := rows.Scan(&qs.Recipient, &qs.Count, &qs.TotalSize, &qs.OldestAt, &qs.NewestAt); err != nil {
			return nil, fmt.Errorf("scan MQ queue statistics: %w", err)
		}
		stats = append(stats, &qs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate MQ queue statistics: %w", err)
	}
	if stats == nil {
		stats = []*QueueStat{}
	}
	return stats, nil
}

// MessageDetail represents details about a stored envelope.
type MessageDetail struct {
	ID               string `json:"id"`
	Sender           string `json:"sender"`
	Size             int    `json:"size"`
	StoredAt         int64  `json:"stored_at"`
	ReadAt           int64  `json:"read_at"`
	Expiry           int64  `json:"expiry"`
	Payload          string `json:"payload,omitempty"` // hex encoded ciphertext, on explicit detail request
	PayloadTruncated bool   `json:"payload_truncated,omitempty"`
}

// ListMessagesDetail is the legacy detail view, bounded by both row count
// and 2 MiB of stored envelope bytes included in its response.
func (s *Store) ListMessagesDetail(ctx context.Context, recipientURN string, status string) ([]*MessageDetail, error) {
	details, _, err := s.listMessagesPage(ctx, recipientURN, status, 100, 0, true)
	return details, err
}

// ListMessagesPage returns a stable page and count from one SQLite snapshot.
// It includes metadata only; fetch a single message for its ciphertext.
func (s *Store) ListMessagesPage(ctx context.Context, recipientURN, status string, limit, offset int) ([]*MessageDetail, int, error) {
	return s.listMessagesPage(ctx, recipientURN, status, limit, offset, false)
}

func (s *Store) listMessagesPage(ctx context.Context, recipientURN, status string, limit, offset int, includePayload bool) ([]*MessageDetail, int, error) {
	if status != "pending" && status != "history" {
		return nil, 0, fmt.Errorf("invalid message status")
	}
	if limit < 1 || limit > 200 || offset < 0 {
		return nil, 0, fmt.Errorf("invalid message page")
	}
	now := time.Now().Unix()
	where := "recipient=? AND read_at=0 AND (expiry=0 OR expiry>?)"
	order := "stored_at ASC, id ASC"
	args := []any{recipientURN, now}
	if status == "history" {
		where = "recipient=? AND read_at>0"
		order = "read_at DESC, id DESC"
		args = []any{recipientURN}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM all_messages WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := tx.QueryContext(ctx, "SELECT id, payload, stored_size, expiry, stored_at, read_at FROM all_messages WHERE "+where+" ORDER BY "+order+" LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var details []*MessageDetail
	const legacyPayloadBudget = 2 << 20
	legacyBytes := 0
	for rows.Next() {
		var id string
		var payload []byte
		var storedSize int
		var expiry, storedAt, readAt int64
		if err := rows.Scan(&id, &payload, &storedSize, &expiry, &storedAt, &readAt); err != nil {
			return nil, 0, err
		}

		if includePayload && legacyBytes+len(payload) > legacyPayloadBudget && len(details) > 0 {
			break
		}
		includeThisPayload := includePayload && legacyBytes+len(payload) <= legacyPayloadBudget
		detail := messageDetailFromStored(id, payload, storedSize, expiry, storedAt, readAt, includeThisPayload)
		if includePayload && !includeThisPayload {
			detail.PayloadTruncated = true
		}
		details = append(details, detail)
		if includePayload {
			legacyBytes += len(payload)
		}
	}
	if details == nil {
		details = []*MessageDetail{}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return details, total, nil
}

func messageDetailFromStored(id string, payload []byte, storedSize int, expiry, storedAt, readAt int64, includePayload bool) *MessageDetail {
	detail := &MessageDetail{ID: id, Size: storedSize, StoredAt: storedAt, ReadAt: readAt, Expiry: expiry}
	if len(payload) > 0 && payload[0] == '{' {
		if v2env, err := v2.ParseEnvelope(payload); err == nil {
			detail.Sender = v2env.Header.SenderURN
			if includePayload {
				detail.Payload = hex.EncodeToString(v2env.Ciphertext)
			}
		}
		return detail
	}
	var env proto.EncryptedEnvelope
	if err := goproto.Unmarshal(payload, &env); err == nil {
		detail.Sender = env.GetSenderUrn()
		if includePayload {
			detail.Payload = hex.EncodeToString(env.GetCiphertext())
		}
	}
	return detail
}

// GetMessageDetail returns one message, scoped to its recipient mailbox.
// The stored envelope size is capped by StoreEnvelope at 1 MiB; a corrupt
// oversized row is refused rather than expanding an unbounded HTTP response.
func (s *Store) GetMessageDetail(ctx context.Context, recipientURN, id string) (*MessageDetail, error) {
	var payload []byte
	var storedSize int
	var expiry, storedAt, readAt int64
	err := s.db.QueryRowContext(ctx, "SELECT payload, stored_size, expiry, stored_at, read_at FROM all_messages WHERE recipient=? AND id=?", recipientURN, id).Scan(&payload, &storedSize, &expiry, &storedAt, &readAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(payload) > maxEnvelopeBytes {
		return nil, fmt.Errorf("stored message exceeds envelope size limit")
	}
	return messageDetailFromStored(id, payload, storedSize, expiry, storedAt, readAt, true), nil
}

// DeleteMessage removes exactly one message in the specified recipient mailbox.
// Repeating the operation is safe and reports zero deleted rows.
func (s *Store) DeleteMessage(ctx context.Context, recipientURN, id string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	deleted := int64(0)
	for _, table := range []string{"messages", "v2_messages"} {
		res, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE recipient=? AND id=?", recipientURN, id)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(deleted), nil
}

type SummaryBucket struct {
	Messages int   `json:"messages"`
	Bytes    int64 `json:"bytes"`
	Queues   int   `json:"queues"`
}

type QueueSummary struct {
	Pending SummaryBucket `json:"pending"`
	History SummaryBucket `json:"history"`
	Expired SummaryBucket `json:"expired"`
}

// SummarizeMessages divides stored rows into three disjoint operational states.
// Expired means unread and expired; read rows remain history until cleanup.
func (s *Store) SummarizeMessages(ctx context.Context) (*QueueSummary, error) {
	now := time.Now().Unix()
	var summary QueueSummary
	err := s.db.QueryRowContext(ctx, `
		SELECT
		COALESCE(SUM(CASE WHEN read_at=0 AND (expiry=0 OR expiry>?) THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN read_at=0 AND (expiry=0 OR expiry>?) THEN stored_size ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at=0 AND (expiry=0 OR expiry>?) THEN recipient END),
		COALESCE(SUM(CASE WHEN read_at>0 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN read_at>0 THEN stored_size ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at>0 THEN recipient END),
		COALESCE(SUM(CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN stored_size ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN recipient END)
		FROM all_messages`, now, now, now, now, now, now).Scan(
		&summary.Pending.Messages, &summary.Pending.Bytes, &summary.Pending.Queues,
		&summary.History.Messages, &summary.History.Bytes, &summary.History.Queues,
		&summary.Expired.Messages, &summary.Expired.Bytes, &summary.Expired.Queues,
	)
	return &summary, err
}

// PurgeQueue deletes all messages for a recipient.
func (s *Store) PurgeQueue(ctx context.Context, recipient string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	deleted := int64(0)
	for _, table := range []string{"messages", "v2_messages", "v2_handshake_frames"} {
		res, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE recipient=?", recipient)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// Close closes the database.
func (s *Store) Close() error { s.closeOnce.Do(func() { close(s.done) }); return s.db.Close() }

func (s *Store) SetHistoryRetentionDays(days int) {
	atomic.StoreInt32(&s.historyRetentionDays, int32(days))
}

func (s *Store) GetHistoryRetentionDays() int {
	return int(atomic.LoadInt32(&s.historyRetentionDays))
}

func (s *Store) cleanupLoop() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
		}
		now := time.Now().Unix()
		// 1. Delete expired messages
		if _, err := s.db.Exec("DELETE FROM messages WHERE expiry>0 AND expiry<?", now); err != nil {
			log.Printf("[mq] cleanup error: %v", err)
		}
		if _, err := s.db.Exec("DELETE FROM v2_messages WHERE expiry<?", now); err != nil {
			log.Printf("[mq] v2 cleanup error: %v", err)
		}
		if _, err := s.db.Exec("DELETE FROM v2_handshake_frames WHERE expiry<?", now); err != nil {
			log.Printf("[mq] v2 handshake cleanup error: %v", err)
		}
		// 2. Delete historical messages older than retention days
		retentionDays := atomic.LoadInt32(&s.historyRetentionDays)
		if retentionDays >= 0 {
			retentionSeconds := int64(retentionDays) * 24 * 3600
			if _, err := s.db.Exec("DELETE FROM messages WHERE read_at>0 AND read_at<?", now-retentionSeconds); err != nil {
				log.Printf("[mq] history cleanup error: %v", err)
			}
			if _, err := s.db.Exec("DELETE FROM v2_messages WHERE read_at>0 AND read_at<?", now-retentionSeconds); err != nil {
				log.Printf("[mq] v2 history cleanup error: %v", err)
			}
			if _, err := s.db.Exec("DELETE FROM v2_handshake_frames WHERE read_at>0 AND read_at<?", now-retentionSeconds); err != nil {
				log.Printf("[mq] v2 handshake history cleanup error: %v", err)
			}
		}
	}
}
