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
	goproto "google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS messages (
  id           TEXT PRIMARY KEY,
  recipient    TEXT NOT NULL,
  payload      BLOB NOT NULL,
  expiry       INTEGER NOT NULL,
  stored_at    INTEGER NOT NULL
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
}

var _ mq.Store = (*Store)(nil)

var ErrQueueFull = errors.New("recipient mailbox is full; retry later")
var ErrSubscriberLimit = errors.New("subscriber limit reached; retry later")
var ErrInvalidMessage = errors.New("invalid message")

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
	// Migration: add read_at column if it doesn't exist
	_, _ = db.Exec("ALTER TABLE messages ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_read_at ON messages(read_at)")

	s := &Store{
		db:                   db,
		done:                 make(chan struct{}),
		defaultTTL:           time.Duration(defaultTTLDays) * 24 * time.Hour,
		maxPerURN:            maxPerURN,
		historyRetentionDays: 30,
		subscribers:          make(map[string][]chan *proto.EncryptedEnvelope),
	}
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
	res, err := tx.ExecContext(ctx,
		"INSERT OR IGNORE INTO messages (id, recipient, payload, expiry, stored_at) VALUES (?, ?, ?, ?, ?)",
		msgID, recipientURN, payload, expiryUnix, time.Now().Unix())
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
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?)`, recipientURN, time.Now().Unix()).Scan(&pending); err != nil {
			return "", fmt.Errorf("quota check: %w", err)
		}
		if pending > s.maxPerURN {
			return "", ErrQueueFull
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.NotifySubscribers(recipientURN, env)
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
func (s *Store) NotifySubscribers(urn string, env *proto.EncryptedEnvelope) {
	s.mu.RLock()
	chans, ok := s.subscribers[urn]
	if !ok || len(chans) == 0 {
		s.mu.RUnlock()
		return
	}
	chansCopy := make([]chan *proto.EncryptedEnvelope, len(chans))
	copy(chansCopy, chans)
	s.mu.RUnlock()

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
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, payload FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) ORDER BY stored_at ASC LIMIT 500",
		recipientURN, time.Now().Unix())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var envs []*proto.EncryptedEnvelope
	var ids []string
	totalBytes := 0
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		if totalBytes+len(data) > maxRetrieveBytes && len(envs) > 0 {
			break
		}
		totalBytes += len(data)
		var env proto.EncryptedEnvelope
		if err := goproto.Unmarshal(data, &env); err != nil {
			continue
		}
		envs = append(envs, &env)
		ids = append(ids, id)
	}
	return envs, ids, rows.Err()
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
	args := make([]interface{}, len(ids)+2)
	args[0], args[1] = time.Now().Unix(), recipientURN
	for i, id := range ids {
		args[i+2] = id
	}
	res, err := s.db.ExecContext(ctx, "UPDATE messages SET read_at=? WHERE recipient=? AND read_at=0 AND id IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
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
		SELECT recipient, COUNT(*), SUM(LENGTH(payload)), MIN(stored_at), MAX(stored_at)
		FROM messages
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
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := tx.QueryContext(ctx, "SELECT id, payload, expiry, stored_at, read_at FROM messages WHERE "+where+" ORDER BY "+order+" LIMIT ? OFFSET ?", pageArgs...)
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
		var expiry, storedAt, readAt int64
		if err := rows.Scan(&id, &payload, &expiry, &storedAt, &readAt); err != nil {
			return nil, 0, err
		}

		if includePayload && legacyBytes+len(payload) > legacyPayloadBudget && len(details) > 0 {
			break
		}
		includeThisPayload := includePayload && legacyBytes+len(payload) <= legacyPayloadBudget
		detail := messageDetailFromStored(id, payload, expiry, storedAt, readAt, includeThisPayload)
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

func messageDetailFromStored(id string, payload []byte, expiry, storedAt, readAt int64, includePayload bool) *MessageDetail {
	detail := &MessageDetail{ID: id, Size: len(payload), StoredAt: storedAt, ReadAt: readAt, Expiry: expiry}
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
	var expiry, storedAt, readAt int64
	err := s.db.QueryRowContext(ctx, "SELECT payload, expiry, stored_at, read_at FROM messages WHERE recipient=? AND id=?", recipientURN, id).Scan(&payload, &expiry, &storedAt, &readAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(payload) > maxEnvelopeBytes {
		return nil, fmt.Errorf("stored message exceeds envelope size limit")
	}
	return messageDetailFromStored(id, payload, expiry, storedAt, readAt, true), nil
}

// DeleteMessage removes exactly one message in the specified recipient mailbox.
// Repeating the operation is safe and reports zero deleted rows.
func (s *Store) DeleteMessage(ctx context.Context, recipientURN, id string) (int, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM messages WHERE recipient=? AND id=?", recipientURN, id)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
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
		COALESCE(SUM(CASE WHEN read_at=0 AND (expiry=0 OR expiry>?) THEN LENGTH(payload) ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at=0 AND (expiry=0 OR expiry>?) THEN recipient END),
		COALESCE(SUM(CASE WHEN read_at>0 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN read_at>0 THEN LENGTH(payload) ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at>0 THEN recipient END),
		COALESCE(SUM(CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN LENGTH(payload) ELSE 0 END),0),
		COUNT(DISTINCT CASE WHEN read_at=0 AND expiry>0 AND expiry<=? THEN recipient END)
		FROM messages`, now, now, now, now, now, now).Scan(
		&summary.Pending.Messages, &summary.Pending.Bytes, &summary.Pending.Queues,
		&summary.History.Messages, &summary.History.Bytes, &summary.History.Queues,
		&summary.Expired.Messages, &summary.Expired.Bytes, &summary.Expired.Queues,
	)
	return &summary, err
}

// PurgeQueue deletes all messages for a recipient.
func (s *Store) PurgeQueue(ctx context.Context, recipient string) (int, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM messages WHERE recipient = ?", recipient)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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
		// 2. Delete historical messages older than retention days
		retentionDays := atomic.LoadInt32(&s.historyRetentionDays)
		if retentionDays >= 0 {
			retentionSeconds := int64(retentionDays) * 24 * 3600
			if _, err := s.db.Exec("DELETE FROM messages WHERE read_at>0 AND read_at<?", now-retentionSeconds); err != nil {
				log.Printf("[mq] history cleanup error: %v", err)
			}
		}
	}
}
