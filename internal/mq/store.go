// Package mq provides the high-availability async message queue (mailbox) for offline agents.
package mq

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	proto "github.com/BillShiyaoZhang/agent-comm/proto"
	"github.com/BillShiyaoZhang/agent-comm/mq"
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
	defaultTTL           time.Duration
	maxPerURN            int
	historyRetentionDays int32

	mu          sync.RWMutex
	subscribers map[string][]chan *proto.EncryptedEnvelope
}

var _ mq.Store = (*Store)(nil)


// NewStore opens (or creates) the MQ database.
func NewStore(dbPath string, defaultTTLDays, maxPerURN int) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open mq db: %w", err)
	}
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
		defaultTTL:           time.Duration(defaultTTLDays) * 24 * time.Hour,
		maxPerURN:            maxPerURN,
		historyRetentionDays: 30,
		subscribers:          make(map[string][]chan *proto.EncryptedEnvelope),
	}
	go s.cleanupLoop()
	return s, nil
}

// StoreEnvelope saves an EncryptedEnvelope for a recipient. Enforces per-URN quota (FIFO eviction).
func (s *Store) StoreEnvelope(ctx context.Context, recipientURN string, env *proto.EncryptedEnvelope, expiryUnix int64) (string, error) {
	msgID := env.GetMessageId()
	if msgID == "" {
		msgID = uuid.New().String()
		env.MessageId = msgID
	} else if env.MessageId == "" {
		env.MessageId = msgID
	}

	if expiryUnix == 0 {
		expiryUnix = time.Now().Add(s.defaultTTL).Unix()
	}

	payload, err := goproto.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	// Enforce per-URN quota: delete oldest if over limit
	if s.maxPerURN > 0 {
		if _, err := s.db.ExecContext(ctx, `
			DELETE FROM messages WHERE id IN (
			  SELECT id FROM messages WHERE recipient=? AND read_at=0 ORDER BY stored_at ASC
			  LIMIT MAX(0, (SELECT COUNT(*) FROM messages WHERE recipient=? AND read_at=0) - ?)
			)`, recipientURN, recipientURN, s.maxPerURN-1); err != nil {
			log.Printf("[mq] quota eviction error: %v", err)
		}
	}

	_, err = s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO messages (id, recipient, payload, expiry, stored_at) VALUES (?, ?, ?, ?, ?)",
		msgID, recipientURN, payload, expiryUnix, time.Now().Unix())
	if err != nil {
		return "", fmt.Errorf("insert message: %w", err)
	}

	s.NotifySubscribers(recipientURN, env)
	return msgID, nil
}

// RegisterSubscriber adds a new subscriber channel for a URN.
func (s *Store) RegisterSubscriber(urn string, ch chan *proto.EncryptedEnvelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribers == nil {
		s.subscribers = make(map[string][]chan *proto.EncryptedEnvelope)
	}
	s.subscribers[urn] = append(s.subscribers[urn], ch)
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

// RetrieveEntry returns all pending envelopes and their database IDs for a recipient (oldest first).
func (s *Store) RetrieveEntry(ctx context.Context, recipientURN string) ([]*proto.EncryptedEnvelope, []string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, payload FROM messages WHERE recipient=? AND read_at=0 AND (expiry=0 OR expiry>?) ORDER BY stored_at ASC",
		recipientURN, time.Now().Unix())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var envs []*proto.EncryptedEnvelope
	var ids []string
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		var env proto.EncryptedEnvelope
		if err := goproto.Unmarshal(data, &env); err != nil {
			continue
		}
		envs = append(envs, &env)
		ids = append(ids, id)
	}
	return envs, ids, nil
}

// Ack updates read_at for the given message IDs, marking them as read history.
func (s *Store) Ack(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := "?" 
	args := make([]interface{}, len(ids)+1)
	args[0] = time.Now().Unix()
	args[1] = ids[0]
	for i := 1; i < len(ids); i++ {
		placeholders += ",?"
		args[i+1] = ids[i]
	}
	res, err := s.db.ExecContext(ctx, "UPDATE messages SET read_at = ? WHERE id IN ("+placeholders+")", args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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
			continue
		}
		stats = append(stats, &qs)
	}
	if stats == nil {
		stats = []*QueueStat{}
	}
	return stats, nil
}

// MessageDetail represents details about a stored envelope.
type MessageDetail struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Size      int    `json:"size"`
	StoredAt  int64  `json:"stored_at"`
	ReadAt    int64  `json:"read_at"`
	Expiry    int64  `json:"expiry"`
	Payload   string `json:"payload"` // hex encoded ciphertext
}

// ListMessagesDetail returns messages for a recipient, filtered by status ('pending' or 'history').
func (s *Store) ListMessagesDetail(ctx context.Context, recipientURN string, status string) ([]*MessageDetail, error) {
	var query string
	if status == "history" {
		query = "SELECT id, payload, expiry, stored_at, read_at FROM messages WHERE recipient=? AND read_at > 0 ORDER BY read_at DESC"
	} else {
		query = "SELECT id, payload, expiry, stored_at, read_at FROM messages WHERE recipient=? AND read_at = 0 AND (expiry = 0 OR expiry > ?) ORDER BY stored_at ASC"
	}

	var rows *sql.Rows
	var err error
	if status == "history" {
		rows, err = s.db.QueryContext(ctx, query, recipientURN)
	} else {
		rows, err = s.db.QueryContext(ctx, query, recipientURN, time.Now().Unix())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var details []*MessageDetail
	for rows.Next() {
		var id string
		var payload []byte
		var expiry, storedAt, readAt int64
		if err := rows.Scan(&id, &payload, &expiry, &storedAt, &readAt); err != nil {
			continue
		}

		var env proto.EncryptedEnvelope
		var sender string
		var payloadHex string
		if err := goproto.Unmarshal(payload, &env); err == nil {
			sender = env.GetSenderUrn()
			payloadHex = hex.EncodeToString(env.GetCiphertext())
		}

		details = append(details, &MessageDetail{
			ID:       id,
			Sender:   sender,
			Size:     len(payload),
			StoredAt: storedAt,
			ReadAt:   readAt,
			Expiry:   expiry,
			Payload:  payloadHex,
		})
	}
	if details == nil {
		details = []*MessageDetail{}
	}
	return details, nil
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
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SetHistoryRetentionDays(days int) {
	atomic.StoreInt32(&s.historyRetentionDays, int32(days))
}

func (s *Store) GetHistoryRetentionDays() int {
	return int(atomic.LoadInt32(&s.historyRetentionDays))
}

func (s *Store) cleanupLoop() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for range tick.C {
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
