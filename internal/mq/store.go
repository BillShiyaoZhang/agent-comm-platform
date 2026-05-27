// Package mq provides the high-availability async message queue (mailbox) for offline agents.
package mq

import (
	"context"
	"database/sql"
	"fmt"
	"log"
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
	db            *sql.DB
	defaultTTL    time.Duration
	maxPerURN     int
}

var _ mq.Store = (*Store)(nil)


// NewStore opens (or creates) the MQ database.
func NewStore(dbPath string, defaultTTLDays, maxPerURN int) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open mq db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create mq schema: %w", err)
	}
	s := &Store{
		db:         db,
		defaultTTL: time.Duration(defaultTTLDays) * 24 * time.Hour,
		maxPerURN:  maxPerURN,
	}
	go s.cleanupLoop()
	return s, nil
}

// StoreEnvelope saves an EncryptedEnvelope for a recipient. Enforces per-URN quota (FIFO eviction).
func (s *Store) StoreEnvelope(ctx context.Context, recipientURN string, env *proto.EncryptedEnvelope, expiryUnix int64) (string, error) {
	msgID := env.GetMessageId()
	if msgID == "" {
		msgID = uuid.New().String()
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
			  SELECT id FROM messages WHERE recipient=? ORDER BY stored_at ASC
			  LIMIT MAX(0, (SELECT COUNT(*) FROM messages WHERE recipient=?) - ?)
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
	return msgID, nil
}

// Retrieve satisfies the mq.Store interface from the core SDK.
func (s *Store) Retrieve(ctx context.Context, recipientURN string) ([]*proto.EncryptedEnvelope, error) {
	envs, _, err := s.RetrieveEntry(ctx, recipientURN)
	return envs, err
}

// RetrieveEntry returns all pending envelopes and their database IDs for a recipient (oldest first).
func (s *Store) RetrieveEntry(ctx context.Context, recipientURN string) ([]*proto.EncryptedEnvelope, []string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, payload FROM messages WHERE recipient=? AND (expiry=0 OR expiry>?) ORDER BY stored_at ASC",
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

// Ack deletes the given message IDs.
func (s *Store) Ack(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := "?" 
	args := make([]interface{}, len(ids))
	args[0] = ids[0]
	for i := 1; i < len(ids); i++ {
		placeholders += ",?"
		args[i] = ids[i]
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM messages WHERE id IN ("+placeholders+")", args...)
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

// ListQueueStats returns statistics about all active message queues in the system.
func (s *Store) ListQueueStats(ctx context.Context) ([]*QueueStat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT recipient, COUNT(*), SUM(LENGTH(payload)), MIN(stored_at), MAX(stored_at)
		FROM messages
		WHERE expiry = 0 OR expiry > ?
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

func (s *Store) cleanupLoop() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		if _, err := s.db.Exec("DELETE FROM messages WHERE expiry>0 AND expiry<?", time.Now().Unix()); err != nil {
			log.Printf("[mq] cleanup error: %v", err)
		}
	}
}
