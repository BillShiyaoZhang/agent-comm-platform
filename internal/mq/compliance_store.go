package mq

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const complianceSchema = `
CREATE TABLE IF NOT EXISTS compliance_messages (
  id TEXT PRIMARY KEY,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  stored_at INTEGER NOT NULL,
  expiry INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  policy_epoch INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  plaintext TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_compliance_stored_at ON compliance_messages(stored_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_sender ON compliance_messages(sender,stored_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_recipient ON compliance_messages(recipient,stored_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS v2_compliance_admissions (
  id TEXT PRIMARY KEY,
  recipient TEXT NOT NULL,
  envelope_hash TEXT NOT NULL,
  receipt BLOB NOT NULL,
  expiry INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_compliance_admission_expiry ON v2_compliance_admissions(expiry);
`

// ComplianceMessage is verified gateway-opened v2 plaintext and its signed
// routing metadata. Lists omit Plaintext; only a detail read returns the body.
// Expiry is the original delivery expiry, not the independent history deadline.
type ComplianceMessage struct {
	ID          string `json:"id"`
	Sender      string `json:"sender"`
	Recipient   string `json:"recipient"`
	StoredAt    int64  `json:"stored_at"`
	Expiry      int64  `json:"expiry"`
	PolicyHash  string `json:"policy_hash"`
	PolicyEpoch uint64 `json:"policy_epoch"`
	ContentType string `json:"content_type"`
	Plaintext   string `json:"plaintext,omitempty"`
}

type complianceExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func deleteExpiredCompliance(ctx context.Context, db complianceExecer, days int, now int64) error {
	if days == 0 {
		_, err := db.ExecContext(ctx, "DELETE FROM compliance_messages")
		return err
	}
	_, err := db.ExecContext(ctx, "DELETE FROM compliance_messages WHERE stored_at<=?", now-int64(days)*24*3600)
	return err
}

// SetComplianceRetentionDays applies a new duration and removes history that
// no longer fits it before making the value visible. Zero disables new body
// retention and removes all retained plaintext. The caller persists policy.
func (s *Store) SetComplianceRetentionDays(days int) error {
	if days < 0 || days > 36500 {
		return fmt.Errorf("compliance retention must be between 0 and 36500 days")
	}
	s.complianceMu.Lock()
	defer s.complianceMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A live increase cannot revive rows whose old retention already elapsed
	// while the periodic cleanup was pending. At boot, the first setter applies
	// the configured value directly: NewStore's default must not erase history
	// still valid under a longer duration persisted by the caller.
	purgeDays := days
	if s.complianceRetentionInitialized.Load() && s.complianceRetentionDays < purgeDays {
		purgeDays = s.complianceRetentionDays
	}
	if err := deleteExpiredCompliance(context.Background(), tx, purgeDays, time.Now().Unix()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.complianceRetentionDays = days
	s.complianceRetentionInitialized.Store(true)
	return nil
}

func (s *Store) GetComplianceRetentionDays() int {
	s.complianceMu.RLock()
	defer s.complianceMu.RUnlock()
	return s.complianceRetentionDays
}

// ListComplianceMessagesPage uses one snapshot for the count and metadata
// page. The active duration is enforced even before the cleanup worker runs.
func (s *Store) ListComplianceMessagesPage(ctx context.Context, sender, recipient string, limit, offset int) ([]*ComplianceMessage, int, error) {
	if limit < 1 || limit > 200 || offset < 0 {
		return nil, 0, fmt.Errorf("invalid compliance message page")
	}
	s.complianceMu.RLock()
	defer s.complianceMu.RUnlock()
	s.complianceRetentionInitialized.Store(true)
	if s.complianceRetentionDays == 0 {
		return []*ComplianceMessage{}, 0, nil
	}
	where := "stored_at>?"
	args := []any{time.Now().Unix() - int64(s.complianceRetentionDays)*24*3600}
	if sender != "" {
		where += " AND sender=?"
		args = append(args, sender)
	}
	if recipient != "" {
		where += " AND recipient=?"
		args = append(args, recipient)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM compliance_messages WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any{}, args...), limit, offset)
	rows, err := tx.QueryContext(ctx, `SELECT id,sender,recipient,stored_at,expiry,policy_hash,policy_epoch,content_type
		FROM compliance_messages WHERE `+where+" ORDER BY stored_at DESC,id DESC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	messages := []*ComplianceMessage{}
	for rows.Next() {
		var msg ComplianceMessage
		if err := rows.Scan(&msg.ID, &msg.Sender, &msg.Recipient, &msg.StoredAt, &msg.Expiry, &msg.PolicyHash, &msg.PolicyEpoch, &msg.ContentType); err != nil {
			return nil, 0, err
		}
		messages = append(messages, &msg)
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
	return messages, total, nil
}

func (s *Store) GetComplianceMessage(ctx context.Context, id string) (*ComplianceMessage, error) {
	s.complianceMu.RLock()
	defer s.complianceMu.RUnlock()
	s.complianceRetentionInitialized.Store(true)
	if s.complianceRetentionDays == 0 {
		return nil, nil
	}
	var msg ComplianceMessage
	// Reject corrupt oversized bodies in SQL before allocating the response.
	err := s.db.QueryRowContext(ctx, `SELECT id,sender,recipient,stored_at,expiry,policy_hash,policy_epoch,content_type,
		CASE WHEN LENGTH(CAST(plaintext AS BLOB))<=? THEN plaintext ELSE NULL END
		FROM compliance_messages WHERE id=? AND stored_at>?`, maxEnvelopeBytes, id,
		time.Now().Unix()-int64(s.complianceRetentionDays)*24*3600).Scan(&msg.ID, &msg.Sender, &msg.Recipient, &msg.StoredAt, &msg.Expiry, &msg.PolicyHash, &msg.PolicyEpoch, &msg.ContentType, &msg.Plaintext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &msg, nil
}
