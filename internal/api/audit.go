package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// LogEntry represents a single audit log entry.
type LogEntry struct {
	ID        int64  `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`   // "info", "warn", "error"
	Source    string `json:"source"`  // "registry", "mq", "relay", "admin", "system"
	Message   string `json:"message"`
	Details   string `json:"details,omitempty"`
}

// AuditLog provides persistent audit logging backed by SQLite.
type AuditLog struct {
	mu sync.Mutex
	db *sql.DB
}

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp  INTEGER NOT NULL,
  level      TEXT NOT NULL DEFAULT 'info',
  source     TEXT NOT NULL DEFAULT 'system',
  message    TEXT NOT NULL,
  details    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_level ON audit_log(level);
CREATE INDEX IF NOT EXISTS idx_audit_source ON audit_log(source);
`

// NewAuditLog creates a new audit log with SQLite persistence.
func NewAuditLog(dataDir string) (*AuditLog, error) {
	dbPath := dataDir + "/audit.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	if _, err := db.Exec(auditSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create audit schema: %w", err)
	}

	a := &AuditLog{db: db}
	// Background cleanup: keep only last 5000 entries
	go a.cleanupLoop()
	return a, nil
}

// Record adds a new entry to the audit log.
func (a *AuditLog) Record(level, source, message, details string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.Exec(
		"INSERT INTO audit_log (timestamp, level, source, message, details) VALUES (?, ?, ?, ?, ?)",
		time.Now().Unix(), level, source, message, details)
	if err != nil {
		log.Printf("[audit] failed to record: %v", err)
	}
}

// List returns the most recent log entries, with optional filtering.
func (a *AuditLog) List(ctx context.Context, limit, offset int, level, source, search string) ([]*LogEntry, int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	where := "1=1"
	args := []interface{}{}

	if level != "" {
		where += " AND level = ?"
		args = append(args, level)
	}
	if source != "" {
		where += " AND source = ?"
		args = append(args, source)
	}
	if search != "" {
		where += " AND message LIKE ?"
		args = append(args, "%"+search+"%")
	}

	// Get total count
	var total int
	countQ := "SELECT COUNT(*) FROM audit_log WHERE " + where
	if err := a.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get entries
	if limit <= 0 {
		limit = 100
	}
	query := fmt.Sprintf(
		"SELECT id, timestamp, level, source, message, details FROM audit_log WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?",
		where)
	args = append(args, limit, offset)

	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Level, &e.Source, &e.Message, &e.Details); err != nil {
			continue
		}
		entries = append(entries, &e)
	}
	if entries == nil {
		entries = []*LogEntry{}
	}
	return entries, total, nil
}

// Close closes the audit database.
func (a *AuditLog) Close() error {
	return a.db.Close()
}

func (a *AuditLog) cleanupLoop() {
	tick := time.NewTicker(1 * time.Hour)
	defer tick.Stop()
	for range tick.C {
		a.mu.Lock()
		// Keep only the most recent 5000 entries
		a.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)`)
		a.mu.Unlock()
	}
}

// handleAdminLogs returns the HTTP handler for the audit log endpoint.
func handleAdminLogs(auditLog *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}

		level := r.URL.Query().Get("level")
		source := r.URL.Query().Get("source")
		search := r.URL.Query().Get("search")

		entries, total, err := auditLog.List(r.Context(), limit, offset, level, source, search)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": entries,
			"total":   total,
			"limit":   limit,
			"offset":  offset,
		})
	}
}
