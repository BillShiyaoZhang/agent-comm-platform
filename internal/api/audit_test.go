package api

import (
	"context"
	"os"
	"testing"
)

func TestAuditLog(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-log-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	al, err := NewAuditLog(tempDir)
	if err != nil {
		t.Fatalf("failed to initialize audit log: %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	// 1. Record logs
	al.Record("info", "registry", "node registered hermes:1", "details 1")
	al.Record("warn", "mq", "queue cleared hermes:2", "")
	al.Record("error", "relay", "connection failed hermes:3", "error details")

	entries, total, err := al.List(ctx, 10, 0, "", "", "")
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 entries, got %d", total)
	}

	// Test order (should be DESC)
	if entries[0].Level != "error" || entries[1].Level != "warn" || entries[2].Level != "info" {
		t.Errorf("unexpected logs order: %#v", entries)
	}

	// 2. Filter by Level
	entriesLevel, totalLevel, err := al.List(ctx, 10, 0, "warn", "", "")
	if err != nil {
		t.Fatalf("list entries by level: %v", err)
	}
	if totalLevel != 1 {
		t.Errorf("expected 1 warn entry, got %d", totalLevel)
	}
	if entriesLevel[0].Source != "mq" {
		t.Errorf("expected warn entry source to be 'mq', got %s", entriesLevel[0].Source)
	}

	// 3. Filter by Source
	entriesSource, totalSource, err := al.List(ctx, 10, 0, "", "relay", "")
	if err != nil {
		t.Fatalf("list entries by source: %v", err)
	}
	if totalSource != 1 {
		t.Errorf("expected 1 relay entry, got %d", totalSource)
	}
	if entriesSource[0].Message != "connection failed hermes:3" {
		t.Errorf("unexpected log message for relay: %s", entriesSource[0].Message)
	}

	// 4. Search by Message
	entriesSearch, totalSearch, err := al.List(ctx, 10, 0, "", "", "hermes:2")
	if err != nil {
		t.Fatalf("search entries: %v", err)
	}
	if totalSearch != 1 {
		t.Errorf("expected 1 searched entry, got %d", totalSearch)
	}
	if entriesSearch[0].Message != "queue cleared hermes:2" {
		t.Errorf("unexpected search result message: %q", entriesSearch[0].Message)
	}

	// 5. Limit and Offset
	entriesLimit, totalLimit, err := al.List(ctx, 1, 1, "", "", "")
	if err != nil {
		t.Fatalf("list with limit/offset: %v", err)
	}
	if totalLimit != 3 {
		t.Errorf("total should still be 3, got %d", totalLimit)
	}
	if len(entriesLimit) != 1 {
		t.Errorf("expected 1 entry returned, got %d", len(entriesLimit))
	}
	// The 2nd entry (offset 1) in DESC order should be "warn" (queue cleared hermes:2)
	if entriesLimit[0].Level != "warn" {
		t.Errorf("expected level 'warn' at offset 1, got %s", entriesLimit[0].Level)
	}
}
