package mq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	goproto "google.golang.org/protobuf/proto"
)

func TestAdminMessagePaginationAndSummary(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "mq.db"), 7, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().Unix()
	for i := 0; i < 110; i++ {
		_, err := store.db.Exec(`INSERT INTO messages(id, recipient, payload, expiry, stored_at, read_at) VALUES(?, ?, ?, ?, ?, 0)`, fmt.Sprintf("message-%03d", i), "agent:a", []byte{1, 2, 3}, now+3600, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, urn        string
		expiry, readAt int64
	}{
		{"history", "agent:a", now - 1, now - 10},
		{"expired", "agent:b", now - 1, 0},
	} {
		if _, err := store.db.Exec(`INSERT INTO messages(id, recipient, payload, expiry, stored_at, read_at) VALUES(?, ?, ?, ?, ?, ?)`, row.id, row.urn, []byte{4, 5}, row.expiry, now-20, row.readAt); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	legacy, err := store.ListMessagesDetail(ctx, "agent:a", "pending")
	if err != nil || len(legacy) != 100 {
		t.Fatalf("legacy detail should be capped at 100, got %d err=%v", len(legacy), err)
	}
	page, total, err := store.ListMessagesPage(ctx, "agent:a", "pending", 20, 100)
	if err != nil || total != 110 || len(page) != 10 || page[0].ID != "message-100" {
		t.Fatalf("pending page: len=%d total=%d err=%v", len(page), total, err)
	}
	history, total, err := store.ListMessagesPage(ctx, "agent:a", "history", 20, 0)
	if err != nil || total != 1 || len(history) != 1 || history[0].ID != "history" {
		t.Fatalf("history page: len=%d total=%d err=%v", len(history), total, err)
	}
	summary, err := store.SummarizeMessages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Pending.Messages != 110 || summary.Pending.Queues != 1 || summary.Pending.Bytes != 330 || summary.History.Messages != 1 || summary.History.Bytes != 2 || summary.Expired.Messages != 1 || summary.Expired.Bytes != 2 {
		t.Fatalf("disjoint summary buckets: %+v", summary)
	}
	largeEnvelope, err := goproto.Marshal(&pb.EncryptedEnvelope{SenderUrn: "agent:sender", Ciphertext: bytes.Repeat([]byte{0xaa}, 900000)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := store.db.Exec(`INSERT INTO messages(id, recipient, payload, expiry, stored_at, read_at) VALUES(?, ?, ?, ?, ?, 0)`, fmt.Sprintf("large-%03d", i), "agent:large", largeEnvelope, now+3600, now); err != nil {
			t.Fatal(err)
		}
	}
	metadataPage, total, err := store.ListMessagesPage(ctx, "agent:large", "pending", 200, 0)
	if err != nil || total != 3 || len(metadataPage) != 3 {
		t.Fatalf("large metadata page: total=%d len=%d err=%v", total, len(metadataPage), err)
	}
	pageJSON, err := json.Marshal(metadataPage)
	if err != nil || len(pageJSON) > 10000 || bytes.Contains(pageJSON, []byte("payload")) {
		t.Fatalf("large metadata page exposed ciphertext or grew too large: bytes=%d err=%v", len(pageJSON), err)
	}
	legacyLarge, err := store.ListMessagesDetail(ctx, "agent:large", "pending")
	if err != nil || len(legacyLarge) != 2 {
		t.Fatalf("legacy response must stop at 2 MiB budget: len=%d err=%v", len(legacyLarge), err)
	}
	full, err := store.GetMessageDetail(ctx, "agent:large", "large-002")
	if err != nil || full == nil {
		t.Fatalf("single detail missing: detail=%v err=%v", full, err)
	}
	if len(full.Payload) != 1800000 {
		t.Fatalf("single detail payload length=%d", len(full.Payload))
	}
}
