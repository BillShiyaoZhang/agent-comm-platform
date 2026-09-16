package mq

import (
	"errors"
	"fmt"
	"testing"
	"time"

	pb "github.com/BillShiyaoZhang/agent-comm/proto"
	"google.golang.org/protobuf/proto"
)

func TestMailboxExpiryAndACKBounds(t *testing.T) {
	s := securityStore(t, 10)
	owner := securityKey(t)
	env := signTestEnvelope(t, owner, owner.URN(), &pb.EncryptedEnvelope{MessageId: "ttl"})
	for _, expiry := range []int64{-1, time.Now().Unix() - 1} {
		if _, err := s.StoreEnvelope(securityCtx(owner), owner.URN(), env, expiry); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("invalid expiry accepted: %v", err)
		}
	}
	if _, err := s.StoreEnvelope(securityCtx(owner), owner.URN(), env, int64(^uint64(0)>>1)); err != nil {
		t.Fatal(err)
	}
	var expiry int64
	if err := s.db.QueryRow("SELECT expiry FROM messages WHERE id='ttl'").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if expiry > time.Now().Add(s.defaultTTL).Unix() {
		t.Fatal("sender bypassed retention limit")
	}
	if _, err := s.Ack(securityCtx(owner), owner.URN(), make([]string, maxAckIDs+1)); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unbounded ACK accepted: %v", err)
	}
}

func TestRetrieveBatchesPreserveUnacknowledgedMessages(t *testing.T) {
	s := securityStore(t, 10)
	owner := securityKey(t)
	for n := 0; n < 6; n++ {
		env := signTestEnvelope(t, owner, owner.URN(), &pb.EncryptedEnvelope{MessageId: fmt.Sprint(n), Ciphertext: make([]byte, 800<<10)})
		if _, err := s.StoreEnvelope(securityCtx(owner), owner.URN(), env, 0); err != nil {
			t.Fatal(err)
		}
	}
	envs, ids, err := s.RetrieveEntry(securityCtx(owner), owner.URN())
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, env := range envs {
		total += proto.Size(env)
	}
	if len(envs) == 0 || len(envs) >= 6 || total > maxRetrieveBytes {
		t.Fatalf("unbounded batch: %d messages, %d bytes", len(envs), total)
	}
	if _, err := s.Ack(securityCtx(owner), owner.URN(), ids); err != nil {
		t.Fatal(err)
	}
	rest, _, err := s.RetrieveEntry(securityCtx(owner), owner.URN())
	if err != nil || len(rest)+len(envs) != 6 {
		t.Fatalf("pagination lost messages: %v", err)
	}
}

func TestSubscriberLimitsAndReleasedCapacity(t *testing.T) {
	s := securityStore(t, 10)
	owner := securityKey(t)
	var channels []chan *pb.EncryptedEnvelope
	for n := 0; n < maxSubscribersPerURN; n++ {
		ch := make(chan *pb.EncryptedEnvelope, 1)
		channels = append(channels, ch)
		if err := s.RegisterSubscriber(securityCtx(owner), owner.URN(), ch); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RegisterSubscriber(securityCtx(owner), owner.URN(), make(chan *pb.EncryptedEnvelope, 1)); !errors.Is(err, ErrSubscriberLimit) {
		t.Fatalf("unbounded subscriptions: %v", err)
	}
	s.UnregisterSubscriber(owner.URN(), channels[0])
	if err := s.RegisterSubscriber(securityCtx(owner), owner.URN(), make(chan *pb.EncryptedEnvelope, 1)); err != nil {
		t.Fatalf("released capacity unavailable: %v", err)
	}
	s.subscriberCount = maxSubscribers
	other := securityKey(t)
	if err := s.RegisterSubscriber(securityCtx(other), other.URN(), make(chan *pb.EncryptedEnvelope, 1)); !errors.Is(err, ErrSubscriberLimit) {
		t.Fatalf("global subscriber limit ignored: %v", err)
	}
}
