package registry

import (
	"strings"
	"testing"
)

func TestRegistrationCannotRollbackNewerSignedRecord(t *testing.T) {
	s := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	old := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	old.Timestamp -= 5
	signRegistryRecord(owner, &old)
	if err := registerTestRecord(s, old); err != nil {
		t.Fatal(err)
	}
	current := signedRegistryRequest(t, owner, owner.Ed25519.URN())
	current.StoresUserData = true
	signRegistryRecord(owner, &current)
	if err := registerTestRecord(s, current); err != nil {
		t.Fatal(err)
	}
	if err := registerTestRecord(s, old); err == nil {
		t.Fatal("old signed registration rolled back current policy")
	}
	got, err := s.ResolveEntry(old.URN)
	if err != nil || got == nil || !got.StoresUserData || got.Timestamp != current.Timestamp {
		t.Fatalf("current record lost: %v %v", got, err)
	}
	if err := registerTestRecord(s, current); err != nil {
		t.Fatalf("idempotent registration rejected: %v", err)
	}
}

func TestRegistrationAddressLimits(t *testing.T) {
	s := newRegistryTestStore(t)
	owner := newRegistryTestIdentity(t)
	for _, addresses := range [][]string{make([]string, 65), {strings.Repeat("x", 2049)}} {
		r := signedRegistryRequest(t, owner, owner.Ed25519.URN())
		r.Addrs = addresses
		if err := registerTestRecord(s, r); err == nil {
			t.Fatal("oversized registration accepted")
		}
	}
}
