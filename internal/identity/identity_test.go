package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "identity-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generation
	id1, err := LoadOrCreate(tempDir)
	if err != nil {
		t.Fatalf("LoadOrCreate error: %v", err)
	}

	if id1.URN == "" {
		t.Error("expected non-empty URN")
	}
	if !strings.HasPrefix(id1.URN, "urn:hermes:platform:") {
		t.Errorf("expected URN prefix 'urn:hermes:platform:', got %q", id1.URN)
	}

	// Verify key files were created
	edFile := filepath.Join(tempDir, ed25519PrivFile)
	xFile := filepath.Join(tempDir, x25519PrivFile)
	if _, err := os.Stat(edFile); os.IsNotExist(err) {
		t.Errorf("expected ed25519 key file to exist")
	}
	if _, err := os.Stat(xFile); os.IsNotExist(err) {
		t.Errorf("expected x25519 key file to exist")
	}

	// 2. Loading
	id2, err := LoadOrCreate(tempDir)
	if err != nil {
		t.Fatalf("LoadOrCreate (reload) error: %v", err)
	}

	if id1.URN != id2.URN {
		t.Errorf("expected URNs to match: %q vs %q", id1.URN, id2.URN)
	}
	if string(id1.Ed25519Pub) != string(id2.Ed25519Pub) {
		t.Error("expected Ed25519 public keys to match")
	}
	if id1.X25519Pub != id2.X25519Pub {
		t.Error("expected X25519 public keys to match")
	}
}

func TestSignAndVerify(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "identity-sign-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	id, err := LoadOrCreate(tempDir)
	if err != nil {
		t.Fatalf("LoadOrCreate error: %v", err)
	}

	msg := []byte("hello hermes agent communication protocol")
	sig := id.Sign(msg)

	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify using platform utility
	if !VerifyEd25519(id.Ed25519Pub, msg, sig) {
		t.Error("expected signature to be valid")
	}

	// Verify with invalid message
	if VerifyEd25519(id.Ed25519Pub, []byte("different message"), sig) {
		t.Error("expected signature to fail verification for different message")
	}

	// Verify with invalid key
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	if VerifyEd25519(otherPub, msg, sig) {
		t.Error("expected signature to fail verification for different public key")
	}
}

func TestFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	fp := Fingerprint(pub)
	if len(fp) != 16 { // Hex representation of 8 bytes = 16 characters
		t.Errorf("expected fingerprint length 16, got %d (fp: %s)", len(fp), fp)
	}
}
