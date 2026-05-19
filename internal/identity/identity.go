// Package identity manages the platform's persistent Ed25519 + X25519 key pair.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

const (
	ed25519PrivFile = "ed25519.key"
	x25519PrivFile  = "x25519.key"
)

// Identity holds the platform's cryptographic identity.
type Identity struct {
	Ed25519Priv ed25519.PrivateKey
	Ed25519Pub  ed25519.PublicKey
	X25519Priv  [32]byte
	X25519Pub   [32]byte
	URN         string // urn:hermes:platform:<fingerprint>
}

// LoadOrCreate loads existing keys from keysDir or generates new ones.
func LoadOrCreate(keysDir string) (*Identity, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir keys: %w", err)
	}

	edPrivPath := filepath.Join(keysDir, ed25519PrivFile)
	x25519Path := filepath.Join(keysDir, x25519PrivFile)

	var edPriv ed25519.PrivateKey
	var x25519Priv [32]byte

	// Load or generate Ed25519 key
	if data, err := os.ReadFile(edPrivPath); err == nil {
		raw, err := hex.DecodeString(string(data))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ed25519 key file")
		}
		edPriv = ed25519.PrivateKey(raw)
	} else {
		_, edPriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519: %w", err)
		}
		if err := os.WriteFile(edPrivPath, []byte(hex.EncodeToString(edPriv)), 0600); err != nil {
			return nil, fmt.Errorf("save ed25519 key: %w", err)
		}
	}

	// Load or generate X25519 key
	if data, err := os.ReadFile(x25519Path); err == nil {
		raw, err := hex.DecodeString(string(data))
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid x25519 key file")
		}
		copy(x25519Priv[:], raw)
	} else {
		if _, err := rand.Read(x25519Priv[:]); err != nil {
			return nil, fmt.Errorf("generate x25519: %w", err)
		}
		if err := os.WriteFile(x25519Path, []byte(hex.EncodeToString(x25519Priv[:])), 0600); err != nil {
			return nil, fmt.Errorf("save x25519 key: %w", err)
		}
	}

	edPub := edPriv.Public().(ed25519.PublicKey)
	var x25519Pub [32]byte
	curve25519.ScalarBaseMult(&x25519Pub, &x25519Priv)

	fingerprint := Fingerprint(edPub)
	urn := "urn:hermes:platform:" + fingerprint

	return &Identity{
		Ed25519Priv: edPriv,
		Ed25519Pub:  edPub,
		X25519Priv:  x25519Priv,
		X25519Pub:   x25519Pub,
		URN:         urn,
	}, nil
}

// Sign signs message with the Ed25519 private key.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.Ed25519Priv, msg)
}

// Fingerprint returns Base58-like hex fingerprint of an Ed25519 public key (first 16 bytes of SHA-256).
func Fingerprint(pub ed25519.PublicKey) string {
	// Simple hex fingerprint — first 8 bytes of raw pubkey
	return hex.EncodeToString(pub[:8])
}

// VerifyEd25519 verifies an Ed25519 signature.
func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}
