package mq

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

// V2Gateway holds separately provisioned policy, gateway-decrypt, and
// admission-signing keys. It never creates a trust root at service startup.
type V2Gateway struct {
	Policy         *v2.Policy
	RawPolicy      []byte
	Root           ed25519.PublicKey
	GatewayPrivate []byte
	ReceiptPrivate ed25519.PrivateKey
}

func readV2Key(path string, want int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == want {
		return raw, nil
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(decoded) != want {
		return nil, fmt.Errorf("key file %s must contain %d raw bytes or hex bytes", path, want)
	}
	return decoded, nil
}

func LoadV2Gateway(policyFile, rootFile, gatewayFile, receiptFile, platformID string) (*V2Gateway, error) {
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("read signed v2 policy: %w", err)
	}
	policy, err := v2.ParsePolicy(raw)
	if err != nil {
		return nil, fmt.Errorf("parse signed v2 policy: %w", err)
	}
	root, err := readV2Key(rootFile, ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("read pinned policy root: %w", err)
	}
	if err := v2.VerifyPolicy(policy, ed25519.PublicKey(root), time.Now()); err != nil {
		return nil, fmt.Errorf("verify signed v2 policy: %w", err)
	}
	if policy.PlatformID != platformID {
		return nil, fmt.Errorf("v2 policy platform_id does not match current platform identity")
	}
	if policy.Mode == v2.ModeCompliance && policy.AllowV1 {
		return nil, errors.New("compliance policy cannot allow generic v1 delivery")
	}
	receiptKey, err := readV2Key(receiptFile, ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("read v2 receipt private key: %w", err)
	}
	if !bytes.Equal(ed25519.PrivateKey(receiptKey).Public().(ed25519.PublicKey), policy.ReceiptPublicKey) {
		return nil, errors.New("v2 receipt private key does not match signed policy")
	}
	g := &V2Gateway{Policy: policy, RawPolicy: raw, Root: ed25519.PublicKey(root), ReceiptPrivate: ed25519.PrivateKey(receiptKey)}
	if policy.Mode == v2.ModeCompliance {
		if gatewayFile == "" {
			return nil, errors.New("compliance mode requires gateway_private_key_file")
		}
		gatewayKey, err := readV2Key(gatewayFile, 32)
		if err != nil {
			return nil, fmt.Errorf("read v2 gateway private key: %w", err)
		}
		private, err := ecdh.X25519().NewPrivateKey(gatewayKey)
		if err != nil {
			return nil, fmt.Errorf("invalid v2 gateway private key: %w", err)
		}
		if !bytes.Equal(private.PublicKey().Bytes(), policy.GatewayPublicKey) {
			return nil, errors.New("v2 gateway private key does not match signed policy")
		}
		g.GatewayPrivate = gatewayKey
	}
	return g, nil
}

func (g *V2Gateway) CheckCurrent() error {
	if g == nil {
		return ErrV2Policy
	}
	return v2.VerifyPolicy(g.Policy, g.Root, time.Now())
}

// AdmitV2 verifies the signed envelope, decrypts exactly that ciphertext in
// compliance mode, signs a CEK proof, then atomically stores both original
// bytes. Decrypted plaintext is never added to the mailbox or log.
func (g *V2Gateway) AdmitV2(ctx context.Context, store *Store, sender ed25519.PublicKey, recipient string, raw []byte, requestedExpiry int64) (string, []byte, error) {
	// An already admitted, byte-identical envelope may be retried after the
	// platform has switched epochs or the old policy has expired. Authenticate
	// its sender first, then return only the receipt committed with those exact
	// original bytes. It is not newly admitted or delivered under this policy.
	env, err := v2.VerifyEnvelopeSignature(sender, raw)
	if err != nil {
		return "", nil, err
	}
	if !crypto.URNMatchesPublicKey(env.Header.SenderURN, sender) || coremq.AuthorizeRecipient(ctx, env.Header.SenderURN) != nil {
		return "", nil, fmt.Errorf("%w: authenticated sender does not match signed header", ErrInvalidMessage)
	}
	if env.Header.RecipientURN != recipient || env.Header.Expiry != requestedExpiry {
		return "", nil, fmt.Errorf("%w: recipient or expiry does not match signed header", ErrInvalidMessage)
	}
	// StoreV2 checks quota and the pinned policy hash again in its transaction.
	if existing, ok, err := store.ExistingV2Receipt(ctx, recipient, env.Header.MessageID, raw); err != nil {
		return "", nil, err
	} else if ok {
		return env.Header.MessageID, existing, nil
	}
	if err := g.CheckCurrent(); err != nil {
		return "", nil, err
	}
	env, err = v2.VerifyEnvelope(g.Policy, sender, raw, time.Now())
	if err != nil {
		return "", nil, err
	}
	var cek, plaintext []byte
	result := v2.ResultAcceptedUninspected
	if g.Policy.Mode == v2.ModeCompliance {
		cek, plaintext, err = v2.GatewayOpen(g.Policy, env, g.GatewayPrivate)
		if err != nil {
			clear(cek)
			clear(plaintext)
			return "", nil, err
		}
		defer clear(cek)
		defer clear(plaintext)
		if err := v2.ValidateBody(plaintext); err != nil {
			return "", nil, fmt.Errorf("invalid declared v2 body: %w", err)
		}
		result = v2.ResultDecryptedAdmitted
	}
	receipt, err := v2.MakeReceipt(g.Policy, raw, cek, g.ReceiptPrivate, time.Now().Unix(), result)
	if err != nil {
		return "", nil, err
	}
	rawReceipt, err := v2.Canonical(receipt)
	if err != nil {
		return "", nil, err
	}
	storedReceipt, err := store.StoreV2(ctx, recipient, env.Header.MessageID, v2.PolicyHash(g.Policy), raw, rawReceipt, env.Header.Expiry)
	if err != nil {
		return "", nil, err
	}
	return env.Header.MessageID, storedReceipt, nil
}
