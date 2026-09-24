package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

func TestOfflinePolicyProvisioning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	if err := keygen(dir); err == nil {
		t.Fatal("keygen overwrote existing trust root")
	}
	root, err := readKey(dir, rootPublicFile, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode    string
		epoch   uint64
		allowV1 bool
	}{
		{v2.ModePrivate, 1, true}, {v2.ModeCompliance, 2, false},
	} {
		out := filepath.Join(t.TempDir(), "policy.json")
		if err := sign(dir, "test-platform-id", tc.mode, tc.epoch, out, time.Hour, tc.allowV1, false); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := v2.ParsePolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := v2.VerifyPolicy(policy, root, time.Now()); err != nil {
			t.Fatal(err)
		}
		if policy.PlatformID != "test-platform-id" || policy.Mode != tc.mode || policy.Epoch != tc.epoch || policy.AllowV1 != tc.allowV1 {
			t.Fatalf("wrong signed policy: %+v", policy)
		}
		if tc.mode == v2.ModeCompliance && (len(policy.GatewayPublicKey) != 32 || len(policy.ReceiptPublicKey) != 32) {
			t.Fatal("compliance keys missing")
		}
		gateway, err := mq.LoadV2Gateway(out, filepath.Join(dir, rootPublicFile), filepath.Join(dir, gatewayPrivateFile),
			filepath.Join(dir, receiptPrivateFile), "test-platform-id")
		if err != nil || gateway.Policy.Mode != tc.mode {
			t.Fatalf("platform cannot load provisioned policy: %v", err)
		}
		if err := sign(dir, "test-platform-id", tc.mode, tc.epoch, out, time.Hour, tc.allowV1, false); err == nil {
			t.Fatal("sign overwrote existing policy")
		}
	}
	if err := run([]string{"sign", "--keys-dir", dir, "--platform-id", "test-platform-id", "--mode", "compliance", "--epoch", "3", "--out", filepath.Join(t.TempDir(), "invalid.json"), "--allow-v1"}); err == nil {
		t.Fatal("compliance policy allowed generic v1")
	}
}

func TestPolicyEpochJSONSafeIntegerBoundary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	maxOut := filepath.Join(t.TempDir(), "max-safe-epoch.json")
	if err := sign(dir, "test-platform-id", v2.ModePrivate, maxSafeEpoch, maxOut, time.Hour, false, false); err != nil {
		t.Fatalf("largest Web-safe epoch was rejected: %v", err)
	}
	raw, err := os.ReadFile(maxOut)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := v2.ParsePolicy(raw)
	if err != nil || policy.Epoch != maxSafeEpoch {
		t.Fatalf("largest safe epoch did not round-trip: %v %v", policy, err)
	}
	root, err := readKey(dir, rootPublicFile, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.VerifyPolicy(policy, root, time.Now()); err != nil {
		t.Fatalf("largest safe epoch policy did not verify: %v", err)
	}
	tooLargeOut := filepath.Join(t.TempDir(), "unsafe-epoch.json")
	if err := run([]string{"sign", "--keys-dir", dir, "--platform-id", "test-platform-id", "--mode", "private", "--epoch", "9007199254740992", "--out", tooLargeOut}); err == nil {
		t.Fatal("CLI signed an epoch Web cannot represent exactly")
	}
	if _, err := os.Stat(tooLargeOut); !os.IsNotExist(err) {
		t.Fatalf("CLI created a policy file for unsafe epoch: %v", err)
	}
	if err := sign(dir, "test-platform-id", v2.ModePrivate, maxSafeEpoch+1, tooLargeOut, time.Hour, false, false); err == nil {
		t.Fatal("direct sign accepted an unsafe epoch")
	}
}

func TestPersistentPolicyDefaultAndFiniteOptIn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	root, err := readKey(dir, rootPublicFile, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"sign", "--keys-dir", dir, "--platform-id", "test-platform-id", "--mode", "compliance"}
	for _, tc := range []struct {
		name       string
		epoch      string
		flags      []string
		persistent bool
	}{
		{"default", "2", nil, true},
		{"explicit-persistent", "3", []string{"--persistent"}, true},
		{"finite", "4", []string{"--valid-for", "1h"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "policy.json")
			args := append(append([]string{}, base...), "--epoch", tc.epoch, "--out", out)
			args = append(args, tc.flags...)
			if err := run(args); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := v2.ParsePolicy(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := v2.VerifyPolicy(policy, root, time.Now()); err != nil {
				t.Fatalf("current v2 clients reject signed policy: %v", err)
			}
			if tc.persistent {
				if policy.ExpiresAt != persistentPolicyExpiry {
					t.Fatalf("persistent expiry = %d, want %d", policy.ExpiresAt, persistentPolicyExpiry)
				}
				if err := v2.VerifyPolicy(policy, root, time.Now().AddDate(100, 0, 0)); err != nil {
					t.Fatalf("unchanged policy requires periodic renewal: %v", err)
				}
				if time.Unix(policy.ExpiresAt, 0).In(time.FixedZone("UTC+8", 8*3600)).Year() != 3000 {
					t.Fatal("persistent expiry does not display in local year 3000")
				}
			} else if remaining := time.Until(time.Unix(policy.ExpiresAt, 0)); remaining < 59*time.Minute || remaining > time.Hour {
				t.Fatalf("explicit finite expiry is outside one hour: %v", remaining)
			}
			if _, err := mq.LoadV2Gateway(out, filepath.Join(dir, rootPublicFile), filepath.Join(dir, gatewayPrivateFile), filepath.Join(dir, receiptPrivateFile), "test-platform-id"); err != nil {
				t.Fatalf("current Platform rejects signed policy: %v", err)
			}
		})
	}
	if err := run(append(append([]string{}, base...), "--epoch", "5", "--out", filepath.Join(t.TempDir(), "invalid.json"), "--persistent", "--valid-for", "1h")); err == nil {
		t.Fatal("combined persistent and finite flags were accepted")
	}
}
