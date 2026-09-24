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
		if err := sign(dir, "test-platform-id", tc.mode, tc.epoch, out, time.Hour, tc.allowV1); err != nil {
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
		if err := sign(dir, "test-platform-id", tc.mode, tc.epoch, out, time.Hour, tc.allowV1); err == nil {
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
	if err := sign(dir, "test-platform-id", v2.ModePrivate, maxSafeEpoch, maxOut, time.Hour, false); err != nil {
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
	if err := sign(dir, "test-platform-id", v2.ModePrivate, maxSafeEpoch+1, tooLargeOut, time.Hour, false); err == nil {
		t.Fatal("direct sign accepted an unsafe epoch")
	}
}
