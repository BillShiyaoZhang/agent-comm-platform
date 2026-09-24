// v2-policy provisions an Agent Comm v2 policy offline. Keep the policy root
// private key outside the running Platform and distribute its public key to
// Agents through an independently authenticated channel.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/v2"
)

const (
	rootPrivateFile    = "policy-root.private"
	rootPublicFile     = "policy-root.public"
	gatewayPrivateFile = "gateway.private"
	receiptPrivateFile = "receipt.private"
	issuerPrivateFile  = "managed-issuer.private"
	// Canonical JSON policy epochs must round-trip through the Web console's
	// JavaScript number type without losing precision.
	maxSafeEpoch uint64 = 1<<53 - 1
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "v2-policy:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: v2-policy keygen --out-dir DIR | sign --keys-dir DIR --platform-id PEER_ID --mode private|compliance --epoch N --out FILE")
	}
	switch args[0] {
	case "keygen":
		flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
		dir := flags.String("out-dir", "", "new key directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" || flags.NArg() != 0 {
			return errors.New("keygen requires --out-dir DIR")
		}
		return keygen(*dir)
	case "sign":
		flags := flag.NewFlagSet("sign", flag.ContinueOnError)
		dir := flags.String("keys-dir", "", "key directory from keygen")
		platformID := flags.String("platform-id", "", "libp2p peer ID from the Platform /info endpoint")
		mode := flags.String("mode", "", "private or compliance")
		epoch := flags.Uint64("epoch", 0, "monotonically increasing policy epoch")
		out := flags.String("out", "", "new signed policy JSON file")
		validFor := flags.Duration("valid-for", 7*24*time.Hour, "policy lifetime")
		allowV1 := flags.Bool("allow-v1", false, "allow legacy v1 only under a private policy")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" || *platformID == "" || *out == "" || *epoch == 0 || flags.NArg() != 0 || (*mode != v2.ModePrivate && *mode != v2.ModeCompliance) {
			return errors.New("sign requires --keys-dir, --platform-id, --mode private|compliance, --epoch, and --out")
		}
		if *epoch > maxSafeEpoch {
			return fmt.Errorf("epoch must not exceed %d (2^53-1) for Web JSON interoperability", maxSafeEpoch)
		}
		if *validFor < time.Minute || *validFor > 30*24*time.Hour {
			return errors.New("--valid-for must be between one minute and 30 days")
		}
		if *mode == v2.ModeCompliance && *allowV1 {
			return errors.New("generic v1 cannot be allowed in compliance mode")
		}
		return sign(*dir, *platformID, *mode, *epoch, *out, *validFor, *allowV1)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func keygen(dir string) error {
	files := []string{rootPrivateFile, rootPublicFile, gatewayPrivateFile, receiptPrivateFile, issuerPrivateFile}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("refusing to overwrite %s", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	gateway, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	generated := map[string][]byte{
		rootPrivateFile: rootPrivate, rootPublicFile: rootPublic, gatewayPrivateFile: gateway.Bytes(),
		receiptPrivateFile: receiptPrivate, issuerPrivateFile: issuerPrivate,
	}
	for _, name := range files {
		mode := os.FileMode(0600)
		if name == rootPublicFile {
			mode = 0644
		}
		if err := writeNew(filepath.Join(dir, name), generated[name], mode); err != nil {
			return err
		}
	}
	fmt.Printf("Created v2 keys in %s. Keep %s offline; distribute only %s as the independent Agent trust anchor.\n", dir, rootPrivateFile, rootPublicFile)
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func readKey(dir, name string, size int) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s must contain %d raw bytes", name, size)
	}
	return raw, nil
}

func keyID(prefix string, public []byte) string {
	digest := sha256.Sum256(public)
	return prefix + ":" + hex.EncodeToString(digest[:16])
}

func sign(dir, platformID, mode string, epoch uint64, out string, validFor time.Duration, allowV1 bool) error {
	if epoch == 0 || epoch > maxSafeEpoch {
		return fmt.Errorf("epoch must be between 1 and %d (2^53-1) for Web JSON interoperability", maxSafeEpoch)
	}
	rootPrivate, err := readKey(dir, rootPrivateFile, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	rootPublic, err := readKey(dir, rootPublicFile, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if !bytes.Equal(ed25519.PrivateKey(rootPrivate).Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("policy root public/private files do not match")
	}
	receiptPrivate, err := readKey(dir, receiptPrivateFile, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	issuerPrivate, err := readKey(dir, issuerPrivateFile, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	receiptPublic := ed25519.PrivateKey(receiptPrivate).Public().(ed25519.PublicKey)
	issuerPublic := ed25519.PrivateKey(issuerPrivate).Public().(ed25519.PublicKey)
	now := time.Now()
	policy := &v2.Policy{
		Version: v2.Version, PlatformID: platformID, Epoch: epoch,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(validFor).Unix(),
		Mode: mode, Suite: v2.Suite, ReceiptKeyID: keyID("receipt", receiptPublic),
		ReceiptPublicKey: receiptPublic, AllowV1: allowV1, ManagedIssuerPublicKey: issuerPublic,
	}
	if mode == v2.ModeCompliance {
		gatewayRaw, err := readKey(dir, gatewayPrivateFile, 32)
		if err != nil {
			return err
		}
		gateway, err := ecdh.X25519().NewPrivateKey(gatewayRaw)
		if err != nil {
			return err
		}
		policy.GatewayPublicKey = gateway.PublicKey().Bytes()
		policy.GatewayKeyID = keyID("gateway", policy.GatewayPublicKey)
	}
	if err := v2.SignPolicy(policy, ed25519.PrivateKey(rootPrivate)); err != nil {
		return err
	}
	raw, err := v2.Canonical(policy)
	if err != nil {
		return err
	}
	if err := writeNew(out, raw, 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote signed %s policy (epoch %d; SHA-256 %s) to %s.\n", mode, epoch, v2.PolicyHash(policy), out)
	return nil
}
