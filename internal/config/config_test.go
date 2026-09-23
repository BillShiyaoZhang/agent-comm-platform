package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if cfg.Platform.Mode != "privacy" {
		t.Errorf("expected Platform.Mode 'privacy', got %q", cfg.Platform.Mode)
	}
	if cfg.API.ListenAddr != ":8080" {
		t.Errorf("expected API.ListenAddr ':8080', got %q", cfg.API.ListenAddr)
	}
	if cfg.API.RateLimitRate != 10.0 {
		t.Errorf("expected API.RateLimitRate 10.0, got %f", cfg.API.RateLimitRate)
	}
	if cfg.API.RateLimitBurst != 20 {
		t.Errorf("expected API.RateLimitBurst 20, got %d", cfg.API.RateLimitBurst)
	}
}

func TestSaveRestrictsExistingConfigPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("api: {}"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.API.AdminToken = "test-secret"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secret remains readable by others: %o", info.Mode().Perm())
	}
}

func TestLoadRejectsInvalidTrustAndPartialTLS(t *testing.T) {
	for _, data := range []string{"api:\n  trusted_proxy_cidrs: [not-a-cidr]\n", "api:\n  tls_cert: cert.pem\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("invalid security configuration accepted")
		}
	}
}

func TestLoad(t *testing.T) {
	// Test load defaults (empty path)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected no error loading defaults, got: %v", err)
	}
	if cfg.Platform.Mode != "privacy" {
		t.Errorf("expected Platform.Mode 'privacy', got %q", cfg.Platform.Mode)
	}

	// Test loading from a temp config file
	tempDir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configData := `
platform:
  mode: "compliance"
  data_dir: "/tmp/custom_data"
api:
  listen_addr: ":9090"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err = Load(configPath)
	if err != nil {
		t.Fatalf("expected no error loading config file, got: %v", err)
	}
	if cfg.Platform.Mode != "compliance" {
		t.Errorf("expected Platform.Mode 'compliance', got %q", cfg.Platform.Mode)
	}
	if cfg.Platform.DataDir != "/tmp/custom_data" {
		t.Errorf("expected Platform.DataDir '/tmp/custom_data', got %q", cfg.Platform.DataDir)
	}
	if cfg.API.ListenAddr != ":9090" {
		t.Errorf("expected API.ListenAddr ':9090', got %q", cfg.API.ListenAddr)
	}

	// Test environment overrides
	os.Setenv("PLATFORM_API_ADDR", ":9999")
	os.Setenv("PLATFORM_DATA_DIR", "/tmp/env_data")
	defer func() {
		os.Unsetenv("PLATFORM_API_ADDR")
		os.Unsetenv("PLATFORM_DATA_DIR")
	}()

	cfg, err = Load(configPath)
	if err != nil {
		t.Fatalf("expected no error loading config with env, got: %v", err)
	}
	if cfg.API.ListenAddr != ":9999" {
		t.Errorf("expected overridden API.ListenAddr ':9999', got %q", cfg.API.ListenAddr)
	}
	if cfg.Platform.DataDir != "/tmp/env_data" {
		t.Errorf("expected overridden Platform.DataDir '/tmp/env_data', got %q", cfg.Platform.DataDir)
	}
}

func TestAdminPolicyOverridesWithReadOnlyMainConfig(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := filepath.Join(dataDir, "config.yaml")
	base := DefaultConfig()
	base.Platform.DataDir = dataDir
	if err := Save(cfgPath, base); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0400); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Platform.StoreUserData = false
	loaded.Platform.HistoryRetentionDays = 0
	loaded.API.AdminToken = "environment-secret"
	if err := SaveAdminPolicies(loaded); err != nil {
		t.Fatalf("read-only main config must not block policy persistence: %v", err)
	}
	override, err := os.ReadFile(filepath.Join(dataDir, adminPoliciesFilename))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(override, []byte("environment-secret")) {
		t.Fatal("admin token written to policy override")
	}
	reloaded, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Platform.StoreUserData || reloaded.Platform.HistoryRetentionDays != 0 {
		t.Fatalf("policy override not applied after restart: %+v", reloaded.Platform)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dataDir, adminPoliciesFilename))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("policy override permissions: %o", info.Mode().Perm())
		}
	}
}

func TestLoadRejectsInvalidAdminPolicyOverride(t *testing.T) {
	for _, override := range []string{
		"history_retention_days: -1\n",
		"unknown_policy: true\n",
		"history_retention_days: nope\n",
	} {
		dataDir := t.TempDir()
		cfgPath := filepath.Join(dataDir, "config.yaml")
		base := DefaultConfig()
		base.Platform.DataDir = dataDir
		if err := Save(cfgPath, base); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, adminPoliciesFilename), []byte(override), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(cfgPath); err == nil {
			t.Fatalf("invalid admin policy override accepted: %q", override)
		}
	}
}
