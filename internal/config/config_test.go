package config

import (
	"os"
	"path/filepath"
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
