// Package config handles platform configuration loading.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform PlatformConfig `yaml:"platform"`
	Identity IdentityConfig `yaml:"identity"`
	Libp2p   Libp2pConfig   `yaml:"libp2p"`
	Registry RegistryConfig `yaml:"registry"`
	Relay    RelayConfig    `yaml:"relay"`
	MQ       MQConfig       `yaml:"mq"`
	API      APIConfig      `yaml:"api"`
	// AdminRegistryResetPending is an internal recovery marker, never part of config.yaml.
	AdminRegistryResetPending bool `yaml:"-" json:"-"`
}

// adminPolicyOverrides contains only the settings the admin console may persist.
// It lives in platform.data_dir so deployments can keep the main config read-only.
type adminPolicyOverrides struct {
	StoreUserData             *bool `yaml:"store_user_data"`
	ForwardToStoragePlatforms *bool `yaml:"forward_to_storage_platforms,omitempty"`
	HistoryRetentionDays      *int  `yaml:"history_retention_days"`
	RegistryResetPending      bool  `yaml:"registry_reset_pending"`
}

const adminPoliciesFilename = "admin-policies.yaml"

type PlatformConfig struct {
	Mode                      string `yaml:"mode"` // "privacy" | "compliance"
	DataDir                   string `yaml:"data_dir"`
	StoreUserData             bool   `yaml:"store_user_data"`
	ForwardToStoragePlatforms bool   `yaml:"forward_to_storage_platforms"`
	HistoryRetentionDays      int    `yaml:"history_retention_days"`
}

type IdentityConfig struct {
	KeysDir string `yaml:"keys_dir"`
}

type Libp2pConfig struct {
	ListenAddrs   []string `yaml:"listen_addrs"`
	ExternalAddrs []string `yaml:"external_addrs"`
}

type RegistryConfig struct {
	PersistDB   string `yaml:"persist_db"`
	TTLHours    int    `yaml:"ttl_hours"`
	HTTPEnabled bool   `yaml:"http_enabled"`
}

type RelayConfig struct {
	Enabled            bool   `yaml:"enabled"`
	MaxReservations    int    `yaml:"max_reservations"`
	MaxCircuitDuration string `yaml:"max_circuit_duration"`
}

type MQConfig struct {
	DBPath         string `yaml:"db_path"`
	DefaultTTLDays int    `yaml:"default_ttl_days"`
	MaxMsgsPerURN  int    `yaml:"max_msgs_per_urn"`
	HTTPEnabled    bool   `yaml:"http_enabled"`
}

type APIConfig struct {
	ListenAddr        string   `yaml:"listen_addr"`
	TLSCert           string   `yaml:"tls_cert"`
	TLSKey            string   `yaml:"tls_key"`
	AdminToken        string   `yaml:"admin_token"`
	RateLimitRate     float64  `yaml:"rate_limit_rate"`     // requests per second per IP (0 to disable)
	RateLimitBurst    int      `yaml:"rate_limit_burst"`    // burst size
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"` // Only these socket peers may supply X-Real-IP.
}

func DefaultConfig() *Config {
	return &Config{
		Platform: PlatformConfig{
			Mode:                      "privacy",
			DataDir:                   "./data",
			StoreUserData:             true,
			ForwardToStoragePlatforms: true,
			HistoryRetentionDays:      30,
		},
		Identity: IdentityConfig{KeysDir: "./data/keys"},
		Libp2p: Libp2pConfig{
			ListenAddrs: []string{
				"/ip4/0.0.0.0/tcp/45041",
				"/ip4/0.0.0.0/udp/45041/quic-v1",
			},
		},
		Registry: RegistryConfig{PersistDB: "./data/registry.db", TTLHours: 24, HTTPEnabled: true},
		Relay:    RelayConfig{Enabled: true, MaxReservations: 1000, MaxCircuitDuration: "2m"},
		MQ:       MQConfig{DBPath: "./data/mq.db", DefaultTTLDays: 7, MaxMsgsPerURN: 500, HTTPEnabled: true},
		API:      APIConfig{ListenAddr: ":8080", RateLimitRate: 10.0, RateLimitBurst: 20},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Env var overrides
	if v := os.Getenv("PLATFORM_API_ADDR"); v != "" {
		cfg.API.ListenAddr = v
	}
	if v := os.Getenv("PLATFORM_DATA_DIR"); v != "" {
		cfg.Platform.DataDir = v
	}
	if v := os.Getenv("PLATFORM_ADMIN_TOKEN"); v != "" {
		cfg.API.AdminToken = v
	}
	if (cfg.API.TLSCert == "") != (cfg.API.TLSKey == "") {
		return nil, fmt.Errorf("tls_cert and tls_key must be configured together")
	}
	for _, cidr := range cfg.API.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid trusted_proxy_cidrs entry %q: %w", cidr, err)
		}
	}
	if err := LoadAdminPolicies(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadAdminPolicies overlays console-managed settings on the base configuration.
// A missing override file preserves the original configuration.
func LoadAdminPolicies(cfg *Config) error {
	path := filepath.Join(cfg.Platform.DataDir, adminPoliciesFilename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read admin policies: %w", err)
	}
	var overrides adminPolicyOverrides
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&overrides); err != nil {
		return fmt.Errorf("parse admin policies: %w", err)
	}
	if overrides.HistoryRetentionDays != nil && *overrides.HistoryRetentionDays < 0 {
		return fmt.Errorf("admin policies history_retention_days must be nonnegative")
	}
	if overrides.StoreUserData != nil {
		cfg.Platform.StoreUserData = *overrides.StoreUserData
	}
	if overrides.ForwardToStoragePlatforms != nil {
		cfg.Platform.ForwardToStoragePlatforms = *overrides.ForwardToStoragePlatforms
	}
	if overrides.HistoryRetentionDays != nil {
		cfg.Platform.HistoryRetentionDays = *overrides.HistoryRetentionDays
	}
	cfg.AdminRegistryResetPending = overrides.RegistryResetPending
	return nil
}

// SaveAdminPolicies atomically persists only console-managed settings. The main
// config and environment-provided admin token are never rewritten by the console.
func SaveAdminPolicies(cfg *Config) error {
	storeUserData := cfg.Platform.StoreUserData
	forwardToStoragePlatforms := cfg.Platform.ForwardToStoragePlatforms
	historyRetentionDays := cfg.Platform.HistoryRetentionDays
	if historyRetentionDays < 0 {
		return fmt.Errorf("history_retention_days must be nonnegative")
	}
	data, err := yaml.Marshal(adminPolicyOverrides{
		StoreUserData:             &storeUserData,
		ForwardToStoragePlatforms: &forwardToStoragePlatforms,
		HistoryRetentionDays:      &historyRetentionDays,
		RegistryResetPending:      cfg.AdminRegistryResetPending,
	})
	if err != nil {
		return fmt.Errorf("marshal admin policies: %w", err)
	}
	tmp, err := os.CreateTemp(cfg.Platform.DataDir, ".admin-policies-*.tmp")
	if err != nil {
		return fmt.Errorf("create admin policies temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure admin policies temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write admin policies temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync admin policies temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close admin policies temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(cfg.Platform.DataDir, adminPoliciesFilename)); err != nil {
		return fmt.Errorf("replace admin policies: %w", err)
	}
	return nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// WriteFile's mode only applies when creating a file. Protect existing
	// configuration before persisting a token inherited from the environment.
	if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secure config permissions: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
