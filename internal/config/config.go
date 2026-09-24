// Package config handles platform configuration loading.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform PlatformConfig `yaml:"platform"`
	Identity IdentityConfig `yaml:"identity"`
	Libp2p   Libp2pConfig   `yaml:"libp2p"`
	Registry RegistryConfig `yaml:"registry"`
	Relay    RelayConfig    `yaml:"relay"`
	MQ       MQConfig       `yaml:"mq"`
	V2       V2Config       `yaml:"v2"`
	API      APIConfig      `yaml:"api"`
	// AdminRegistryResetPending is an internal recovery marker, never part of config.yaml.
	AdminRegistryResetPending bool `yaml:"-" json:"-"`
}

// adminPolicyOverrides contains only the settings the admin console may persist.
// It lives in platform.data_dir so deployments can keep the main config read-only.
type adminPolicyOverrides struct {
	StoreUserData             *bool   `yaml:"store_user_data"`
	ForwardToStoragePlatforms *bool   `yaml:"forward_to_storage_platforms,omitempty"`
	HistoryRetentionDays      *int    `yaml:"history_retention_days"`
	RegistryResetPending      bool    `yaml:"registry_reset_pending"`
	RegistryTTLHours          *int    `yaml:"registry_ttl_hours,omitempty"`
	MQDefaultTTLDays          *int    `yaml:"mq_default_ttl_days,omitempty"`
	MQMaxMsgsPerURN           *int    `yaml:"mq_max_msgs_per_urn,omitempty"`
	RelayEnabled              *bool   `yaml:"relay_enabled,omitempty"`
	RelayMaxReservations      *int    `yaml:"relay_max_reservations,omitempty"`
	RelayMaxCircuitDuration   *string `yaml:"relay_max_circuit_duration,omitempty"`
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

// V2 is an explicitly provisioned signed policy. The legacy platform.mode
// display field never enables gateway admission by itself.
type V2Config struct {
	Enabled                 bool   `yaml:"enabled"`
	PolicyFile              string `yaml:"policy_file"`
	PolicyRootPublicKeyFile string `yaml:"policy_root_public_key_file"`
	GatewayPrivateKeyFile   string `yaml:"gateway_private_key_file"`
	ReceiptPrivateKeyFile   string `yaml:"receipt_private_key_file"`
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
	if cfg.V2.Enabled {
		if cfg.V2.PolicyFile == "" || cfg.V2.PolicyRootPublicKeyFile == "" || cfg.V2.ReceiptPrivateKeyFile == "" {
			return nil, fmt.Errorf("v2 requires policy_file, policy_root_public_key_file, and receipt_private_key_file")
		}
	}
	return cfg, nil
}

// LoadAdminPolicies overlays console-managed settings on the base configuration.
// A missing override file preserves the original configuration.
func LoadAdminPolicies(cfg *Config) error {
	path := filepath.Join(cfg.Platform.DataDir, adminPoliciesFilename)
	overrides, err := readAdminPolicyOverrides(path)
	if err != nil {
		return err
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
	if overrides.RegistryTTLHours != nil {
		cfg.Registry.TTLHours = *overrides.RegistryTTLHours
	}
	if overrides.MQDefaultTTLDays != nil {
		cfg.MQ.DefaultTTLDays = *overrides.MQDefaultTTLDays
	}
	if overrides.MQMaxMsgsPerURN != nil {
		cfg.MQ.MaxMsgsPerURN = *overrides.MQMaxMsgsPerURN
	}
	if overrides.RelayEnabled != nil {
		cfg.Relay.Enabled = *overrides.RelayEnabled
	}
	if overrides.RelayMaxReservations != nil {
		cfg.Relay.MaxReservations = *overrides.RelayMaxReservations
	}
	if overrides.RelayMaxCircuitDuration != nil {
		cfg.Relay.MaxCircuitDuration = *overrides.RelayMaxCircuitDuration
	}
	for key, present := range map[string]bool{
		"registry.ttl_hours":         overrides.RegistryTTLHours != nil,
		"mq.default_ttl_days":        overrides.MQDefaultTTLDays != nil,
		"mq.max_msgs_per_urn":        overrides.MQMaxMsgsPerURN != nil,
		"relay.max_reservations":     overrides.RelayMaxReservations != nil,
		"relay.max_circuit_duration": overrides.RelayMaxCircuitDuration != nil,
	} {
		if present {
			if err := ValidateAdminEditableSetting(cfg, key); err != nil {
				return fmt.Errorf("admin policies: %w", err)
			}
		}
	}
	cfg.AdminRegistryResetPending = overrides.RegistryResetPending
	return nil
}

func readAdminPolicyOverrides(path string) (adminPolicyOverrides, error) {
	var overrides adminPolicyOverrides
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return overrides, nil
	}
	if err != nil {
		return overrides, fmt.Errorf("read admin policies: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&overrides); err != nil {
		return overrides, fmt.Errorf("parse admin policies: %w", err)
	}
	return overrides, nil
}

// ValidateAdminEditableSetting checks a single console-managed value. Base
// config.yaml remains compatible with older values (for example MQ max=0),
// while every override written by the console is validated before restart.
func ValidateAdminEditableSetting(cfg *Config, key string) error {
	switch key {
	case "registry.ttl_hours":
		if cfg.Registry.TTLHours < 1 || cfg.Registry.TTLHours > 8760 {
			return fmt.Errorf("registry.ttl_hours must be 1..8760")
		}
	case "mq.default_ttl_days":
		if cfg.MQ.DefaultTTLDays < 1 || cfg.MQ.DefaultTTLDays > 3650 {
			return fmt.Errorf("mq.default_ttl_days must be 1..3650")
		}
	case "mq.max_msgs_per_urn":
		if cfg.MQ.MaxMsgsPerURN < 1 || cfg.MQ.MaxMsgsPerURN > 100000 {
			return fmt.Errorf("mq.max_msgs_per_urn must be 1..100000")
		}
	case "relay.enabled":
		return nil
	case "relay.max_reservations":
		if cfg.Relay.MaxReservations < 1 || cfg.Relay.MaxReservations > 100000 {
			return fmt.Errorf("relay.max_reservations must be 1..100000")
		}
	case "relay.max_circuit_duration":
		duration, err := time.ParseDuration(cfg.Relay.MaxCircuitDuration)
		if err != nil || duration < 10*time.Second || duration > 24*time.Hour {
			return fmt.Errorf("relay.max_circuit_duration must be a duration from 10s to 24h")
		}
	default:
		return fmt.Errorf("%s is not a console-managed setting", key)
	}
	return nil
}

// SaveAdminPolicies atomically persists only console-managed settings. The main
// config and environment-provided admin token are never rewritten by the console.
func SaveAdminPolicies(cfg *Config) error {
	overrides, err := readAdminPolicyOverrides(filepath.Join(cfg.Platform.DataDir, adminPoliciesFilename))
	if err != nil {
		return err
	}
	return saveAdminPolicies(cfg, overrides)
}

// SaveAdminEditableSettings persists only requested startup settings together
// with the current live policies. Callers serialize this with other admin writes.
func SaveAdminEditableSettings(cfg *Config, keys []string) error {
	overrides, err := readAdminPolicyOverrides(filepath.Join(cfg.Platform.DataDir, adminPoliciesFilename))
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := ValidateAdminEditableSetting(cfg, key); err != nil {
			return err
		}
		switch key {
		case "registry.ttl_hours":
			overrides.RegistryTTLHours = &cfg.Registry.TTLHours
		case "mq.default_ttl_days":
			overrides.MQDefaultTTLDays = &cfg.MQ.DefaultTTLDays
		case "mq.max_msgs_per_urn":
			overrides.MQMaxMsgsPerURN = &cfg.MQ.MaxMsgsPerURN
		case "relay.enabled":
			overrides.RelayEnabled = &cfg.Relay.Enabled
		case "relay.max_reservations":
			overrides.RelayMaxReservations = &cfg.Relay.MaxReservations
		case "relay.max_circuit_duration":
			overrides.RelayMaxCircuitDuration = &cfg.Relay.MaxCircuitDuration
		}
	}
	return saveAdminPolicies(cfg, overrides)
}

func saveAdminPolicies(cfg *Config, overrides adminPolicyOverrides) error {
	storeUserData := cfg.Platform.StoreUserData
	forwardToStoragePlatforms := cfg.Platform.ForwardToStoragePlatforms
	historyRetentionDays := cfg.Platform.HistoryRetentionDays
	if historyRetentionDays < 0 {
		return fmt.Errorf("history_retention_days must be nonnegative")
	}
	overrides.StoreUserData = &storeUserData
	overrides.ForwardToStoragePlatforms = &forwardToStoragePlatforms
	overrides.HistoryRetentionDays = &historyRetentionDays
	overrides.RegistryResetPending = cfg.AdminRegistryResetPending
	data, err := yaml.Marshal(overrides)
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
