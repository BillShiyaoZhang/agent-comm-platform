// Package config handles platform configuration loading.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform PlatformConfig  `yaml:"platform"`
	Identity IdentityConfig  `yaml:"identity"`
	Libp2p   Libp2pConfig    `yaml:"libp2p"`
	Registry RegistryConfig  `yaml:"registry"`
	Relay    RelayConfig     `yaml:"relay"`
	MQ       MQConfig        `yaml:"mq"`
	API      APIConfig       `yaml:"api"`
}

type PlatformConfig struct {
	Mode    string `yaml:"mode"`     // "privacy" | "compliance"
	DataDir string `yaml:"data_dir"`
}

type IdentityConfig struct {
	KeysDir string `yaml:"keys_dir"`
}

type Libp2pConfig struct {
	ListenAddrs   []string `yaml:"listen_addrs"`
	ExternalAddrs []string `yaml:"external_addrs"`
}

type RegistryConfig struct {
	PersistDB  string `yaml:"persist_db"`
	TTLHours   int    `yaml:"ttl_hours"`
	HTTPEnabled bool  `yaml:"http_enabled"`
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
	ListenAddr string `yaml:"listen_addr"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
	AdminToken string `yaml:"admin_token"`
}

func DefaultConfig() *Config {
	return &Config{
		Platform: PlatformConfig{Mode: "privacy", DataDir: "./data"},
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
		API:      APIConfig{ListenAddr: ":8080"},
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
	return cfg, nil
}
