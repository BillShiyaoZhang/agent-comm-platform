package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComplianceRetentionDefaultAndLegacyOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	if cfg.Platform.ComplianceRetentionDays != 30 {
		t.Fatal("missing safe default")
	}
	cfg.Platform.DataDir = dir
	cfg.Platform.ComplianceRetentionDays = 45
	path := filepath.Join(dir, "config.yaml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adminPoliciesFilename), []byte("history_retention_days: 5\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform.ComplianceRetentionDays != 45 || got.Platform.HistoryRetentionDays != 5 {
		t.Fatalf("legacy override lost configured retention: %+v", got.Platform)
	}
	got.Platform.ComplianceRetentionDays = 0
	if err := SaveAdminPolicies(got); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform.ComplianceRetentionDays != 0 || got.Platform.HistoryRetentionDays != 5 {
		t.Fatalf("zero retention did not survive restart: %+v", got.Platform)
	}
	got.Registry.TTLHours = 48
	if err := SaveAdminEditableSettings(got, []string{"registry.ttl_hours"}); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform.ComplianceRetentionDays != 0 || got.Registry.TTLHours != 48 {
		t.Fatal("startup edits overwrote retention")
	}
}

func TestComplianceRetentionRejectsInvalidConfigAndOverrides(t *testing.T) {
	for _, value := range []string{"-1", "36501", "1.5", "nope"} {
		for _, override := range []bool{false, true} {
			dir := t.TempDir()
			cfg := DefaultConfig()
			cfg.Platform.DataDir = dir
			path := filepath.Join(dir, "config.yaml")
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			if override {
				if err := os.WriteFile(filepath.Join(dir, adminPoliciesFilename), []byte("compliance_retention_days: "+value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte("platform:\n  data_dir: "+dir+"\n  compliance_retention_days: "+value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("invalid retention %q (override=%v) accepted", value, override)
			}
		}
	}
}
