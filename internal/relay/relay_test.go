package relay

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
)

func TestRelayStartAndClose(t *testing.T) {
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create libp2p host error: %v", err)
	}
	defer h.Close()

	cfg := Config{
		MaxReservations:    10,
		MaxCircuitDuration: 2 * time.Second,
		MaxCircuitBytes:    1024,
	}

	service, err := Start(h, cfg)
	if err != nil {
		t.Fatalf("Start relay error: %v", err)
	}
	if service == nil {
		t.Fatal("expected non-nil service")
	}

	if err := service.Close(); err != nil {
		t.Errorf("Close relay error: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxReservations != 1000 {
		t.Errorf("expected 1000 reservations, got %d", cfg.MaxReservations)
	}
	if cfg.MaxCircuitDuration != 2*time.Minute {
		t.Errorf("expected 2m duration, got %v", cfg.MaxCircuitDuration)
	}
	if cfg.MaxCircuitBytes != 5*1024*1024 {
		t.Errorf("expected 5MB bytes, got %d", cfg.MaxCircuitBytes)
	}
}

func TestRelayEnforcesConfiguredCircuitLimits(t *testing.T) {
	cfg := Config{MaxReservations: 1000, MaxCircuitDuration: time.Second, MaxCircuitBytes: 1024}
	resources, err := relayResources(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resources.Limit.Duration != cfg.MaxCircuitDuration || resources.Limit.Data != 1024 {
		t.Fatalf("circuit limits ignored: %+v", resources.Limit)
	}
	if resources.ReservationTTL != time.Hour {
		t.Fatal("circuit duration changed reservation TTL")
	}
	if resources.MaxCircuits > 16 {
		t.Fatal("global reservation quota expanded per-peer circuit quota")
	}
	cfg.MaxCircuitBytes = ^uint64(0)
	if _, err := relayResources(cfg); err == nil {
		t.Fatal("overflowed byte limit accepted")
	}
}
