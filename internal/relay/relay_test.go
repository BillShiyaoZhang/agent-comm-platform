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
