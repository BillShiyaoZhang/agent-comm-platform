// Package relay manages the libp2p Circuit Relay v2 service for NAT traversal.
package relay

import (
	"fmt"
	"math"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
)

// Service wraps the libp2p relay v2 service.
type Service struct {
	relay *relayv2.Relay
}

// Config holds relay service parameters.
type Config struct {
	MaxReservations    int
	MaxCircuitDuration time.Duration
	MaxCircuitBytes    uint64
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		MaxReservations:    1000,
		MaxCircuitDuration: 2 * time.Minute,
		MaxCircuitBytes:    5 * 1024 * 1024, // 5 MB
	}
}

// Start enables the Circuit Relay v2 service on the given host.
func Start(h host.Host, cfg Config) (*Service, error) {
	resources, err := relayResources(cfg)
	if err != nil {
		return nil, err
	}
	r, err := relayv2.New(h, relayv2.WithResources(resources))
	if err != nil {
		return nil, fmt.Errorf("start relay v2: %w", err)
	}
	return &Service{relay: r}, nil
}

func relayResources(cfg Config) (relayv2.Resources, error) {
	resources := relayv2.DefaultResources()
	if cfg.MaxReservations <= 0 || cfg.MaxCircuitDuration <= 0 || cfg.MaxCircuitBytes == 0 || cfg.MaxCircuitBytes > math.MaxInt64 {
		return resources, fmt.Errorf("relay resource limits must be positive and fit in int64")
	}
	resources.MaxReservations = cfg.MaxReservations
	// MaxCircuits is per peer, not global. Preserve libp2p's bounded default.
	resources.Limit.Duration = cfg.MaxCircuitDuration
	resources.Limit.Data = int64(cfg.MaxCircuitBytes)
	return resources, nil
}

// Close stops the relay service.
func (s *Service) Close() error {
	return s.relay.Close()
}
