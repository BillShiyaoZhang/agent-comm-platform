package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	golibp2p "github.com/libp2p/go-libp2p"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/api"
	"github.com/BillShiyaoZhang/agent-comm-platform/internal/config"
	mqpkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/mq"
	registrypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/registry"
	relaypkg "github.com/BillShiyaoZhang/agent-comm-platform/internal/relay"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	"github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/registry"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := os.MkdirAll(cfg.Platform.DataDir, 0755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Identity ─────────────────────────────────────────────────────────────
	id, err := crypto.LoadOrCreateIdentity(cfg.Identity.KeysDir)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	log.Printf("Platform identity: %s", id.Ed25519.URN())

	// ── libp2p Host ───────────────────────────────────────────────────────────
	libp2pPrivKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(id.Ed25519.PrivateKey)
	if err != nil {
		log.Fatalf("unmarshal libp2p key: %v", err)
	}
	h, err := golibp2p.New(
		golibp2p.ListenAddrStrings(cfg.Libp2p.ListenAddrs...),
		golibp2p.Identity(libp2pPrivKey),
		golibp2p.EnableNATService(),
		golibp2p.EnableRelay(),
	)
	if err != nil {
		log.Fatalf("create libp2p host: %v", err)
	}
	defer h.Close()
	log.Printf("libp2p PeerID: %s", h.ID())
	for _, addr := range h.Addrs() {
		log.Printf("  %s/p2p/%s", addr, h.ID())
	}

	// ── Registry ─────────────────────────────────────────────────────────────
	regStore, err := registrypkg.NewStore(cfg.Registry.PersistDB, cfg.Registry.TTLHours)
	if err != nil {
		log.Fatalf("create registry store: %v", err)
	}
	defer regStore.Close()
	regSrv := registry.NewServer(h, regStore)
	regSrv.Register()
	log.Printf("Registry: %s", registry.ProtoID)

	// Self-register
	_ = regStore.RegisterWithSignature(id.Ed25519.URN(), h.ID().String(), hostAddrs(h), nil,
		id.X25519PK, id.Ed25519.PublicKey, nil, 0)

	// ── Relay v2 ─────────────────────────────────────────────────────────────
	if cfg.Relay.Enabled {
		relayCfg := relaypkg.DefaultConfig()
		relayCfg.MaxReservations = cfg.Relay.MaxReservations
		if d, err := time.ParseDuration(cfg.Relay.MaxCircuitDuration); err == nil {
			relayCfg.MaxCircuitDuration = d
		}
		rs, err := relaypkg.Start(h, relayCfg)
		if err != nil {
			log.Fatalf("start relay: %v", err)
		}
		defer rs.Close()
		log.Println("Circuit Relay v2 started")
	}

	// ── MQ ───────────────────────────────────────────────────────────────────
	mqStore, err := mqpkg.NewStore(cfg.MQ.DBPath, cfg.MQ.DefaultTTLDays, cfg.MQ.MaxMsgsPerURN)
	if err != nil {
		log.Fatalf("create mq store: %v", err)
	}
	defer mqStore.Close()
	_, err = mq.NewServer(h, mqStore)
	if err != nil {
		log.Fatalf("create mq server: %v", err)
	}
	log.Printf("MQ: %s", mq.ProtoID)

	// ── HTTP API ─────────────────────────────────────────────────────────────
	apiSrv := api.New(cfg, regStore, mqStore, h.ID().String(), h)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiSrv.Start(ctx); err != nil {
			log.Printf("HTTP API: %v", err)
		}
	}()

	fmt.Printf("\n=== Agent Comm Platform ===\nMode : %s\nHTTP : http://%s\nURN  : %s\nCtrl+C to stop.\n",
		cfg.Platform.Mode, cfg.API.ListenAddr, id.Ed25519.URN())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
	cancel()
	wg.Wait()
	log.Println("Done.")
}

func hostAddrs(h host.Host) []string {
	var addrs []string
	for _, a := range h.Addrs() {
		addrs = append(addrs, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
	}
	return addrs
}
