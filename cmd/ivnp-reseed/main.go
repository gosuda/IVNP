package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

var version = "active-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ivnp-reseed", flag.ContinueOnError)
	flags.SetOutput(stderr)

	listenAddr := flags.String("listen", ":8080", "HTTP reseed server listen address(es), comma-separated (e.g. :8080 or :8080,:8443)")
	dataDir := flags.String("data-dir", "/data", "base persistent data directory")
	peersFile := flags.String("peers-file", "", "path to peer cache file (default <data-dir>/reseed-peers.json)")
	targetPeers := flags.Int("target", 1000, "target number of diverse peers in reseed archive")
	interval := flags.Duration("interval", 5*time.Minute, "refresh interval for harvesting, probing, and packaging")
	netID := flags.Uint("netid", 2, "I2P network ID")
	signerID := flags.String("signer-id", "reseed@ivnp.network", "SU3 signer common name")
	noRouter := flags.Bool("no-router", false, "disable embedded router (test/replay mode)")
	healthCheckURL := flags.String("healthcheck", "", "check health endpoint URL and exit 0 (healthy) or 1 (unhealthy)")
	runOnce := flags.Bool("once", false, "run one pass and exit")
	showVersion := flags.Bool("version", false, "show version and exit")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "ivnp-reseed", version)
		return 0
	}
	if *healthCheckURL != "" {
		client := http.Client{Timeout: 3 * time.Second}
		resp, checkErr := client.Get(*healthCheckURL)
		if checkErr != nil || resp.StatusCode != http.StatusOK {
			return 1
		}
		return 0
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cachePath := cmp.Or(*peersFile, filepath.Join(*dataDir, "reseed-peers.json"))

	// Generate or load signing keys
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Error("failed to generate RSA key", "error", err)
		return 1
	}
	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Error("failed to generate Ed25519 key", "error", err)
		return 1
	}

	logger.Info("initialized signing keys",
		"su3_signer", *signerID,
		"ed25519_pubkey", hex.EncodeToString(edPubKey),
	)

	store := NewPeerStore()
	if cachePath != "" {
		if loadErr := store.LoadFromFile(cachePath); loadErr != nil {
			logger.Warn("failed to load peer cache file", "path", cachePath, "error", loadErr)
		} else {
			logger.Info("loaded peer cache", "peers", store.Len(), "path", cachePath)
		}
	}

	crawler := NewActiveCrawler(store)
	prober := NewProber(store, 16)
	server := NewReseedServer(ServerConfig{
		NetworkID:     uint8(*netID),
		ListenAddress: *listenAddr,
		CacheDuration: *interval,
	}, store)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var routerSubsystem *node.Subsystem
	if !*noRouter {
		logger.Info("starting embedded IVNP router in client mode (no public port binding)...")
		routerCfg := configureActiveClientRouter(*dataDir, uint8(*netID))
		subsystem, routerErr := node.NewSubsystem(routerCfg, node.Options{Logger: logger})
		if routerErr != nil {
			logger.Error("failed to initialize embedded router", "error", routerErr)
			return 1
		}
		defer func() {
			if closeErr := subsystem.Close(); closeErr != nil {
				logger.Error("embedded router cleanup failed", "error", closeErr)
			}
		}()
		if startErr := subsystem.Start(ctx); startErr != nil {
			logger.Error("failed to start embedded router", "error", startErr)
			return 1
		}
		routerSubsystem = subsystem
		logger.Info("embedded router started successfully")
	}

	refreshPass := func(refreshCtx context.Context) error {
		start := time.Now()

		// 1. Harvest live RouterInfos directly from embedded router's NetDB memory table
		if routerSubsystem != nil {
			harvested := crawler.Harvest(routerSubsystem)
			logger.Info("harvested live peers from embedded NetDB",
				"newly_admitted", harvested,
				"total_store", store.Len(),
			)
		}

		// 2. Rate-limited non-disruptive probing
		if store.Len() > 0 {
			success := prober.ProbeAll(refreshCtx)
			logger.Info("probing completed", "reachable_peers", success, "total_probed", store.Len())
		}

		// 3. Save peer cache
		if cachePath != "" {
			if saveErr := store.SaveToFile(cachePath); saveErr != nil {
				logger.Warn("failed to save peer cache", "error", saveErr)
			}
		}

		// 4. Select diverse, accessible Floodfills and high-performance routers
		selectorCfg := DefaultSelectorConfig()
		selectorCfg.TargetCount = *targetPeers
		selectorCfg.RequireReachable = false // Allow candidates if cold-start
		selected := SelectDiversePeers(store.Snapshot(), selectorCfg)

		logger.Info("selected diverse peers",
			"target", *targetPeers,
			"selected", len(selected),
		)

		if len(selected) > 0 {
			now := time.Now()
			floodCount := 0
			for _, p := range selected {
				if p.IsFloodfill {
					floodCount++
				}
			}
			su3Bytes, su3Err := BuildSU3(selected, *signerID, rsaPrivKey, now)
			if su3Err != nil {
				return fmt.Errorf("build su3: %w", su3Err)
			}
			ivbsBytes, ivbsErr := BuildIVBS(selected, uint8(*netID), edPrivKey, now)
			if ivbsErr != nil {
				return fmt.Errorf("build ivbs: %w", ivbsErr)
			}

			sum := sha256.Sum256(ivbsBytes)
			etag := `"` + hex.EncodeToString(sum[:8]) + `"`
			server.UpdatePackage(ReseedPackage{
				GeneratedAt:    now,
				PeerCount:      len(selected),
				FloodfillCount: floodCount,
				SU3Data:        su3Bytes,
				IVBSData:       ivbsBytes,
				ETag:           etag,
			})

			logger.Info("reseed archives packaged",
				"su3_bytes", len(su3Bytes),
				"ivbs_bytes", len(ivbsBytes),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}
		return nil
	}

	if err := refreshPass(ctx); err != nil {
		logger.Error("initial refresh pass failed", "error", err)
	}

	if *runOnce {
		return 0
	}

	rawAddrs := strings.Split(*listenAddr, ",")
	var httpServers []*http.Server
	for _, raw := range rawAddrs {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		srv := &http.Server{
			Addr:    addr,
			Handler: server,
		}
		httpServers = append(httpServers, srv)
		go func(s *http.Server) {
			logger.Info("starting reseed HTTP server", "listen", s.Addr)
			if srvErr := s.ListenAndServe(); srvErr != nil && srvErr != http.ErrServerClosed {
				logger.Error("HTTP server failed", "listen", s.Addr, "error", srvErr)
			}
		}(srv)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down reseed server...")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, s := range httpServers {
				_ = s.Shutdown(shutdownCtx)
			}
			shutdownCancel()
			return 0
		case <-ticker.C:
			if err := refreshPass(ctx); err != nil {
				logger.Error("periodic refresh pass failed", "error", err)
			}
		}
	}
}

func configureActiveClientRouter(baseDir string, netID uint8) state.ConfigurationOperating {
	cfg := state.ConfigurationDefaultOperating()
	cfg.DataDir = filepath.Join(baseDir, "router")
	cfg.StateDir = filepath.Join(cfg.DataDir, "state")
	cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
	cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
	cfg.Network.ID = uint32(netID)

	// Pure outbound client: ephemeral port 0, unadvertised, no UPnP/NAT-PMP
	cfg.NTCP2.Enabled = false
	cfg.SSU2.Enabled = true
	cfg.SSU2.Bind = state.ConfigurationEndpoint{Host: "0.0.0.0", Port: 0}
	cfg.SSU2.Advertised = state.ConfigurationEndpoint{}
	cfg.NAT.UPnPEndpoint = ""
	cfg.NAT.NATPMPEndpoint = netip.AddrPort{}

	// Disable client-facing services to keep RAM bounded
	cfg.SAM.Enabled = false
	cfg.HTTPProxy.Enabled = false
	cfg.SOCKS5.Enabled = false
	cfg.Control.Enabled = false
	cfg.Metrics.Enabled = false
	cfg.AddressBook.Enabled = false

	return cfg
}
