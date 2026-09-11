package main

import (
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
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ivnp-reseed", flag.ContinueOnError)
	flags.SetOutput(stderr)

	listenAddr := flags.String("listen", ":8443", "HTTP reseed server listen address")
	netdbPath := flags.String("netdb", "", "path to NetDB directory to crawl")
	peersFile := flags.String("peers-file", "reseed-peers.json", "path to peer cache file")
	targetPeers := flags.Int("target", 1000, "target number of diverse peers in reseed archive")
	interval := flags.Duration("interval", 5*time.Minute, "refresh interval for crawling, probing, and packaging")
	netID := flags.Uint("netid", 2, "I2P network ID")
	signerID := flags.String("signer-id", "reseed@ivnp.network", "SU3 signer common name")
	healthCheckURL := flags.String("healthcheck", "", "check health endpoint URL and exit 0 (healthy) or 1 (unhealthy)")
	runOnce := flags.Bool("once", false, "run one pass of crawl, probe, package and exit")
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
	if *peersFile != "" {
		if loadErr := store.LoadFromFile(*peersFile); loadErr != nil {
			logger.Warn("failed to load peer cache file", "path", *peersFile, "error", loadErr)
		} else {
			logger.Info("loaded peer cache", "peers", store.Len(), "path", *peersFile)
		}
	}

	crawler := NewCrawler(store)
	prober := NewProber(store, 32)
	server := NewReseedServer(ServerConfig{
		NetworkID:     uint8(*netID),
		ListenAddress: *listenAddr,
		CacheDuration: *interval,
	}, store)

	refreshPass := func(ctx context.Context) error {
		start := time.Now()
		if *netdbPath != "" {
			imported, crawlErr := crawler.CrawlDirectory(*netdbPath)
			if crawlErr != nil {
				logger.Warn("crawl error", "path", *netdbPath, "error", crawlErr)
			} else {
				logger.Info("crawl completed", "imported_or_updated", imported, "total_store", store.Len())
			}
		}

		if store.Len() > 0 {
			success := prober.ProbeAll(ctx)
			logger.Info("probing completed", "reachable_peers", success, "total_probed", store.Len())
		}

		if *peersFile != "" {
			if saveErr := store.SaveToFile(*peersFile); saveErr != nil {
				logger.Warn("failed to save peer cache", "error", saveErr)
			}
		}

		// Select optimal diverse peers
		selectorCfg := DefaultSelectorConfig()
		selectorCfg.TargetCount = *targetPeers
		selectorCfg.RequireReachable = false // fallback to viable if early cold-start
		selected := SelectDiversePeers(store.Snapshot(), selectorCfg)

		logger.Info("selected diverse peers",
			"target", *targetPeers,
			"selected", len(selected),
		)

		if len(selected) > 0 {
			now := time.Now()
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
				GeneratedAt: now,
				PeerCount:   len(selected),
				SU3Data:     su3Bytes,
				IVBSData:    ivbsBytes,
				ETag:        etag,
			})

			logger.Info("reseed archives packaged",
				"su3_bytes", len(su3Bytes),
				"ivbs_bytes", len(ivbsBytes),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := refreshPass(ctx); err != nil {
		logger.Error("initial refresh pass failed", "error", err)
	}

	if *runOnce {
		return 0
	}

	httpSrv := &http.Server{
		Addr:    *listenAddr,
		Handler: server,
	}

	go func() {
		logger.Info("starting reseed HTTP server", "listen", *listenAddr)
		if srvErr := httpSrv.ListenAndServe(); srvErr != nil && srvErr != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", srvErr)
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down reseed server...")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = httpSrv.Shutdown(shutdownCtx)
			shutdownCancel()
			return 0
		case <-ticker.C:
			if err := refreshPass(ctx); err != nil {
				logger.Error("periodic refresh pass failed", "error", err)
			}
		}
	}
}
