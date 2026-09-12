package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/keygen"
	"golang.org/x/crypto/hkdf"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

var version = "active-dev"

var errEmptySeedPhrase = errors.New("seed phrase is empty after normalization")

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ivnp-reseed", flag.ContinueOnError)
	flags.SetOutput(stderr)

	listenAddr := flags.String("listen", ":8080", "HTTP reseed server listen address(es), comma-separated (e.g. :8080 or :8080,:8443)")
	dataDir := flags.String("data-dir", "/data", "base persistent data directory")
	tempDir := flags.String("temp-dir", "", "temporary directory for tainted copy state (default os.TempDir())")
	peersFile := flags.String("peers-file", "", "path to peer cache file (default <data-dir>/reseed-peers.json)")
	targetPeers := flags.Int("target", 1024, "target number of diverse peers in reseed archive")
	interval := flags.Duration("interval", 10*time.Minute, "refresh interval for harvesting, probing, and packaging")
	netID := flags.Uint("netid", 2, "I2P network ID")
	signerID := flags.String("signer-id", envOr("RESEED_SIGNER_ID", "reseed@ivnp.network"), "SU3 signer common name (env RESEED_SIGNER_ID)")
	seedPhrase := flags.String("seed-phrase", envOr("RESEED_SEED_PHRASE", ""), "deterministic RSA-4096 signing key seed phrase; prefer env RESEED_SEED_PHRASE so the phrase stays out of process arguments")
	routerPort := flags.Int("router-port", 0, "port for embedded router NTCP2/SSU2 transports (default 0 for random/ephemeral)")
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
	su3Path := filepath.Join(*dataDir, "i2pseeds.su3")
	keyPath := filepath.Join(*dataDir, "reseed-rsa.key")
	certPath := filepath.Join(*dataDir, "reseed-rsa.crt")
	pubKeyPath := filepath.Join(*dataDir, "reseed-rsa.pub.pem")

	// Drop partial state left by interrupted atomic writes before loading.
	for _, statePath := range []string{cachePath, su3Path, keyPath, certPath, pubKeyPath} {
		removeStaleTempFile(statePath, logger)
	}
	if _, statErr := os.Stat(keyPath); statErr == nil {
		logger.Warn("ignoring legacy reseed-rsa.key file; file-based keys are no longer used", "path", keyPath)
	}

	store := NewPeerStore()
	if cachePath != "" {
		if loadErr := store.LoadFromFile(cachePath); loadErr != nil {
			logger.Warn("failed to load peer cache file", "path", cachePath, "error", loadErr)
		} else {
			logger.Info("loaded peer cache", "peers", store.Len(), "path", cachePath)
		}
	}

	crawler := NewActiveCrawler(store)
	prober := NewProber(store, 48)
	server := NewReseedServer(ServerConfig{
		NetworkID:     uint8(*netID),
		ListenAddress: *listenAddr,
		CacheDuration: *interval,
		SignerID:      *signerID,
	}, store)

	// Load persistent SU3 archive if present for immediate availability across restarts
	if su3Data, readErr := os.ReadFile(su3Path); readErr == nil && len(su3Data) > 0 {
		sum := sha256.Sum256(su3Data)
		etag := `"` + hex.EncodeToString(sum[:8]) + `"`
		server.UpdatePackage(ReseedPackage{
			GeneratedAt: time.Now(),
			PeerCount:   store.Len(),
			SU3Data:     su3Data,
			ETag:        etag,
		})
		logger.Info("loaded persistent reseed archive for immediate serving",
			"path", su3Path,
			"su3_bytes", len(su3Data),
		)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Bind the HTTP listeners before RSA keygen, router bootstrap, and the
	// initial crawl pass so /health answers while startup work is running.
	var httpServers []*http.Server
	if !*runOnce {
		for _, raw := range strings.Split(*listenAddr, ",") {
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
	}

	rsaPrivKey, err := initSigningKey(*seedPhrase, logger)
	if err != nil {
		logger.Error("failed to initialize RSA signing key", "error", err)
		return 1
	}

	certPEM, pubKeyPEM, err := initReseedMaterial(certPath, pubKeyPath, *signerID, rsaPrivKey, logger)
	if err != nil {
		logger.Error("failed to initialize reseed certificate", "error", err)
		return 1
	}
	server.SetSigningMaterial(certPEM, pubKeyPEM)

	logger.Info("initialized signing keys",
		"su3_signer", *signerID,
		"cert_path", certPath,
	)

	var routerSubsystem *node.Subsystem
	if !*noRouter {
		logger.Info("starting embedded IVNP router in floodfill mode (tainted state)...")
		routerCfg := configureActiveClientRouter(*dataDir, *tempDir, uint8(*netID), *routerPort)
		subsystem, routerErr := node.NewSubsystem(routerCfg, node.Options{Logger: logger, TaintedCopy: true})
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

	activeCrawlPass := func(crawlCtx context.Context) {
		if routerSubsystem != nil {
			harvested := crawler.Harvest(routerSubsystem)
			if harvested > 0 {
				logger.Info("active crawl: harvested new peers from embedded NetDB",
					"newly_admitted", harvested,
					"total_store", store.Len(),
				)
			}
			reachable := store.ReachableCount()
			queryBudget := 48
			if reachable >= 1024 {
				queryBudget = 12
			}
			// Active DHT tree exploration to populate empty and sparse K-Buckets
			dispatched, exploreErr := crawler.TreeExplore(crawlCtx, routerSubsystem, queryBudget)
			if exploreErr != nil && !errors.Is(exploreErr, context.Canceled) {
				logger.Debug("tree exploration notice", "error", exploreErr)
			} else if dispatched > 0 {
				logger.Debug("active crawl: dispatched tree exploration lookups", "dispatched", dispatched, "budget", queryBudget)
			}

			_ = routerSubsystem.TriggerTunnelProbe(crawlCtx)
			if store.Len() < 150 {
				_, _ = routerSubsystem.TriggerReseed(crawlCtx)
			}
		}

		if store.Len() > 0 {
			success := prober.ProbeAll(crawlCtx)
			if success > 0 {
				logger.Debug("active crawl: probing pass completed", "reachable_peers", success)
			}
		}
	}

	refreshPass := func(refreshCtx context.Context) error {
		start := time.Now()

		activeCrawlPass(refreshCtx)

		if evicted := store.PruneRedundant(); evicted > 0 {
			logger.Info("evicted redundant peers dominated in subnet/family contests",
				"evicted", evicted,
				"store_total", store.Len(),
			)
		}

		// 2. Save peer cache
		if cachePath != "" {
			if saveErr := store.SaveToFile(cachePath); saveErr != nil {
				logger.Warn("failed to save peer cache", "error", saveErr)
			}
		}

		// 3. Select diverse, accessible Floodfills and high-performance routers
		reachableCount := store.ReachableCount()
		selectorCfg := DefaultSelectorConfig()
		selectorCfg.TargetCount = *targetPeers
		// If directly reachable peer count > 256, strictly include only directly reachable peers
		// (no artificial padding with dead/unverified nodes up to 1024).
		// If <= 256 (cold-start), allow candidates to bootstrap.
		selectorCfg.RequireReachable = (reachableCount > 256)
		selected := SelectDiversePeers(store.Snapshot(), selectorCfg)

		logger.Info("selected diverse peers",
			"target", *targetPeers,
			"selected", len(selected),
			"reachable_in_store", reachableCount,
			"require_reachable", selectorCfg.RequireReachable,
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

			if writeErr := writeFileAtomic(su3Path, su3Bytes, 0644); writeErr != nil {
				logger.Warn("failed to persist SU3 archive", "path", su3Path, "error", writeErr)
			}

			sum := sha256.Sum256(su3Bytes)
			etag := `"` + hex.EncodeToString(sum[:8]) + `"`
			pkgStats := CalculatePackageStats(selected, len(su3Bytes), etag, now, selectorCfg.RequireReachable)
			server.UpdatePackage(ReseedPackage{
				GeneratedAt:    now,
				PeerCount:      len(selected),
				FloodfillCount: floodCount,
				SU3Data:        su3Bytes,
				ETag:           etag,
				Stats:          pkgStats,
			})

			logger.Info("reseed archives packaged",
				"peers", len(selected),
				"floodfills", floodCount,
				"floodfill_ratio", fmt.Sprintf("%.1f%%", pkgStats.FloodfillRatio*100),
				"dual_stack", pkgStats.DualStackCount,
				"ipv4_only", pkgStats.IPv4OnlyCount,
				"avg_availability", fmt.Sprintf("%.1f%%", pkgStats.AverageAvailability*100),
				"avg_rtt_ms", pkgStats.RTT.AvgMs,
				"su3_bytes", len(su3Bytes),
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

	packageTicker := time.NewTicker(*interval)
	defer packageTicker.Stop()

	crawlTicker := time.NewTicker(4 * time.Second)
	defer crawlTicker.Stop()

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
		case <-crawlTicker.C:
			activeCrawlPass(ctx)
		case <-packageTicker.C:
			if err := refreshPass(ctx); err != nil {
				logger.Error("periodic refresh pass failed", "error", err)
			}
		}
	}
}

func configureActiveClientRouter(baseDir, tempDir string, netID uint8, routerPort int) state.ConfigurationOperating {
	cfg := state.ConfigurationDefaultOperating()
	cfg.DataDir = filepath.Join(baseDir, "router")
	cfg.StateDir = filepath.Join(cfg.DataDir, "state")
	cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
	cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
	if tempDir != "" {
		cfg.TempDir = tempDir
	}
	cfg.State.TaintedCopy = true
	cfg.Network.ID = uint32(netID)
	cfg.Router.Floodfill = true // Operate as Floodfill router by default to participate in NetDB replication

	port := uint16(0)
	if routerPort > 0 && routerPort <= 65535 {
		port = uint16(routerPort)
	}

	cfg.NTCP2.Enabled = true
	cfg.NTCP2.Bind = state.ConfigurationEndpoint{Host: "0.0.0.0", Port: port}
	cfg.NTCP2.Advertised = state.ConfigurationEndpoint{}
	cfg.SSU2.Enabled = true
	cfg.SSU2.Bind = state.ConfigurationEndpoint{Host: "0.0.0.0", Port: port}
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

	// Scale exploratory tunnel pool and lookup capacity for active DHT crawling
	cfg.Tunnel.ExploratoryInboundTarget = 12
	cfg.Tunnel.ExploratoryOutboundTarget = 12
	cfg.Tunnel.ExploratoryPoolCapacity = 32
	cfg.Tunnel.BuildPendingCapacity = 128
	cfg.Tunnel.MaintenanceInterval = 10 * time.Second

	// Expand NetDB capacity for deep network exploration
	cfg.NetDB.BucketCapacity = 128
	cfg.NetDB.LookupCapacity = 128

	return cfg
}

func normalizeSeedPhrase(phrase string) (string, error) {
	normalized := strings.Join(strings.Fields(phrase), " ")
	if normalized == "" {
		return "", errEmptySeedPhrase
	}
	return normalized, nil
}

// deriveSigningKeyFromSeedPhrase turns a seed phrase into a deterministic
// RSA-4096 key: HKDF-SHA512 expands the phrase into the key-generation
// secret, then keygen.RSA runs the c2sp.org/det-keygen procedure (internal
// HMAC_DRBG per NIST SP 800-90A), so the same phrase always reproduces the
// same key. rsa.GenerateKey cannot be used: since Go 1.26 it ignores custom
// readers and always uses crypto/rand.
func deriveSigningKeyFromSeedPhrase(phrase string) (*rsa.PrivateKey, error) {
	normalized, err := normalizeSeedPhrase(phrase)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha512.New, []byte(normalized), []byte("ivnp-reseed"), []byte("reseed-rsa-4096")), secret); err != nil {
		return nil, fmt.Errorf("expand seed phrase: %w", err)
	}
	defer clear(secret)
	key, err := keygen.RSA(4096, secret)
	if err != nil {
		return nil, fmt.Errorf("derive key from seed phrase: %w", err)
	}
	return key, nil
}

// initSigningKey derives the RSA-4096 signing key from the seed phrase, or
// generates an ephemeral one when no phrase is configured. Key files are
// never read or written: the seed phrase is the only backup.
func initSigningKey(seedPhrase string, logger *slog.Logger) (*rsa.PrivateKey, error) {
	if seedPhrase != "" {
		return deriveSigningKeyFromSeedPhrase(seedPhrase)
	}
	logger.Warn("RESEED_SEED_PHRASE not set; generating ephemeral signing key that changes on restart")
	return rsa.GenerateKey(rand.Reader, 4096)
}

func generateSelfSignedCertificate(signerID string, privKey *rsa.PrivateKey) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   signerID,
			Organization: []string{"I2P Anonymous Network"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return certPEM, nil
}

// initReseedMaterial generates a fresh self-signed certificate for the
// in-memory signing key and publishes the public artifacts for operators.
// Certificates are never loaded back: the seed phrase (or ephemeral key)
// fully determines the signer identity.
func initReseedMaterial(certPath string, pubKeyPath string, signerID string, privKey *rsa.PrivateKey, logger *slog.Logger) ([]byte, []byte, error) {
	certPEM, err := generateSelfSignedCertificate(signerID, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate reseed certificate: %w", err)
	}
	if certPath != "" {
		if writeErr := writeFileAtomic(certPath, certPEM, 0644); writeErr != nil {
			logger.Warn("failed to persist reseed certificate", "path", certPath, "error", writeErr)
		}
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	if pubKeyPath != "" {
		if writeErr := writeFileAtomic(pubKeyPath, pubKeyPEM, 0644); writeErr != nil {
			logger.Warn("failed to persist reseed public key", "path", pubKeyPath, "error", writeErr)
		}
	}

	return certPEM, pubKeyPEM, nil
}

// writeFileAtomic stages data under "<path>.tmp" then renames it over path so
// readers never observe a partially written state file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// removeStaleTempFile deletes a leftover "<statePath>.tmp" from a write
// interrupted before its rename completed.
func removeStaleTempFile(statePath string, logger *slog.Logger) {
	tmpPath := statePath + ".tmp"
	if err := os.Remove(tmpPath); err == nil {
		logger.Warn("removed stale temporary state file left by interrupted write", "path", tmpPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Warn("failed to remove stale temporary state file", "path", tmpPath, "error", err)
	}
}
