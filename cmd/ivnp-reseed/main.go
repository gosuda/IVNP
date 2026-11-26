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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/keygen"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

var version = "active-dev"

var (
	errEmptySeedPhrase          = errors.New("seed phrase is empty after normalization")
	errSeedPhraseTooShort       = fmt.Errorf("seed phrase must be at least %d characters for %s", minArgon2idSeedPhraseLen, seedKDFArgon2id)
	errUnknownSeedKDF           = errors.New("unknown seed KDF")
	errAdvertiseHostNeedsPort   = errors.New("-router-advertise-host requires -router-port")
	errAdvertisePortOutOfRange  = errors.New("-router-advertise-port must be between 1 and 65535")
	errAdvertiseHostnameTooLong = errors.New("hostname longer than 255 characters")
)

// seedPhraseEnv names the environment variable that carries the signing
// seed phrase. It is read only after flag parsing and then removed from the
// process environment, so usage output and child processes never see it.
const seedPhraseEnv = "RESEED_SEED_PHRASE"

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
	minBundlePeers := flags.Int("min-bundle-peers", 10, "minimum qualified peers required to publish a new epoch bundle; below this the previous bundle keeps serving")
	minProbeRate := flags.Float64("min-probe-rate", 0.85, "minimum probe success rate for the strict qualification gate (0-1)")
	interval := flags.Duration("interval", 10*time.Minute, "refresh interval for harvesting, probing, and packaging")
	netID := flags.Uint("netid", 2, "I2P network ID")
	signerID := flags.String("signer-id", envOr("RESEED_SIGNER_ID", "reseed@ivnp.network"), "SU3 signer common name (env RESEED_SIGNER_ID)")
	seedPhraseFlag := flags.String("seed-phrase", "", "deterministic RSA-4096 signing key seed phrase; prefer env "+seedPhraseEnv+" so the phrase stays out of process arguments")
	routerPort := flags.Int("router-port", 0, "port for embedded router NTCP2/SSU2 transports (default 0 for random/ephemeral)")
	routerAdvertiseHost := flags.String("router-advertise-host", envOr("RESEED_ROUTER_ADVERTISE_HOST", ""), "public host or IP advertised in the embedded router's info for inbound connections (requires -router-port; empty keeps the router firewalled)")
	seedKDFName := flags.String("seed-kdf", envOr("RESEED_SEED_KDF", string(seedKDFHKDF)), "seed phrase key derivation: "+string(seedKDFHKDF)+" (legacy, unstretched) or "+string(seedKDFArgon2id)+" (stretched, salted with -signer-id); changing it changes the signing key (env RESEED_SEED_KDF)")
	routerAdvertisePort := flags.Int("router-advertise-port", 0, "public port advertised when it differs from -router-port, e.g. NAT port forwarding (default: same as -router-port)")
	noRouter := flags.Bool("no-router", false, "disable embedded router (test/replay mode)")
	pprofAddr := flags.String("pprof", "", "serve net/http/pprof endpoints on this address (e.g. 127.0.0.1:6060); disabled when empty")
	healthCheckURL := flags.String("healthcheck", "", "check health endpoint URL and exit 0 (healthy) or 1 (unhealthy)")
	runOnce := flags.Bool("once", false, "run one pass and exit")
	showVersion := flags.Bool("version", false, "show version and exit")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	seedPhrase := resolveSeedPhrase(*seedPhraseFlag)
	kdf, err := parseSeedKDF(*seedKDFName)
	if err != nil {
		fmt.Fprintf(stderr, "invalid -seed-kdf: %v\n", err)
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
	if *pprofAddr != "" {
		if err := validatePprofAddr(*pprofAddr); err != nil {
			fmt.Fprintln(stderr, "ivnp-reseed:", err)
			return 2
		}
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
	prober := NewProber(store, 16)
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
		peerCount, floodCount, inspectErr := InspectSU3Archive(su3Data)
		if inspectErr != nil {
			logger.Warn("failed to parse existing SU3 archive metadata", "path", su3Path, "error", inspectErr)
		}
		server.UpdatePackage(ReseedPackage{
			GeneratedAt:    time.Now(),
			PeerCount:      peerCount,
			FloodfillCount: floodCount,
			SU3Data:        su3Data,
			ETag:           etag,
		})
		logger.Info("loaded persistent reseed archive for immediate serving",
			"path", su3Path,
			"su3_bytes", len(su3Data),
			"peers", peerCount,
			"floodfills", floodCount,
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
			srv := newPublicHTTPServer(addr, server)
			httpServers = append(httpServers, srv)
			go func(s *http.Server) {
				logger.Info("starting reseed HTTP server", "listen", s.Addr)
				if srvErr := s.ListenAndServe(); srvErr != nil && srvErr != http.ErrServerClosed {
					logger.Error("HTTP server failed", "listen", s.Addr, "error", srvErr)
				}
			}(srv)
		}
	}

	rsaPrivKey, err := initSigningKey(seedPhrase, kdf, *signerID, logger)
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
		advertisedHost, advertisedPort, advErr := resolveAdvertisedEndpoint(*routerAdvertiseHost, *routerAdvertisePort, *routerPort, logger)
		if advErr != nil {
			logger.Error("invalid advertised endpoint", "error", advErr)
			return 2
		}
		routerCfg := configureActiveClientRouter(*dataDir, *tempDir, uint8(*netID), *routerPort, advertisedHost, advertisedPort)
		subsystem, routerErr := node.NewSubsystem(routerCfg, node.Options{
			Logger:                    logger,
			TaintedCopy:               true,
			DisableClientDestinations: true,
			RouterLimit:               MaxStorePeers,
		})
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
		clientStatus, statusErr := subsystem.ClientStatus(ctx)
		if statusErr != nil {
			logger.Warn("failed to read embedded router status", "error", statusErr)
		}
		logger.Info("embedded router started successfully", "router_hash", clientStatus.RouterHash)
	}

	var probeRunning atomic.Int32
	var initialPassDone atomic.Int32
	var probeWG sync.WaitGroup
	triggerProbePass := func(probeCtx context.Context) {
		if store.Len() == 0 {
			return
		}
		if *runOnce {
			if success := prober.ProbeAll(probeCtx); success > 0 {
				logger.Debug("active crawl: probing pass completed", "reachable_peers", success)
			}
			return
		}
		if initialPassDone.CompareAndSwap(0, 1) {
			if success := prober.ProbeBatch(probeCtx, maxProbesPerPass); success > 0 {
				logger.Debug("active crawl: initial probing pass completed", "reachable_peers", success)
			}
			return
		}
		if !probeRunning.CompareAndSwap(0, 1) {
			return
		}
		probeWG.Go(func() {
			defer probeRunning.Store(0)
			if success := prober.ProbeBatch(probeCtx, maxProbesPerPass); success > 0 {
				logger.Debug("active crawl: probing pass completed", "reachable_peers", success)
			}
		})
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
			maxBudget := DefaultExploreBudgetExpansion
			if reachable >= 1024 {
				maxBudget = DefaultExploreBudgetMaintenance
			}
			queryBudget := crawler.DynamicExplorationBudget(maxBudget)
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

		triggerProbePass(crawlCtx)
	}

	refreshPass := func(refreshCtx context.Context) error {
		start := time.Now()

		activeCrawlPass(refreshCtx)

		if evicted := store.PruneRedundant(); evicted > 0 {
			logger.Info("evicted redundant peers dominated in subnet contests",
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
		selectorCfg.MinBundlePeers = *minBundlePeers
		selectorCfg.MinProbeSuccessRate = *minProbeRate
		selected, selStats := SelectDiversePeersWithStats(store.Snapshot(), selectorCfg)

		logger.Info("selected diverse peers",
			"target", *targetPeers,
			"selected", len(selected),
			"reachable_in_store", reachableCount,
			"min_bundle_peers", *minBundlePeers,
		)

		if len(selected) >= *minBundlePeers {
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
			pkgStats := CalculatePackageStats(selected, len(su3Bytes), etag, now, selStats)
			pkgStats.EpochStartedAt = now.Truncate(*interval)
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

	var pprofServer *http.Server
	if *pprofAddr != "" {
		pprofServer = newPprofServer(*pprofAddr)
		go func() {
			logger.Info("starting pprof server", "listen", *pprofAddr)
			if srvErr := servePprof(pprofServer); srvErr != nil && srvErr != http.ErrServerClosed {
				logger.Error("pprof server failed", "listen", *pprofAddr, "error", srvErr)
			}
		}()
	}

	// Epoch-aligned packaging: bundle builds fire on fixed wall-clock
	// boundaries so every downloader in an epoch receives identical bytes.
	epochTimer := time.NewTimer(time.Until(nextEpochBoundary(time.Now(), *interval)))
	defer epochTimer.Stop()

	crawlTicker := time.NewTicker(4 * time.Second)
	defer crawlTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down reseed server...")
			probeWG.Wait()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			for _, s := range httpServers {
				_ = s.Shutdown(shutdownCtx)
			}
			if pprofServer != nil {
				_ = pprofServer.Shutdown(shutdownCtx)
			}
			shutdownCancel()
			return 0
		case <-crawlTicker.C:
			activeCrawlPass(ctx)
		case <-epochTimer.C:
			if err := refreshPass(ctx); err != nil {
				logger.Error("periodic refresh pass failed", "error", err)
			}
			epochTimer.Reset(time.Until(nextEpochBoundary(time.Now(), *interval)))
		}
	}
}

// Public reseed listener bounds. Every request is a small GET, so headers and
// bodies arrive quickly; the write budget covers an SU3 download to a slow
// client, and idle keep-alive connections are reclaimed.
const (
	publicReadHeaderTimeout = 10 * time.Second
	publicReadTimeout       = 30 * time.Second
	publicWriteTimeout      = 60 * time.Second
	publicIdleTimeout       = 120 * time.Second
	publicMaxHeaderBytes    = 16 << 10
)

// newPublicHTTPServer builds an internet-facing reseed listener whose read,
// write, and idle deadlines and header size limit stop slow or oversized
// clients from pinning connections and goroutines indefinitely.
func newPublicHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: publicReadHeaderTimeout,
		ReadTimeout:       publicReadTimeout,
		WriteTimeout:      publicWriteTimeout,
		IdleTimeout:       publicIdleTimeout,
		MaxHeaderBytes:    publicMaxHeaderBytes,
	}
}

// nextEpochBoundary returns the next wall-clock multiple of interval so bundle
// epochs align to fixed clock boundaries (e.g. :00, :10, :20 for 10m).
func nextEpochBoundary(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return now.Truncate(interval).Add(interval)
}

// resolveAdvertisedEndpoint validates the router advertise flags and fills in
// defaults: the advertised port falls back to the router port (the common 1:1 NAT
// case), and an empty advertised host disables address advertisement entirely so
// the router stays firewalled/automatic.
func resolveAdvertisedEndpoint(host string, advertisedPort, routerPort int, logger *slog.Logger) (string, int, error) {
	if host == "" {
		if advertisedPort != 0 {
			logger.Warn("-router-advertise-port ignored: -router-advertise-host is not set")
		}
		return "", 0, nil
	}
	if routerPort <= 0 {
		return "", 0, errAdvertiseHostNeedsPort
	}
	if err := validateAdvertisedHost(host); err != nil {
		return "", 0, fmt.Errorf("invalid -router-advertise-host %q: %w", host, err)
	}
	port := routerPort
	if advertisedPort != 0 {
		if advertisedPort < 1 || advertisedPort > 65535 {
			return "", 0, errAdvertisePortOutOfRange
		}
		port = advertisedPort
	}
	return host, port, nil
}

// validateAdvertisedHost accepts an IP address or an RFC 1123 hostname, the two
// address forms I2P RouterInfos may publish.
func validateAdvertisedHost(host string) error {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 255 {
		return errAdvertiseHostnameTooLong
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid hostname label %q", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname label %q must not start or end with '-'", label)
		}
		for _, r := range label {
			if !isHostnameLabelChar(r) {
				return fmt.Errorf("hostname label %q contains invalid character %q", label, r)
			}
		}
	}
	return nil
}

// isHostnameLabelChar reports whether r is allowed in an RFC 1123 hostname label.
func isHostnameLabelChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
}

func configureActiveClientRouter(baseDir, tempDir string, netID uint8, routerPort int, advertisedHost string, advertisedPort int) state.ConfigurationOperating {
	cfg := state.ConfigurationDefaultOperating()
	cfg.DataDir = filepath.Join(baseDir, "router")
	cfg.StateDir = filepath.Join(cfg.DataDir, "state")
	cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
	cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
	if tempDir != "" {
		cfg.TempDir = tempDir
	}
	cfg.State.TaintedCopy = true
	cfg.State.MaxDestinations = 1
	cfg.Network.ID = uint32(netID)
	cfg.Router.Floodfill = true // Operate as Floodfill router by default to participate in NetDB replication
	cfg.Router.Transit = false  // Do not relay third-party transit tunnels on the reseed crawler

	port := uint16(0)
	if routerPort > 0 && routerPort <= 65535 {
		port = uint16(routerPort)
	}

	// Advertise a fixed public host/port so remote routers can establish inbound
	// transport connections; without it the router publishes a firewalled RouterInfo
	// with no address when UPnP/NAT-PMP are unavailable (i.e. any NAT'd host whose
	// gateway cannot map ports automatically).
	// The advertised port may differ from the bound port behind NAT port forwarding.
	advertised := state.ConfigurationEndpoint{}
	if advertisedHost != "" && port > 0 {
		advertised = state.ConfigurationEndpoint{Host: advertisedHost, Port: uint16(advertisedPort)}
	}

	cfg.NTCP2.Enabled = true
	cfg.NTCP2.Bind = state.ConfigurationEndpoint{Host: "0.0.0.0", Port: port}
	cfg.NTCP2.Advertised = advertised
	cfg.SSU2.Enabled = true
	cfg.SSU2.Bind = state.ConfigurationEndpoint{Host: "0.0.0.0", Port: port}
	cfg.SSU2.Advertised = advertised
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
	cfg.Tunnel.ExploratoryInboundTarget = 6
	cfg.Tunnel.ExploratoryOutboundTarget = 6
	cfg.Tunnel.ExploratoryPoolCapacity = 16
	cfg.Tunnel.BuildPendingCapacity = 48
	cfg.Tunnel.MaintenanceInterval = 10 * time.Second

	// Bound NetDB capacity to match PeerStore retention limits
	cfg.NetDB.BucketCapacity = 32
	cfg.NetDB.LookupCapacity = 48

	return cfg
}

// resolveSeedPhrase returns the -seed-phrase flag value, or the
// RESEED_SEED_PHRASE environment value when the flag is empty, and removes
// the environment variable either way. The phrase is never a flag default, so
// flag usage and error output cannot print it.
func resolveSeedPhrase(flagValue string) string {
	envValue := os.Getenv(seedPhraseEnv)
	_ = os.Unsetenv(seedPhraseEnv)
	return cmp.Or(flagValue, envValue)
}

func normalizeSeedPhrase(phrase string) (string, error) {
	normalized := strings.Join(strings.Fields(phrase), " ")
	if normalized == "" {
		return "", errEmptySeedPhrase
	}
	return normalized, nil
}

// seedKDF names a versioned seed phrase derivation. Each version fixes its
// algorithm and parameters: changing either changes the derived signing key
// and therefore the published reseed certificate.
type seedKDF string

const (
	// seedKDFHKDF is the original, unstretched HKDF-SHA512 derivation with a
	// global salt. It stays the default so existing signer identities persist.
	seedKDFHKDF seedKDF = "hkdf-sha512"
	// seedKDFArgon2id stretches the phrase with Argon2id, salted with the
	// signer ID, so each guess against a published certificate costs memory
	// and time and precomputed tables do not carry across deployments.
	seedKDFArgon2id seedKDF = "argon2id-v2"
)

// Argon2id parameters for seedKDFArgon2id (RFC 9106 section 4, second
// recommended option). They are part of the version and must never change.
const (
	argon2idSeedTime    = 3
	argon2idSeedMemory  = 64 * 1024 // KiB
	argon2idSeedThreads = 4
	argon2idSeedSalt    = "ivnp-reseed/argon2id-v2/signer:"

	// minArgon2idSeedPhraseLen is a length floor, not an entropy measurement:
	// a phrase of random characters this long (for example the output of
	// "openssl rand -base64 32") carries well over 128 bits.
	minArgon2idSeedPhraseLen = 32
)

func parseSeedKDF(name string) (seedKDF, error) {
	switch seedKDF(name) {
	case "", seedKDFHKDF:
		return seedKDFHKDF, nil
	case seedKDFArgon2id:
		return seedKDFArgon2id, nil
	}
	return "", fmt.Errorf("%w %q (want %s or %s)", errUnknownSeedKDF, name, seedKDFHKDF, seedKDFArgon2id)
}

// deriveSigningKeyFromSeedPhrase derives the key with the legacy default KDF.
func deriveSigningKeyFromSeedPhrase(phrase string) (*rsa.PrivateKey, error) {
	return deriveSigningKey(phrase, seedKDFHKDF, "")
}

// deriveSigningKey turns a seed phrase into a deterministic RSA-4096 key: the
// selected KDF expands the phrase into the key-generation secret, then
// keygen.RSA runs the c2sp.org/det-keygen procedure (internal HMAC_DRBG per
// NIST SP 800-90A), so the same inputs always reproduce the same key.
// rsa.GenerateKey cannot be used: since Go 1.26 it ignores custom readers and
// always uses crypto/rand. signerID salts only seedKDFArgon2id.
func deriveSigningKey(phrase string, kdf seedKDF, signerID string) (*rsa.PrivateKey, error) {
	normalized, err := normalizeSeedPhrase(phrase)
	if err != nil {
		return nil, err
	}
	var secret []byte
	switch kdf {
	case seedKDFHKDF:
		secret = make([]byte, 64)
		if _, err := io.ReadFull(hkdf.New(sha512.New, []byte(normalized), []byte("ivnp-reseed"), []byte("reseed-rsa-4096")), secret); err != nil {
			clear(secret)
			return nil, fmt.Errorf("expand seed phrase: %w", err)
		}
	case seedKDFArgon2id:
		if len(normalized) < minArgon2idSeedPhraseLen {
			return nil, errSeedPhraseTooShort
		}
		secret = argon2.IDKey([]byte(normalized), []byte(argon2idSeedSalt+signerID), argon2idSeedTime, argon2idSeedMemory, argon2idSeedThreads, 64)
	default:
		return nil, fmt.Errorf("%w %q", errUnknownSeedKDF, kdf)
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
func initSigningKey(seedPhrase string, kdf seedKDF, signerID string, logger *slog.Logger) (*rsa.PrivateKey, error) {
	if seedPhrase != "" {
		if kdf == seedKDFHKDF {
			logger.Warn("seed phrase uses the legacy unstretched "+string(seedKDFHKDF)+" derivation; a low-entropy phrase can be guessed offline from the published certificate",
				"migrate_to", string(seedKDFArgon2id),
				"min_phrase_chars", minArgon2idSeedPhraseLen,
			)
		}
		return deriveSigningKey(seedPhrase, kdf, signerID)
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

// writeFileAtomic stages data in an exclusively created, randomly named file
// in the same directory, then renames it over path so readers never observe a
// partially written state file and a planted symlink is never followed.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return state.FilesystemStoreWriteAtomic(path, data, perm, -1)
}

// removeStaleTempFile deletes a leftover "<statePath>.tmp" written by earlier
// releases, which staged atomic writes under that predictable name.
func removeStaleTempFile(statePath string, logger *slog.Logger) {
	tmpPath := statePath + ".tmp"
	if err := os.Remove(tmpPath); err == nil {
		logger.Warn("removed stale temporary state file left by interrupted write", "path", tmpPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Warn("failed to remove stale temporary state file", "path", tmpPath, "error", err)
	}
}
