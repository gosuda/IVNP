// Command ivnpd starts an embedded IVNP router daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gosuda.org/ivnp/node"
	"gosuda.org/ivnp/state"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ivnpd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "ivnp.conf", "operating configuration path")
	webUIEnabled := flags.Bool("webui", true, "enable the embedded WebUI")
	webUIListen := flags.String("webui-listen", defaultWebUIListenAddress, "WebUI listen address")
	webUIAuth := flags.Bool("webui-auth", true, "require authentication for non-loopback WebUI access")
	webUIToken := flags.String("webui-token", "", "WebUI bearer token (overrides IVNPD_WEBUI_TOKEN)")
	httpProxyEnabled := flags.Bool("http-proxy", true, "enable local HTTP outproxy (default :4444)")
	socks5Enabled := flags.Bool("socks5", false, "enable local SOCKS5 proxy (default :4447)")
	dataDir := flags.String("data-dir", "", "override data directory")
	logLevel := flags.String("log-level", "", "override log level (debug, info, warn, error)")
	logFormat := flags.String("log-format", "", "override log format (text, json)")
	testConfig := flags.Bool("test-config", false, "validate configuration and exit")
	memoryMode := flags.Bool("memory", false, "run entirely in memory without writing or reading disk state")
	pidFile := flags.String("pidfile", "", "path to write process ID file")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "ivnpd: unexpected positional arguments")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	var cfg state.ConfigurationOperating
	var err error
	if *memoryMode {
		configSpecified := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				configSpecified = true
			}
		})
		if configSpecified {
			cfg, err = state.ConfigurationLoadOperating(*configPath)
			if err != nil {
				fmt.Fprintln(stderr, "ivnpd: configuration error:", err)
				return 1
			}
		} else {
			cfg = state.ConfigurationDefaultOperating()
		}
	} else if *testConfig {
		cfg, err = state.ConfigurationLoadOperating(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, "ivnpd: configuration error:", err)
			return 1
		}
	} else {
		cfg, err = state.ConfigurationLoadOrCreateOperating(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, "ivnpd: configuration error:", err)
			return 1
		}
	}
	applyConfigOverrides(&cfg, *dataDir, *logLevel, *logFormat, *httpProxyEnabled, *socks5Enabled)
	if *memoryMode {
		clearStoragePaths(&cfg)
	}
	if *testConfig {
		fmt.Fprintln(stdout, "ivnpd: configuration is valid")
		return 0
	}

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			fmt.Fprintf(stderr, "ivnpd: cannot write pidfile: %v\n", err)
			return 1
		}
		defer func() { _ = os.Remove(*pidFile) }()
	}

	logger, level := newLogger(cfg.Log, stderr)
	if !*memoryMode {
		registerConfigReloadSignal(*configPath, level, logger)
	}

	d, err := node.NewSubsystem(cfg, node.Options{Logger: logger, Embedded: *memoryMode})
	if err != nil {
		logger.Error("daemon initialization failed", "error", err)
		return 1
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			logger.Error("daemon cleanup failed", "error", closeErr)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := d.Start(ctx); err != nil {
		logger.Error("daemon startup failed", "error", err)
		return 1
	}
	if *webUIEnabled {
		webUIHost, _, _ := net.SplitHostPort(*webUIListen)
		token := *webUIToken
		if token == "" && !isLoopbackHost(webUIHost) {
			token = os.Getenv("IVNPD_WEBUI_TOKEN")
		}
		webUIConfigPath := *configPath
		if *memoryMode {
			webUIConfigPath = ""
		}
		webUI, webErr := NewWebUIServer(WebUIConfig{
			ListenAddress: *webUIListen,
			BearerToken:   token,
			DisableAuth:   !*webUIAuth,
			ConfigPath:    webUIConfigPath,
		}, d, logger, level)
		if webErr != nil {
			logger.Error("WebUI configuration failed", "error", webErr)
			return 1
		}
		if webErr = webUI.Start(ctx); webErr != nil {
			logger.Error("WebUI startup failed", "error", webErr)
			return 1
		}
		defer func() {
			if closeErr := webUI.Close(); closeErr != nil {
				logger.Error("WebUI cleanup failed", "error", closeErr)
			}
		}()
	}
	if err := d.Wait(); err != nil {
		logger.Error("daemon stopped with error", "error", err)
		return 1
	}
	return 0
}

func applyConfigOverrides(cfg *state.ConfigurationOperating, dataDir, logLevel, logFormat string, httpProxy, socks5 bool) {
	if dataDir != "" {
		cfg.DataDir = dataDir
		cfg.StateDir = filepath.Join(dataDir, "state")
		cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
		cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
		if cfg.AddressBook.StatePath != "" {
			cfg.AddressBook.StatePath = filepath.Join(cfg.StateDir, "addressbook.json")
		}
	}
	if logLevel != "" {
		cfg.Log.Level = strings.ToLower(logLevel)
	}
	if logFormat != "" {
		cfg.Log.Format = strings.ToLower(logFormat)
	}
	if httpProxy {
		cfg.HTTPProxy.Enabled = true
	}
	if socks5 {
		cfg.SOCKS5.Enabled = true
	}
}

func clearStoragePaths(cfg *state.ConfigurationOperating) {
	cfg.DataDir = ""
	cfg.StateDir = ""
	cfg.StatePath = ""
	cfg.KeyPath = ""
	cfg.AddressBook.PrivateHostsPath = ""
	cfg.AddressBook.UserHostsPath = ""
	cfg.AddressBook.HostsPath = ""
	cfg.AddressBook.StatePath = ""
	cfg.NetDB.BootstrapRouterInfoPaths = nil
}

func setLoggerLevel(level *slog.LevelVar, levelName string) {
	switch strings.ToLower(levelName) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
}

func newLogger(cfg state.ConfigurationLog, output io.Writer) (*slog.Logger, *slog.LevelVar) {
	level := new(slog.LevelVar)
	setLoggerLevel(level, cfg.Level)
	options := &slog.HandlerOptions{Level: level}
	var logger *slog.Logger
	if cfg.Format == "json" {
		logger = slog.New(slog.NewJSONHandler(output, options))
	} else {
		logger = slog.New(slog.NewTextHandler(output, options))
	}
	return logger, level
}
