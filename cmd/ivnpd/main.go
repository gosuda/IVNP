// Command ivnpd starts an embedded IVNP router daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gosuda.org/ivnp"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ivnpd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "ivnp.conf", "operating configuration path")
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
	cfg, err := ivnp.LoadOrCreateConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ivnpd: configuration error:", err)
		return 1
	}
	logger := newLogger(cfg.Log, stderr)
	d, err := ivnp.New(cfg, ivnp.Options{Logger: logger})
	if err != nil {
		logger.Error("daemon initialization failed", "error", err)
		return 1
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := d.Start(ctx); err != nil {
		logger.Error("daemon startup failed", "error", err)
		return 1
	}
	if err := d.Wait(); err != nil {
		logger.Error("daemon stopped with error", "error", err)
		return 1
	}
	return 0
}

func newLogger(cfg ivnp.LogConfig, output io.Writer) *slog.Logger {
	level := new(slog.LevelVar)
	switch cfg.Level {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	options := &slog.HandlerOptions{Level: level}
	if cfg.Format == "json" {
		return slog.New(slog.NewJSONHandler(output, options))
	}
	return slog.New(slog.NewTextHandler(output, options))
}
