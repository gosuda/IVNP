// Command ivnp starts an embedded IVNP router daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ivnp "gosuda.org/ivnp"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("ivnp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "ivnp.conf", "operating configuration path")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ivnp: unexpected positional arguments")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return 0
	}
	cfg, err := ivnp.LoadOrCreateConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ivnp: configuration error:", err)
		return 1
	}
	logger := newLogger(cfg.Log)
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

func newLogger(cfg ivnp.LogConfig) *slog.Logger {
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
		return slog.New(slog.NewJSONHandler(os.Stderr, options))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, options))
}
