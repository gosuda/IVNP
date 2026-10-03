//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gosuda.org/ivnp/state"
)

func registerConfigReloadSignal(configPath string, level *slog.LevelVar, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			logger.Info("reloading configuration", "path", configPath)
			reloaded, err := state.ConfigurationLoadOperating(configPath)
			if err != nil {
				logger.Error("failed to reload configuration", "error", err)
				continue
			}
			if reloaded.Log.Level != "" && level != nil {
				setLoggerLevel(level, reloaded.Log.Level)
				logger.Info("log level updated", "level", reloaded.Log.Level)
			}
		}
	}()
}
