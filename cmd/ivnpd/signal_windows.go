//go:build windows

package main

import (
	"log/slog"
)

func registerConfigReloadSignal(_ string, _ *slog.LevelVar, _ *slog.Logger) {
	// SIGHUP is not supported on Windows.
}
