// Package registry provides logging, metric collectors, and HTTP health check handlers.
package registry

import (
	"cmp"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

var (
	ErrInvalidLogFormat = errors.New("observability: invalid log format")
	ErrInvalidLogLevel  = errors.New("observability: invalid log level")
)

// LogConfig controls structured logger formatting and output destination.
type LogConfig struct {
	Format string
	Level  string
	Output io.Writer
}

// NewLogger creates a structured slog.Logger for text or JSON output.
func NewLogger(config LogConfig) (*slog.Logger, error) {
	format := config.Format

	format = cmp.Or(format, "text")

	level := config.Level

	level = cmp.Or(level, "info")

	parsedLevel, err := ParseLogLevel(level)
	if err != nil {
		return nil, err
	}
	output := config.Output
	if output == nil {
		output = os.Stderr

	}
	options := &slog.HandlerOptions{Level: parsedLevel}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text":
		return slog.New(slog.NewTextHandler(output, options)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(output, options)), nil
	default:
		return nil, ErrInvalidLogFormat
	}
}

// ParseLogLevel parses string log levels ("debug", "info", "warn", "error").
func ParseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, ErrInvalidLogLevel
	}
}

// Redacted is the placeholder string used for sensitive values in logs.
const Redacted = "[REDACTED]"

// Secret returns a log attribute whose value is always replaced with Redacted.
func Secret(key string, _ ...any) slog.Attr {
	return slog.String(key, Redacted)
}

// SecretBytes returns a log attribute for byte slices whose value is always replaced with Redacted.
func SecretBytes(key string, _ []byte) slog.Attr {
	return slog.String(key, Redacted)
}

// SafeError returns an attribute marking an error as redacted if non-nil.
func SafeError(key string, err error) slog.Attr {
	if err == nil {
		return slog.String(key, "")
	}
	return slog.String(key, Redacted)
}
