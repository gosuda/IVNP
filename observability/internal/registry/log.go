// Package observability provides bounded, secret-safe logging, metrics, and
// status endpoints for IVNP processes.
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

// LogConfig controls a structured logger. Empty Format and Level use secure,
// operator-friendly text and info defaults. A nil Output writes to stderr.
type LogConfig struct {
	Format string
	Level  string
	Output io.Writer
}

// NewLogger constructs a structured logger using only text or JSON output and
// the four standard severity levels.
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

// ParseLogLevel validates and parses a standard slog severity level.
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

// Redacted is the fixed replacement used for values that must not reach logs.
const Redacted = "[REDACTED]"

// Secret returns an attribute whose value is always redacted. Any supplied
// values are intentionally discarded before logging.
func Secret(key string, _ ...any) slog.Attr {
	return slog.String(key, Redacted)
}

// SecretBytes returns an attribute whose byte value is always redacted.
func SecretBytes(key string, _ []byte) slog.Attr {
	return slog.String(key, Redacted)
}

// SafeError returns a redacted attribute when err is non-nil. It permits
// callers to record that an error occurred without logging its raw text.
func SafeError(key string, err error) slog.Attr {
	if err == nil {
		return slog.String(key, "")
	}
	return slog.String(key, Redacted)
}
