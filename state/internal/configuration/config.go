// Package config parses bounded i2pd-style INI configuration files.
package configuration

import (
	"errors"
	"strings"
)

const (
	maxConfigBytes              = 1 << 20
	maxReseedEndpoints          = 32
	maxReseedEndpointBytes      = 512
	maxBootstrapRouterInfoFiles = 8
	maxOperatingPathBytes       = 4_096
	maxConfigLine               = len("bootstrap_router_info_files = ") + maxBootstrapRouterInfoFiles*maxOperatingPathBytes + maxBootstrapRouterInfoFiles - 1
	maxConfigEntries            = 4_096
)

var ErrMalformed = errors.New("config: malformed configuration")

type Entry struct{ Section, Key, Value string }

// Parse handles global keys, [section] keys, comments, and quoted values.
func Parse(text string) ([]Entry, error) {
	if len(text) > maxConfigBytes {
		return nil, ErrMalformed
	}

	entries := make([]Entry, 0, 32)
	seen := make(map[entryKey]struct{})
	section := ""
	for len(text) > 0 {
		raw, rest, found := strings.Cut(text, "\n")
		if found {
			text = rest
		} else {
			text = ""
		}
		if len(raw) > maxConfigLine {
			return nil, ErrMalformed
		}
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if len(line) < 3 || line[len(line)-1] != ']' {
				return nil, ErrMalformed
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				return nil, ErrMalformed
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, ErrMalformed
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if len(entries) == maxConfigEntries {
			return nil, ErrMalformed
		}
		keyID := entryKey{section: section, key: key}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, ErrMalformed
		}
		seen[keyID] = struct{}{}
		entries = append(entries, Entry{Section: section, Key: key, Value: value})
	}
	return entries, nil
}

type entryKey struct{ section, key string }

// Lookup returns the value for a section/key pair.
func Lookup(entries []Entry, section, key string) (string, bool) {
	for _, entry := range entries {
		if entry.Section == section && entry.Key == key {
			return entry.Value, true
		}
	}
	return "", false
}

func stripComment(line string) string {
	quoted := false
	for i, c := range line {
		if c == '"' {
			quoted = !quoted
		}
		if !quoted && (c == '#' || c == ';') {
			return line[:i]
		}
	}
	return line
}
