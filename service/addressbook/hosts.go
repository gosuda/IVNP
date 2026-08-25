package addressbook

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	ivnp "gosuda.org/ivnp"
)

func normalizeName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(value))
	if strings.HasSuffix(name, ".i2p.alt") {
		name = strings.TrimSuffix(name, ".alt")
	}
	if len(name) < len("a.i2p") || len(name) > 67 || !strings.HasSuffix(name, ".i2p") || strings.HasPrefix(name, ".") || strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return "", ErrName
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, ".i2p"), ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrName
		}
		if strings.Contains(label, "--") && !strings.HasPrefix(label, "xn--") {
			return "", ErrName
		}
		for i := range len(label) {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", ErrName
			}
		}
	}
	return name, nil
}

func canonicalDestination(value string) (string, bool) {
	value = strings.TrimSpace(value)
	identity, err := ivnp.ParseDestination([]byte(value))
	if err != nil {
		return "", false
	}
	canonical := ivnp.EncodeI2PBase64(identity.Bytes())
	if value != canonical {
		return "", false
	}
	return canonical, true
}

func parseHosts(reader io.Reader, maxBytes int64, maxEntries int) (map[string]string, error) {
	if maxBytes <= 0 || maxEntries <= 0 {
		return nil, ErrConfig
	}
	limited := io.LimitReader(reader, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrConfig
	}
	entries := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#!") {
			return nil, ErrMutation
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		nameRaw, destinationRaw, ok := strings.Cut(line, "=")
		if !ok || strings.Contains(destinationRaw, "=") && strings.Contains(strings.TrimSpace(destinationRaw), " ") {
			return nil, ErrName
		}
		name, nameErr := normalizeName(nameRaw)
		if nameErr != nil {
			return nil, nameErr
		}
		destination, destinationOK := canonicalDestination(strings.TrimSpace(destinationRaw))
		if !destinationOK {
			return nil, ErrDestination
		}
		if _, exists := entries[name]; exists {
			return nil, ErrName
		}
		if len(entries) >= maxEntries {
			return nil, ErrConfig
		}
		entries[name] = destination
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func loadHostsFile(path string, maxBytes int64, maxEntries int) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, ErrConfig
	}
	return parseHosts(file, maxBytes, maxEntries)
}
