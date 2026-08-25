package sam

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrLineTooLong = errors.New("sam: command line too long")
	ErrUnsupported = errors.New("sam: unsupported protocol path")
)

type command struct {
	verb     string
	subverb  string
	argument string
	values   map[string]string
}

func parseCommand(line string, maxValues int) (command, error) {
	tokens, err := tokenize(line)
	if err != nil || len(tokens) == 0 || maxValues < 1 {
		return command{}, ErrProtocol
	}
	cmd := command{verb: strings.ToUpper(tokens[0]), values: make(map[string]string)}
	if len(tokens) > 1 {
		cmd.subverb, cmd.argument = strings.ToUpper(tokens[1]), tokens[1]
		cmd.values = make(map[string]string, len(tokens)-2)
	}
	if len(tokens)-2 > maxValues {
		return command{}, ErrProtocol
	}
	if len(tokens) < 2 {
		return cmd, nil
	}
	for _, token := range tokens[2:] {
		key, value, ok := strings.Cut(token, "=")
		key = strings.ToUpper(key)
		if !ok || key == "" {
			return command{}, ErrProtocol
		}
		if _, exists := cmd.values[key]; exists {
			return command{}, ErrProtocol
		}
		cmd.values[key] = value
	}
	return cmd, nil
}

func tokenize(line string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	quoted, escaped, active := false, false, false
	for _, r := range strings.TrimSpace(line) {
		if escaped {
			token.WriteRune(r)
			escaped, active = false, true
			continue
		}
		if r == '\\' {
			escaped, active = true, true
			continue
		}
		if r == '"' {
			quoted, active = !quoted, true
			continue
		}
		if (r == ' ' || r == '\t') && !quoted {
			if active {
				tokens = append(tokens, token.String())
				token.Reset()
				active = false
			}
			continue
		}
		token.WriteRune(r)
		active = true
	}
	if escaped || quoted {
		return nil, ErrProtocol
	}
	if active {
		tokens = append(tokens, token.String())
	}
	return tokens, nil
}

func uintValue(values map[string]string, key string, bits int, fallback uint64) (uint64, error) {
	value, ok := values[key]
	if !ok {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, ErrProtocol
	}
	return parsed, nil
}

func boolValue(values map[string]string, key string) (bool, error) {
	value, ok := values[key]
	if !ok {
		return false, nil
	}
	switch strings.ToLower(value) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	}
	return false, ErrProtocol
}
