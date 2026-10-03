package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gosuda.org/ivnp/state"
)

func TestRunPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(-version) code = %d, want 0", code)
	}
	if got, want := stdout.String(), version+"\n"; got != want {
		t.Fatalf("run(-version) stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("run(-version) stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{name: "unknown flag", args: []string{"-unknown"}, wantStderr: "flag provided but not defined"},
		{name: "positional argument", args: []string{"unexpected"}, wantStderr: "ivnpd: unexpected positional arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(test.args, &stdout, &stderr); code != 2 {
				t.Fatalf("run(%q) code = %d, want 2", test.args, code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("run(%q) stdout = %q, want empty", test.args, stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantStderr) {
				t.Fatalf("run(%q) stderr = %q, want substring %q", test.args, stderr.String(), test.wantStderr)
			}
		})
	}
}

func TestRunTestConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "ivnp.conf")
	if err := os.WriteFile(configPath, []byte("[router]\nfloodfill = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-test-config", "-config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(-test-config) code = %d, want 0, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration is valid") {
		t.Fatalf("run(-test-config) stdout = %q, want valid message", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	missingPath := filepath.Join(dir, "nonexistent.conf")
	code = run([]string{"-test-config", "-config", missingPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(-test-config with missing file) code = %d, want 1", code)
	}
}

func TestApplyConfigOverrides(t *testing.T) {
	cfg := state.ConfigurationDefaultOperating()
	applyConfigOverrides(&cfg, "/tmp/custom-data", "DEBUG", "JSON", true, true)
	if cfg.DataDir != "/tmp/custom-data" {
		t.Errorf("DataDir = %q, want /tmp/custom-data", cfg.DataDir)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json", cfg.Log.Format)
	}
	if !cfg.HTTPProxy.Enabled {
		t.Errorf("HTTPProxy.Enabled = false, want true")
	}
	if !cfg.SOCKS5.Enabled {
		t.Errorf("SOCKS5.Enabled = false, want true")
	}
}

func TestRunTestConfigMemory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-memory", "-test-config"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(-memory -test-config) code = %d, want 0, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration is valid") {
		t.Fatalf("run(-memory -test-config) stdout = %q, want valid message", stdout.String())
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.conf")
	if err := os.WriteFile(configPath, []byte("[router]\nfloodfill = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-memory", "-config", configPath, "-test-config"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(-memory -config ... -test-config) code = %d, want 0, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration is valid") {
		t.Fatalf("run(-memory -config ... -test-config) stdout = %q, want valid message", stdout.String())
	}
}

func TestClearStoragePaths(t *testing.T) {
	cfg := state.ConfigurationDefaultOperating()
	cfg.NetDB.BootstrapRouterInfoPaths = []string{"/tmp/routerinfo"}
	clearStoragePaths(&cfg)
	if cfg.DataDir != "" || cfg.StateDir != "" || cfg.StatePath != "" || cfg.KeyPath != "" {
		t.Errorf("clearStoragePaths did not clear node state paths: %+v", cfg)
	}
	if cfg.AddressBook.PrivateHostsPath != "" || cfg.AddressBook.UserHostsPath != "" ||
		cfg.AddressBook.HostsPath != "" || cfg.AddressBook.StatePath != "" {
		t.Errorf("clearStoragePaths did not clear addressbook paths: %+v", cfg.AddressBook)
	}
	if len(cfg.NetDB.BootstrapRouterInfoPaths) != 0 {
		t.Errorf("clearStoragePaths did not clear bootstrap router info paths: %+v", cfg.NetDB.BootstrapRouterInfoPaths)
	}
}
