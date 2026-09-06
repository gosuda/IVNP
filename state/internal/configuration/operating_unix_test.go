//go:build !windows

package configuration

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadOperatingRejectsUnsafeSecretSources(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("[control]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 7650\nbearer_token = token-token-token-1\n")
	path := filepath.Join(dir, "ivnp.conf")
	if err := os.WriteFile(path, secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(path); err == nil {
		t.Fatal("LoadOperating accepted world-readable bearer credentials")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(path); err != nil {
		t.Fatalf("LoadOperating(private secret) error = %v", err)
	}
	link := filepath.Join(dir, "ivnp-link.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(link); err == nil {
		t.Fatal("LoadOperating accepted a symlink")
	}
	fifo := filepath.Join(dir, "ivnp-fifo.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(fifo); err == nil {
		t.Fatal("LoadOperating accepted a FIFO")
	}
}
