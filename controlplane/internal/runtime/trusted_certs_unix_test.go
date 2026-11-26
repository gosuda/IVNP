//go:build !windows

package noderuntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTrustedCertFilesRejectsGroupOrWorldWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reseed.crt")
	if err := os.WriteFile(path, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o620, 0o602, 0o664, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := loadTrustedCertFiles([]string{path})
		if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
			t.Fatalf("loadTrustedCertFiles(mode %#o) error = %v, want group- or world-writable rejection", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		certs, err := loadTrustedCertFiles([]string{path})
		if err != nil || len(certs) != 1 || string(certs[0]) != "certificate" {
			t.Fatalf("loadTrustedCertFiles(mode %#o) = %q, %v", mode, certs, err)
		}
	}
}
