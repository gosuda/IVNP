//go:build !windows

package filesystemstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCreatePrivateBoundedCopyRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(source, filepath.Join(dir, "copied"), 32); err == nil {
		t.Fatal("FIFO was accepted")
	}
	if _, err := os.Lstat(filepath.Join(dir, "copied")); !os.IsNotExist(err) {
		t.Fatalf("FIFO produced destination: %v", err)
	}
}
