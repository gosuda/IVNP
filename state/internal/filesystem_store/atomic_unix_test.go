//go:build !windows

package filesystemstore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadBoundedRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "state-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(fifo, 8); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("ReadBounded(FIFO) error = %v, want invalid file", err)
	}
}
func TestSyncDirRejectsFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir(directory) error = %v", err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(file); err == nil {
		t.Fatal("SyncDir accepted a regular file")
	}
	link := filepath.Join(dir, "dir-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(link); err == nil {
		t.Fatal("SyncDir accepted a symlink")
	}
}
