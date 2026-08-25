package filesystemstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAtomicRoundTripAndBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "router.info")
	if err := WriteAtomic(path, []byte("state"), 0600, 8); err != nil {
		t.Fatal(err)
	}
	data, err := ReadBounded(path, 8)
	if err != nil || !bytes.Equal(data, []byte("state")) {
		t.Fatalf("ReadBounded=%q err=%v", data, err)
	}
	if err := WriteAtomic(path, []byte("oversize"), 0600, 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("WriteAtomic bound=%v", err)
	}
}

func TestReadBoundedRejectsSymlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state")
	if err := os.WriteFile(target, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(link, 8); err == nil {
		t.Fatal("ReadBounded accepted a symlink")
	}
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
