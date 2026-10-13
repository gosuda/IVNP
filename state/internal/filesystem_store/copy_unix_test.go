//go:build !windows

package filesystemstore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCopyOwnedFileIfExistsRejectsUnsafeMetadata(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	dst := filepath.Join(dir, "destination")
	if err := os.WriteFile(src, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopyOwnedFileIfExists(src, dst, 16, true); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("public source = %v, want unsafe permissions", err)
	}
	if err := CopyOwnedFileIfExists(src, dst, 16, false); err != nil {
		t.Fatalf("public owned snapshot must be permitted: %v", err)
	}
	if err := os.Chmod(src, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "other-link")
	if err := os.Link(src, link); err != nil {
		t.Fatal(err)
	}
	if err := CopyOwnedFileIfExists(src, dst, 16, false); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("hard-linked source = %v, want unsafe permissions", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyOwnedFileIfExists(fifo, dst, 16, false); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("FIFO source = %v, want invalid file", err)
	}
}
