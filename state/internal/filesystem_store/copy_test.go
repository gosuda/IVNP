package filesystemstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writePrivateCopyFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreatePrivateBoundedCopy(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "state")
	dest := filepath.Join(dir, "copied")
	if err := CopyPrivateBoundedIfExists(source, dest, 3); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source installed destination: %v", err)
	}
	writePrivateCopyFixture(t, source, []byte("abc"))
	if err := CopyPrivateBoundedIfExists(source, dest, 3); err != nil {
		t.Fatalf("exact size: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(data, []byte("abc")) {
		t.Fatalf("copy = %q, %v", data, err)
	}
	copied, _, err := OpenRegular(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(copied); err != nil {
		t.Fatal(err)
	}
	if err := copied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(source, dest, 3); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize error: %v", err)
	}
	data, err = os.ReadFile(dest)
	if err != nil || string(data) != "abc" {
		t.Fatalf("overlarge input changed destination: %q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(source, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CopyPrivateBoundedIfExists(source, dest, 8); !errors.Is(err, ErrUnsafePermissions) {
			t.Fatalf("mode laundering: %v", err)
		}
		if err := os.Chmod(source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(source, link); err == nil {
		if err := CopyPrivateBoundedIfExists(link, dest, 8); err == nil {
			t.Fatal("symlink accepted")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	hardlink := filepath.Join(dir, "hardlinked")
	if err := os.Link(source, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(source, dest, 8); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("hardlink accepted: %v", err)
	}
	if err := CopyPrivateBoundedIfExists(dir, dest, 8); err == nil {
		t.Fatal("directory accepted")
	}
	if err := CopyPrivateBoundedIfExists(source, dest, -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("negative limit: %v", err)
	}
}

func TestCreatePrivateBoundedCopyReplacesDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	dst := filepath.Join(dir, "destination")
	other := filepath.Join(dir, "other")
	writePrivateCopyFixture(t, src, []byte("source"))
	writePrivateCopyFixture(t, other, []byte("untouched"))
	if err := os.Symlink(other, dst); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("no symlink rights: %v", err)
		}
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, 6); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dst)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("destination not regular: %v %v", info, err)
	}
	data, err := os.ReadFile(other)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("destination symlink followed: %q %v", data, err)
	}
}
