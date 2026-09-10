package filesystemstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	data, err = ReadBounded(path, 8)
	if err != nil || string(data) != "state" {
		t.Fatalf("rejected replacement changed prior state: %q, error %v", data, err)
	}
}

func TestReadBoundedRejectsSymlink(t *testing.T) {
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
}

func TestCreatePrivateDoesNotReplaceExistingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	file, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := SyncCreated(file); err != nil {
		t.Fatal(err)
	}
	other, err := CreatePrivate(path)
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive creation = %v, want exists", err)
	}
	data, err := ReadBounded(path, 32)
	if err != nil || string(data) != "original" {
		t.Fatalf("existing secret changed: %q, %v", data, err)
	}
}
