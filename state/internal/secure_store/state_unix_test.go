//go:build !windows

package securestore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStateRejectsUnsafeParentAndFiles(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(store.StatePath)
	if err := os.Chmod(parent, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("Load(group-writable parent) error = %v, want unsafe permissions", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.StatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("Load(world-readable state) error = %v, want unsafe permissions", err)
	}
	if err := os.Chmod(store.StatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.MasterKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("Load(world-readable key) error = %v, want unsafe permissions", err)
	}
}
