package netdb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	ivnp "gosuda.org/ivnp"
)

func TestLoadStaticRouterInfosRequiresSignedFreshExactFiles(t *testing.T) {
	const now = uint64(1_000_000)
	first := signedPersistenceRouter(t, now)
	second := signedPersistenceRouter(t, now-1)
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.dat")
	secondPath := filepath.Join(directory, "second.dat")
	if err := os.WriteFile(firstPath, first.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, second.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	database := NewDatabase(ivnp.Hash{}, 2)
	loaded, err := LoadStaticRouterInfos([]string{firstPath, secondPath}, database, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || database.Routers().Len() != 2 {
		t.Fatalf("loaded=%d routers=%d, want 2", len(loaded), database.Routers().Len())
	}

	corrupt := append([]byte(nil), first.Bytes()...)
	corrupt[len(corrupt)-1] ^= 0x80
	corruptPath := filepath.Join(directory, "corrupt.dat")
	if err = os.WriteFile(corruptPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadStaticRouterInfos([]string{corruptPath}, NewDatabase(ivnp.Hash{}, 1), now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("corrupt signature error = %v", err)
	}
}

func TestLoadStaticRouterInfosRejectsTransportStaleRecord(t *testing.T) {
	const now = RouterInfoMaxAgeMillis + 2
	stale := signedPersistenceRouter(t, 1)
	path := filepath.Join(t.TempDir(), "stale.dat")
	if err := os.WriteFile(path, stale.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStaticRouterInfos([]string{path}, NewDatabase(ivnp.Hash{}, 1), now); !errors.Is(err, ErrRouterInfoStale) {
		t.Fatalf("stale RouterInfo error = %v", err)
	}
}
