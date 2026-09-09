package securestore

import (
	"bytes"
	"errors"
	"testing"
)

func TestMemoryStoreOwnsSnapshotsAndWipesOnClose(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	first, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	hash := first.Router.Hash
	first.ReleaseSensitive()
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.ReleaseSensitive()
	if loaded.Router.Hash != hash {
		t.Fatal("releasing caller's bundle changed stored identity")
	}
	if bytes.Equal(loaded.Router.SigningPrivate, make([]byte, len(loaded.Router.SigningPrivate))) {
		t.Fatal("releasing caller's bundle wiped stored signing key")
	}
	snapshot := store.snapshot
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, make([]byte, len(snapshot))) {
		t.Fatal("closed store retained sensitive snapshot bytes")
	}
	if _, err := store.LoadOrCreate(); !errors.Is(err, ErrStoreConfig) {
		t.Fatalf("closed store reopened: %v", err)
	}
}

func TestMemoryStoreRejectsOversizeSaveWithoutLosingIdentity(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.ReleaseSensitive()
	store.MaxStateBytes = headerSize + 16
	if err := store.Save(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("oversized snapshot = %v", err)
	}
	store.MaxStateBytes = DefaultMaxStateBytes
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.ReleaseSensitive()
	if loaded.Router.Hash != bundle.Router.Hash {
		t.Fatal("failed save replaced identity")
	}
}
