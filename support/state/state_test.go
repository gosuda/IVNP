package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ivnp "gosuda.org/ivnp"
)

func TestLoadOrCreatePersistsRouterAndLegacyDestinationIdentityMaterial(t *testing.T) {
	store := testStore(t)
	first, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	service, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	first.Destinations["service"] = service
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	routerIdentity, err := loaded.Router.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if routerIdentity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519 || routerIdentity.CryptoKeyType() != ivnp.CryptoX25519 {
		t.Fatal("reloaded router identity is not Ed25519/X25519")
	}
	serviceIdentity, err := loaded.Destinations["service"].Identity()
	if err != nil {
		t.Fatal(err)
	}
	if serviceIdentity.SigningKeyType() != ivnp.SigningEdDSASHA512Ed25519 || serviceIdentity.CryptoKeyType() != ivnp.CryptoElGamal {
		t.Fatal("reloaded destination is not legacy Ed25519/ElGamal")
	}
	if !sameBundle(first, loaded) {
		t.Fatal("saved identity material changed after reload")
	}
	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if !sameBundle(first, reloaded) {
		t.Fatal("LoadOrCreate regenerated existing identity material")
	}
}

func TestStateCiphertextAndModesProtectPrivateMaterial(t *testing.T) {
	store := testStore(t)
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{
		bundle.Router.SigningPrivate,
		bundle.Router.X25519Private[:],
		bundle.NTCP2StaticPrivate,
		bundle.SSU2StaticPrivate,
		bundle.SSU2IntroKey,
	} {
		if bytes.Contains(ciphertext, private) {
			t.Fatal("state ciphertext exposes private material")
		}
	}
	for _, path := range []string{store.StatePath, store.MasterKeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", path, got)
		}
	}
}

func TestLoadRejectsCorruptionWrongKeyAndTruncationWithoutRegeneration(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-1] ^= 1
	if err := os.WriteFile(store.StatePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("LoadOrCreate(corrupt) error = %v, want invalid state", err)
	}
	if got, err := os.ReadFile(store.StatePath); err != nil || !bytes.Equal(got, corrupt) {
		t.Fatal("corrupt state was replaced")
	}

	if err := os.WriteFile(store.StatePath, original[:headerSize-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("LoadOrCreate(truncated) error = %v, want invalid state", err)
	}

	if err := os.WriteFile(store.StatePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKey := bytes.Repeat([]byte{0x5a}, masterKeySize)
	if err := os.WriteFile(store.MasterKeyPath, wrongKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load(wrong key) error = %v, want invalid state", err)
	}
}

func TestLoadOrCreateRejectsOldStateVersionWithoutRegeneration(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	oldVersion, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	oldVersion[len(stateMagic)] = stateVersion - 1
	if err := os.WriteFile(store.StatePath, oldVersion, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("LoadOrCreate(old version) error = %v, want invalid state", err)
	}
	if got, err := os.ReadFile(store.StatePath); err != nil || !bytes.Equal(got, oldVersion) {
		t.Fatal("old-version state was replaced")
	}
}

func TestSaveAtomicallyReplacesState(t *testing.T) {
	store := testStore(t)
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle.NTCP2StaticIV[0] ^= 1
	if err := store.Save(bundle); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(store.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, prior) {
		t.Fatal("state file was overwritten rather than atomically replaced")
	}
}

func TestSaveRejectsBoundsAndMismatchedIdentityKeys(t *testing.T) {
	store := testStore(t)
	store.MaxDestinations = 1
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	first, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ivnp.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	bundle.Destinations["one"] = first
	bundle.Destinations["two"] = second
	if err := store.Save(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("Save(over destination limit) error = %v", err)
	}

	delete(bundle.Destinations, "two")
	bundle.Router.SigningPrivate[0] ^= 1
	if err := store.Save(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("Save(mismatched signing key) error = %v", err)
	}
	bundle.Router.SigningPrivate[0] ^= 1
	bundle.Router.X25519Private[16] ^= 1
	if err := store.Save(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("Save(mismatched X25519 key) error = %v", err)
	}

	bundle.Router.X25519Private[16] ^= 1
	store.MaxNameBytes = 3
	bundle.Destinations["long"] = first
	if err := store.Save(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("Save(overlong name) error = %v", err)
	}
}

func TestLoadOrCreateRejectsOrphanedStateOrKey(t *testing.T) {
	t.Run("key without state", func(t *testing.T) {
		store := testStore(t)
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(store.StatePath); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("LoadOrCreate(orphan key) error = %v, want invalid state", err)
		}
		if _, err := os.Stat(store.StatePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("orphaned key caused state regeneration")
		}
	})
	t.Run("state without key", func(t *testing.T) {
		store := testStore(t)
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(store.MasterKeyPath); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("LoadOrCreate(orphan state) error = %v, want invalid state", err)
		}
	})
}

func TestLoadRejectsSwappedAndOversizeState(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	replaced := store.StatePath + ".replaced"
	if err := os.Rename(store.StatePath, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replaced, store.StatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("Load accepted a symlink-swapped state path")
	}
	if err := os.Remove(store.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replaced, store.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.StatePath, make([]byte, store.maxStateBytes()+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load(oversize) error = %v, want invalid state", err)
	}
}

func TestStateRejectsUnsafeParentAndFiles(t *testing.T) {
	store := testStore(t)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(store.StatePath)
	if err := os.Chmod(parent, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load(group-writable parent) error = %v, want invalid state", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.StatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load(world-readable state) error = %v, want invalid state", err)
	}
	if err := os.Chmod(store.StatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.MasterKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load(world-readable key) error = %v, want invalid state", err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "state", "router.bin"), filepath.Join(t.TempDir(), "keys", "master.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func sameBundle(left, right Bundle) bool {
	sameBundleRejected := !sameRouterAddress(left.Router, right.Router) || !bytes.Equal(left.NTCP2StaticPrivate, right.NTCP2StaticPrivate) || !bytes.Equal(left.NTCP2StaticIV, right.NTCP2StaticIV) || !bytes.Equal(left.SSU2StaticPrivate, right.SSU2StaticPrivate) || !bytes.Equal(left.SSU2IntroKey, right.SSU2IntroKey)
	if !sameBundleRejected {
		sameBundleRejected = len(left.Destinations) != len(right.Destinations)
	}
	if sameBundleRejected {
		return false
	}
	for name, address := range left.Destinations {
		other, ok := right.Destinations[name]
		if !ok || !sameAddress(address, other) {
			return false
		}
	}
	return true
}

func sameRouterAddress(left, right ivnp.LocalRouterAddress) bool {
	return bytes.Equal(left.RouterIdentity, right.RouterIdentity) && left.Hash == right.Hash && bytes.Equal(left.SigningPublic, right.SigningPublic) && bytes.Equal(left.SigningPrivate, right.SigningPrivate) && left.X25519Public == right.X25519Public && left.X25519Private == right.X25519Private
}

func sameAddress(left, right ivnp.LocalAddress) bool {
	return bytes.Equal(left.Destination, right.Destination) && left.Hash == right.Hash && bytes.Equal(left.SigningPublic, right.SigningPublic) && bytes.Equal(left.SigningPrivate, right.SigningPrivate) && left.EncryptionPublic == right.EncryptionPublic && left.EncryptionPrivate == right.EncryptionPrivate
}
