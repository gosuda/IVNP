package netdb

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func signedPersistenceRouter(t *testing.T, published uint64) RouterInfo {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, foundation.IdentityBaseLength+7)
	copy(identity[352:384], public)
	identity[384] = byte(foundation.CertificateKey)
	identity[385], identity[386] = 0, 4
	identity[387], identity[388] = 0, byte(foundation.SigningEdDSASHA512Ed25519)
	identity[389], identity[390] = 0, byte(foundation.CryptoElGamal)
	unsigned := append(identity, make([]byte, 12)...)
	binary.BigEndian.PutUint64(unsigned[len(identity):len(identity)+8], published)
	info, err := ParseRouterInfo(append(unsigned, ed25519.Sign(private, unsigned)...))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestRouterInfoStoreRestoresVerifiedSnapshotAndRejectsCorruption(t *testing.T) {
	const now = uint64(1_000_000)
	path := filepath.Join(t.TempDir(), "netdb.routers")
	first := NewDatabase(foundation.Hash{}, 2)
	info := signedPersistenceRouter(t, now)
	if err := first.AdmitRouterInfo(info, false, now); err != nil {
		t.Fatal(err)
	}
	writer, err := NewRouterInfoStore(RouterInfoStoreConfig{Path: path, Database: first, NetworkID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Save(); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions = %o, want 0600", stat.Mode().Perm())
	}

	restored := NewDatabase(foundation.Hash{}, 2)
	reader, err := NewRouterInfoStore(RouterInfoStoreConfig{Path: path, Database: restored, NetworkID: 2})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.Load(now)
	if err != nil || result.Loaded != 1 || restored.Routers().Len() != 1 {
		t.Fatalf("Load() = %#v, %v; routers = %d", result, err, restored.Routers().Len())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0x80
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := NewDatabase(foundation.Hash{}, 2)
	corruptStore, err := NewRouterInfoStore(RouterInfoStoreConfig{Path: path, Database: corrupt, NetworkID: 2})
	if err != nil {
		t.Fatal(err)
	}
	result, err = corruptStore.Load(now)
	if err != nil || result.Loaded != 0 || result.Rejected != 1 || corrupt.Routers().Len() != 0 {
		t.Fatalf("corrupt Load() = %#v, %v; routers = %d", result, err, corrupt.Routers().Len())
	}
}
