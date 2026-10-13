package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane"
)

func TestRestoreCachedSU3VerifiesBeforePublishing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	const signerID = "cache-test@ivnp.network"

	info, raw := createTestRouterInfo(t, "f")
	valid, err := BuildSU3([]PeerRecord{{Hash: info.Hash(), Raw: raw}}, signerID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "i2pseeds.su3")
		if err := os.WriteFile(filename, valid, 0600); err != nil {
			t.Fatal(err)
		}
		server := NewReseedServer(ServerConfig{NetworkID: 2}, NewPeerStore())
		pkg, err := restoreCachedSU3(server, filename, signerID, &key.PublicKey)
		if err != nil {
			t.Fatalf("restore valid cached archive: %v", err)
		}
		if pkg.PeerCount != 1 || pkg.FloodfillCount != 1 || !bytes.Equal(pkg.SU3Data, valid) {
			t.Fatalf("unexpected restored package: %+v", pkg)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/i2pseeds.su3?netid=2", nil))
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), valid) {
			t.Fatalf("served cached archive: status=%d size=%d", rec.Code, rec.Body.Len())
		}

		// A later failed restoration must not replace an already valid package.
		if err := os.WriteFile(filename, []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
		if replaced, err := restoreCachedSU3(server, filename, signerID, &key.PublicKey); err == nil || replaced != nil {
			t.Fatalf("invalid replacement accepted: pkg=%v err=%v", replaced, err)
		}
		rec = httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/i2pseeds.su3?netid=2", nil))
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), valid) {
			t.Fatal("failed restoration replaced the last verified package")
		}
	})

	wrongKey := key.PublicKey
	wrongKey.N = new(big.Int).Add(key.N, big.NewInt(2))
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-su3RSASignatureLen-1] ^= 0xff
	malformedSigned, err := BuildSU3([]PeerRecord{{Raw: []byte("bad router info")}}, signerID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		data    []byte
		signer  string
		key     *rsa.PublicKey
		wantErr error
	}{
		{"truncated archive", []byte("corrupt"), signerID, &key.PublicKey, errSU3TooShort},
		{"wrong signer", valid, "other@ivnp.network", &key.PublicKey, controlplane.ReseedErrSU3Signer},
		{"wrong public key", valid, signerID, &wrongKey, controlplane.ReseedErrSU3Signature},
		{"tampered signed bytes", tampered, signerID, &key.PublicKey, controlplane.ReseedErrSU3Signature},
		{"signed invalid router info", malformedSigned, signerID, &key.PublicKey, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "i2pseeds.su3")
			if err := os.WriteFile(filename, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			server := NewReseedServer(ServerConfig{NetworkID: 2}, NewPeerStore())
			pkg, err := restoreCachedSU3(server, filename, tc.signer, tc.key)
			if err == nil || pkg != nil {
				t.Fatalf("invalid archive accepted: pkg=%v err=%v", pkg, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("restore error = %v, want %v", err, tc.wantErr)
			}

			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/i2pseeds.su3?netid=2", nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("invalid archive was published: status=%d", rec.Code)
			}
		})
	}
}

func TestRestoreCachedSU3FileSizeBoundary(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		size       int64
		wantTooBig bool
	}{
		{"at limit", maxCachedSU3Bytes, false},
		{"above limit", maxCachedSU3Bytes + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "i2pseeds.su3")
			f, err := os.Create(filename)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tc.size); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			server := NewReseedServer(ServerConfig{NetworkID: 2}, NewPeerStore())
			pkg, err := restoreCachedSU3(server, filename, "cache-test@ivnp.network", &key.PublicKey)
			if err == nil || pkg != nil {
				t.Fatalf("invalid file accepted: pkg=%v err=%v", pkg, err)
			}
			if errors.Is(err, errCachedSU3TooLarge) != tc.wantTooBig {
				t.Fatalf("file size %d: error=%v, wantTooBig=%t", tc.size, err, tc.wantTooBig)
			}
		})
	}
}

func TestInspectSU3ArchiveExpansionLimits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	const signerID = "cache-limits@ivnp.network"

	for _, tc := range []struct {
		name          string
		entries       int
		bytesPerEntry int
		reject        error
	}{
		{"entry count at limit", maxCachedRouterInfos, 1, nil},
		{"entry count above limit", maxCachedRouterInfos + 1, 1, errSU3TooManyEntries},
		{"entry size at limit", 1, maxRouterInfoBytes, nil},
		{"entry size above limit", 1, maxRouterInfoBytes + 1, errSU3EntryTooLarge},
		{"total size at limit", maxTotalRouterBytes / maxRouterInfoBytes, maxRouterInfoBytes, nil},
		{"total size above limit", maxTotalRouterBytes/maxRouterInfoBytes + 1, maxRouterInfoBytes, errSU3TotalTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers := make([]PeerRecord, tc.entries)
			raw := make([]byte, tc.bytesPerEntry)
			for i := range peers {
				binary.BigEndian.PutUint32(peers[i].Hash[:4], uint32(i))
				peers[i].Raw = raw
			}
			archive, err := BuildSU3(peers, signerID, key, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if len(archive) > maxCachedSU3Bytes {
				t.Fatalf("test archive unexpectedly exceeds outer size budget: %d", len(archive))
			}
			_, _, err = InspectSU3Archive(archive, signerID, &key.PublicKey)
			if tc.reject != nil {
				if !errors.Is(err, tc.reject) {
					t.Fatalf("inspection error = %v, want %v", err, tc.reject)
				}
			} else {
				// The dummy RouterInfo is invalid, but the resource boundary
				// itself must permit an archive exactly at the limit.
				if errors.Is(err, errSU3TooManyEntries) ||
					errors.Is(err, errSU3EntryTooLarge) || errors.Is(err, errSU3TotalTooLarge) {
					t.Fatalf("boundary archive got unexpected error: %v", err)
				}
			}
		})
	}
}
