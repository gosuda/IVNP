package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
)

func TestLoadCachedSU3RejectsInvalidCache(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	info, raw := createTestRouterInfo(t, "f")
	const signerID = "cached-test@ivnp.network"
	valid, err := BuildSU3([]PeerRecord{{Hash: info.Hash(), Raw: raw}}, signerID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "i2pseeds.su3")
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(valid)
	pkg, err := loadCachedSU3(path, signerID, key)
	if err != nil {
		t.Fatalf("valid SU3 rejected: %v", err)
	}
	if pkg.PeerCount != 1 || pkg.FloodfillCount != 1 || !bytes.Equal(pkg.SU3Data, valid) {
		t.Fatalf("unexpected cached package: peers=%d floodfills=%d", pkg.PeerCount, pkg.FloodfillCount)
	}
	if _, err := loadCachedSU3(path, "different-signer@ivnp.network", key); !errors.Is(err, controlplane.ReseedErrSU3Signer) {
		t.Fatalf("wrong signer: got %v", err)
	}

	corrupted := bytes.Clone(valid)
	corrupted[len(corrupted)-1] ^= 0x01
	write(corrupted)
	if _, err := loadCachedSU3(path, signerID, key); !errors.Is(err, controlplane.ReseedErrSU3Signature) {
		t.Fatalf("corrupt signature: got %v", err)
	}

	invalidZip, err := BuildSU3([]PeerRecord{{Hash: info.Hash(), Raw: []byte("not a RouterInfo")}}, signerID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write(invalidZip)
	if _, err := loadCachedSU3(path, signerID, key); err == nil {
		t.Fatal("signed archive with invalid RouterInfo was accepted")
	}

	zipBomb, err := BuildSU3([]PeerRecord{{Hash: info.Hash(), Raw: bytes.Repeat([]byte{0}, foundation.NetworkDatabaseMaxRouterInfoBytes+1)}}, signerID, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write(zipBomb)
	if _, err := loadCachedSU3(path, signerID, key); !errors.Is(err, errSU3InvalidRouterInfoSize) {
		t.Fatalf("signed oversized RouterInfo: got %v", err)
	}

	write(bytes.Repeat([]byte{0}, maxCachedSU3Bytes))
	if _, err := loadCachedSU3(path, signerID, key); err == nil || errors.Is(err, errCachedSU3TooLarge) {
		t.Fatalf("archive at size limit must reach verification: got %v", err)
	}

	write(bytes.Repeat([]byte{0}, maxCachedSU3Bytes+1))
	if _, err := loadCachedSU3(path, signerID, key); !errors.Is(err, errCachedSU3TooLarge) {
		t.Fatalf("archive above size limit: got %v", err)
	}

	linkPath := filepath.Join(t.TempDir(), "linked.su3")
	if err := os.Symlink(path, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCachedSU3(linkPath, signerID, key); !errors.Is(err, errCachedSU3InvalidFile) {
		t.Fatalf("symlink cache: got %v", err)
	}
	if _, err := loadCachedSU3(t.TempDir(), signerID, key); !errors.Is(err, errCachedSU3InvalidFile) {
		t.Fatalf("directory cache: got %v", err)
	}
	if _, err := loadCachedSU3(filepath.Join(t.TempDir(), "missing"), signerID, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing cache: got %v", err)
	}
}

func inspectTestSU3(t *testing.T, writeEntries func(*zip.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeEntries(zw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	const signerLen = 1
	data := make([]byte, su3HeaderLen+su3MinimumVersion+signerLen+buf.Len()+su3RSASignatureLen)
	copy(data, []byte{'I', '2', 'P', 's', 'u', '3', 0})
	data[13] = su3MinimumVersion
	data[15] = signerLen
	binary.BigEndian.PutUint64(data[16:24], uint64(buf.Len()))
	data[25] = su3FileTypeZIP
	data[27] = su3ContentTypeReseed
	copy(data[su3HeaderLen:su3HeaderLen+su3MinimumVersion], []byte("2026101323380000"))
	data[su3HeaderLen+su3MinimumVersion] = 'x'
	copy(data[su3HeaderLen+su3MinimumVersion+signerLen:], buf.Bytes())
	return data
}

func TestInspectSU3ArchiveResourceLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries int
		size    int
		want    error
	}{
		{"maximum entries", controlplane.ReseedDefaultMaxRouterInfos, 1, errSU3NoRouterInfos},
		{"excess entries", controlplane.ReseedDefaultMaxRouterInfos + 1, 1, errSU3TooManyEntries},
		{"maximum RouterInfo bytes", 1, foundation.NetworkDatabaseMaxRouterInfoBytes, nil},
		{"excess RouterInfo bytes", 1, foundation.NetworkDatabaseMaxRouterInfoBytes + 1, errSU3InvalidRouterInfoSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := inspectTestSU3(t, func(zw *zip.Writer) {
				for i := range tc.entries {
					name := fmt.Sprintf("other-%d", i)
					if tc.entries == 1 {
						name = "routerInfo-example.dat"
					}
					w, err := zw.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(bytes.Repeat([]byte{0}, tc.size)); err != nil {
						t.Fatal(err)
					}
				}
			})
			_, _, err := InspectSU3Archive(archive)
			if tc.want == nil {
				if err == nil || errors.Is(err, errSU3InvalidRouterInfoSize) {
					t.Fatalf("at RouterInfo limit: expected parse error, got %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("InspectSU3Archive() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestInspectSU3ArchiveRejectsForgedLength(t *testing.T) {
	archive := inspectTestSU3(t, func(zw *zip.Writer) {
		w, err := zw.Create("routerInfo-example.dat")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("bad")); err != nil {
			t.Fatal(err)
		}
	})
	binary.BigEndian.PutUint64(archive[16:24], ^uint64(0))
	if _, _, err := InspectSU3Archive(archive); !errors.Is(err, errInvalidSU3Bounds) {
		t.Fatalf("forged SU3 length: got %v", err)
	}
}
