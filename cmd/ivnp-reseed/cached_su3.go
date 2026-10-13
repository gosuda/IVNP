package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// restoreCachedSU3 publishes cached bytes only after bounded reading,
// signer verification, and complete ZIP inspection succeed.
func restoreCachedSU3(server *ReseedServer, filename, signerID string, publicKey *rsa.PublicKey) (*ReseedPackage, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open cached su3 %q: %w", filename, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxCachedSU3Bytes+1))
	if err != nil {
		return nil, fmt.Errorf("read cached su3 %q: %w", filename, err)
	}
	if len(data) > maxCachedSU3Bytes {
		return nil, fmt.Errorf("read cached su3 %q: %w", filename, errCachedSU3TooLarge)
	}

	peerCount, floodfillCount, err := InspectSU3Archive(data, signerID, publicKey)
	if err != nil {
		return nil, fmt.Errorf("inspect cached su3 %q: %w", filename, err)
	}

	sum := sha256.Sum256(data)
	pkg := ReseedPackage{
		GeneratedAt:    time.Now(),
		PeerCount:      peerCount,
		FloodfillCount: floodfillCount,
		SU3Data:        data,
		ETag:           `"` + hex.EncodeToString(sum[:8]) + `"`,
	}
	server.UpdatePackage(pkg)
	return &pkg, nil
}
