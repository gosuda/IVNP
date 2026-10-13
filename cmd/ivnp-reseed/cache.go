package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
)

// Allow the reseed payload limit plus the largest possible SU3 framing.
const maxCachedSU3Bytes = controlplane.ReseedDefaultMaxArchiveBytes + su3HeaderLen + 2*255 + su3RSASignatureLen

var (
	errCachedSU3TooLarge    = errors.New("reseed cache: SU3 archive exceeds size limit")
	errCachedSU3InvalidFile = errors.New("reseed cache: expected a nonempty regular file")
)

// loadCachedSU3 reads, authenticates, and inspects a persisted archive.
// No package is returned unless every check succeeds.
func loadCachedSU3(path, signerID string, signingKey *rsa.PrivateKey) (ReseedPackage, error) {
	if signingKey == nil || signingKey.N == nil || signingKey.N.BitLen() != 4096 {
		return ReseedPackage{}, ErrInvalidPrivateKey
	}
	// Reject links, devices, and FIFOs before opening: a FIFO open can block.
	entry, err := os.Lstat(path)
	if err != nil {
		return ReseedPackage{}, fmt.Errorf("lstat cached SU3: %w", err)
	}
	if !entry.Mode().IsRegular() || entry.Size() == 0 {
		return ReseedPackage{}, errCachedSU3InvalidFile
	}
	if entry.Size() > maxCachedSU3Bytes {
		return ReseedPackage{}, errCachedSU3TooLarge
	}
	file, err := os.Open(path)
	if err != nil {
		return ReseedPackage{}, fmt.Errorf("open cached SU3: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return ReseedPackage{}, fmt.Errorf("stat cached SU3: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Size() == 0 {
		return ReseedPackage{}, errCachedSU3InvalidFile
	}
	if stat.Size() > maxCachedSU3Bytes {
		return ReseedPackage{}, errCachedSU3TooLarge
	}

	data, err := io.ReadAll(io.LimitReader(file, maxCachedSU3Bytes+1))
	if err != nil {
		return ReseedPackage{}, fmt.Errorf("read cached SU3: %w", err)
	}
	if len(data) > maxCachedSU3Bytes {
		return ReseedPackage{}, errCachedSU3TooLarge
	}
	if len(data) == 0 {
		return ReseedPackage{}, errCachedSU3InvalidFile
	}

	signers := map[string]controlplane.ReseedSU3Signer{
		signerID: {
			SigningType: foundation.SigningRSASHA512_4096,
			PublicKey:   signingKey.N.FillBytes(make([]byte, su3RSASignatureLen)),
		},
	}
	if _, err := controlplane.ReseedVerifySU3(data, signers, controlplane.ReseedDefaultMaxArchiveBytes); err != nil {
		return ReseedPackage{}, fmt.Errorf("verify cached SU3: %w", err)
	}
	peerCount, floodCount, err := InspectSU3Archive(data)
	if err != nil {
		return ReseedPackage{}, fmt.Errorf("inspect cached SU3: %w", err)
	}

	sum := sha256.Sum256(data)
	return ReseedPackage{
		GeneratedAt:    time.Now(),
		PeerCount:      peerCount,
		FloodfillCount: floodCount,
		SU3Data:        data,
		ETag:           "\"" + hex.EncodeToString(sum[:8]) + "\"",
	}, nil
}
