package reseed

import (
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	ivnp "gosuda.org/ivnp/foundation"
	"io/fs"
	"time"
)

// certificates contains the current Java-I2P reseed trust set from
// installer/resources/certificates/reseed in github.com/i2p/i2p.i2p.
//
//go:embed certs/*.crt
var certificates embed.FS

var ErrDefaultSigners = errors.New("reseed: embedded signer set is invalid")

// DefaultSU3Signers returns the pinned Java-I2P reseed signers, validating
// their certificate lifetime at the current time.
func DefaultSU3Signers() (map[string]SU3Signer, error) {
	return DefaultSU3SignersAt(time.Now())
}

// DefaultSU3SignersAt validates and returns the pinned Java-I2P reseed signers
// at now. The explicit time keeps certificate lifetime checks deterministic for
// callers with an injected clock.
func DefaultSU3SignersAt(now time.Time) (map[string]SU3Signer, error) {
	return loadSU3Signers(certificates, now)
}

func loadSU3Signers(source fs.FS, now time.Time) (map[string]SU3Signer, error) {
	entries, err := fs.ReadDir(source, "certs")
	if err != nil {
		return nil, fmt.Errorf("%w: read embedded certificates: %v", ErrDefaultSigners, err)
	}
	signers := make(map[string]SU3Signer, len(entries))
	for _, entry := range entries {
		contents, err := fs.ReadFile(source, "certs/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("%w: read embedded certificate %q: %v", ErrDefaultSigners, entry.Name(), err)
		}
		block, rest := pem.Decode(contents)
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: invalid embedded certificate %q", ErrDefaultSigners, entry.Name())
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse embedded certificate %q: %v", ErrDefaultSigners, entry.Name(), err)
		}
		publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
		loadSU3SignersRejected := !ok || publicKey.E != 65537 || publicKey.N.BitLen() != 4096 ||
			certificate.Subject.CommonName == "" ||
			certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
			now.Before(certificate.NotBefore)
		if !loadSU3SignersRejected {
			loadSU3SignersRejected = now.After(certificate.NotAfter)
		}
		if loadSU3SignersRejected {
			return nil, fmt.Errorf("%w: unsupported or inactive embedded certificate %q", ErrDefaultSigners, entry.Name())
		}
		if _, exists := signers[certificate.Subject.CommonName]; exists {
			return nil, fmt.Errorf("%w: duplicate embedded signer %q", ErrDefaultSigners, certificate.Subject.CommonName)
		}
		signers[certificate.Subject.CommonName] = SU3Signer{
			SigningType: ivnp.SigningRSASHA512_4096,
			PublicKey:   publicKey.N.FillBytes(make([]byte, 512)),
		}
	}
	return signers, nil
}
