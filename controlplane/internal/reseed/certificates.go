package reseed

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"gosuda.org/ivnp/foundation"
)

//go:embed certs/*.crt
var certificates embed.FS

var (
	ErrDefaultSigners    = errors.New("reseed: embedded signer set is invalid")
	ErrSignerCertificate = errors.New("reseed: invalid signer certificate")
)

// DefaultSU3Signers returns the embedded set of trusted reseed signer certificates.
func DefaultSU3Signers() (map[string]SU3Signer, error) {
	return DefaultSU3SignersAt(time.Now())
}

// DefaultSU3SignersAt returns the trusted reseed signers valid at the given time.
func DefaultSU3SignersAt(now time.Time) (map[string]SU3Signer, error) {
	return loadSU3Signers(certificates, now)
}

// ParseSU3SignerCertificate parses and validates one PEM-encoded RSA-4096 SU3
// signer certificate at the given reference time.
func ParseSU3SignerCertificate(pemBytes []byte, now time.Time) (string, SU3Signer, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" {
		return "", SU3Signer{}, fmt.Errorf("%w: invalid PEM certificate block", ErrSignerCertificate)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", SU3Signer{}, fmt.Errorf("%w: parse certificate: %v", ErrSignerCertificate, err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	rejected := !ok || publicKey.E != 65537 || publicKey.N.BitLen() != 4096 ||
		certificate.Subject.CommonName == "" ||
		certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		now.Before(certificate.NotBefore)
	if !rejected {
		rejected = now.After(certificate.NotAfter)
	}
	if rejected {
		return "", SU3Signer{}, fmt.Errorf("%w: unsupported or inactive certificate %q", ErrSignerCertificate, certificate.Subject.CommonName)
	}
	return certificate.Subject.CommonName, SU3Signer{
		SigningType: foundation.SigningRSASHA512_4096,
		PublicKey:   publicKey.N.FillBytes(make([]byte, 512)),
	}, nil
}

// MergeSU3Signers returns a copy of base with additional PEM-encoded signer
// certificates merged by Subject CommonName.
func MergeSU3Signers(base map[string]SU3Signer, pemCerts [][]byte, now time.Time) (map[string]SU3Signer, error) {
	merged := make(map[string]SU3Signer, len(base)+len(pemCerts))
	for name, signer := range base {
		merged[name] = signer
	}
	for index, raw := range pemCerts {
		name, signer, err := ParseSU3SignerCertificate(raw, now)
		if err != nil {
			return nil, fmt.Errorf("trusted certificate %d: %w", index, err)
		}
		merged[name] = signer
	}
	return merged, nil
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
		name, signer, err := ParseSU3SignerCertificate(contents, now)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrDefaultSigners, entry.Name(), err)
		}
		if _, exists := signers[name]; exists {
			return nil, fmt.Errorf("%w: duplicate embedded signer %q", ErrDefaultSigners, name)
		}
		signers[name] = signer
	}
	return signers, nil
}
