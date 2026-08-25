// Package registration generates reg.i2p address-registration authentication strings.
package registration

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

var (
	ErrDomain = errors.New("registration: invalid .i2p domain")
	i2pBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
)

type Signer func([]byte) ([]byte, error)

// Authentication generates the legacy reg.i2p auth string:
// domain.i2p=<base64 destination>#!sig=<base64 signature>.
// The signer receives exactly the bytes before `#!sig=`.
func Authentication(domain string, destination []byte, sign Signer) (string, error) {
	domain, err := normalizeDomain(domain)
	if err != nil {
		return "", err
	}
	if len(destination) == 0 || sign == nil {
		return "", ErrDomain
	}
	unsigned := domain + "=" + i2pBase64.EncodeToString(destination)
	signature, err := sign([]byte(unsigned))
	if err != nil {
		return "", err
	}
	return unsigned + "#!sig=" + i2pBase64.EncodeToString(signature), nil
}

// Ed25519Signer returns a registration signer for a 32-byte Ed25519 seed or
// a full 64-byte Ed25519 private key.
func Ed25519Signer(private []byte) (Signer, error) {
	var key ed25519.PrivateKey
	switch len(private) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(private)
	case ed25519.PrivateKeySize:
		key = ed25519.PrivateKey(private)
	default:
		return nil, ErrDomain
	}
	return func(message []byte) ([]byte, error) { return ed25519.Sign(key, message), nil }, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !strings.HasSuffix(domain, ".i2p") || len(domain) <= len(".i2p") || len(domain) > 255 {
		return "", ErrDomain
	}
	for _, character := range domain {
		if !(character == '.' || character == '-' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			return "", ErrDomain
		}
	}
	return domain, nil
}
