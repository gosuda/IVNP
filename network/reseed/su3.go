package reseed

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	ivnp "gosuda.org/ivnp/i2p"
	"math/big"
)

const (
	su3HeaderLen         = 40
	su3FileVersion       = 0
	su3MinimumVersion    = 16
	su3FileTypeZIP       = 0
	su3ContentTypeReseed = 3
	su3RSASignatureLen   = 512
)

var (
	ErrSU3Malformed = errors.New("reseed: malformed SU3 container")
	ErrSU3Signer    = errors.New("reseed: untrusted or unsupported SU3 signer")
	ErrSU3Signature = errors.New("reseed: invalid SU3 signature")
)

// SU3Signer is a pinned reseed signing key. Current reseed SU3 deployments
// use Java NONEwithRSA over the raw SHA-512 digest.
type SU3Signer struct {
	SigningType ivnp.SigningKeyType
	PublicKey   []byte
}

// VerifySU3 validates the complete container and returns the ZIP content view.
// The returned slice aliases container. maxContent limits only signed content;
// callers still apply their archive transport-size limit before this function.
func VerifySU3(container []byte, signers map[string]SU3Signer, maxContent int64) ([]byte, error) {
	if maxContent < 0 || len(container) < su3HeaderLen || !bytes.Equal(container[:6], []byte("I2Psu3")) ||
		container[6] != 0 || container[7] != su3FileVersion {
		return nil, ErrSU3Malformed
	}
	signingType := ivnp.SigningKeyType(binary.BigEndian.Uint16(container[8:10]))
	signatureLen := int(binary.BigEndian.Uint16(container[10:12]))
	versionLen := int(container[13])
	signerLen := int(container[15])
	contentLen := binary.BigEndian.Uint64(container[16:24])
	verifySU3Rejected := signingType != ivnp.SigningRSASHA512_4096 || signatureLen != su3RSASignatureLen ||
		versionLen < su3MinimumVersion || signerLen == 0 || container[12] != 0 ||
		container[14] != 0 || container[24] != 0 || container[25] != su3FileTypeZIP ||
		container[26] != 0 || container[27] != su3ContentTypeReseed ||
		!allZero(container[28:su3HeaderLen]) || contentLen == 0
	if !verifySU3Rejected {
		verifySU3Rejected = contentLen > uint64(maxContent)
	}
	if verifySU3Rejected {
		return nil, ErrSU3Malformed
	}
	contentStart := su3HeaderLen + versionLen + signerLen
	if contentStart < su3HeaderLen || contentStart > len(container) || contentLen > uint64(len(container)-contentStart) {
		return nil, ErrSU3Malformed
	}
	contentEnd := contentStart + int(contentLen)
	if signatureLen != len(container)-contentEnd {
		return nil, ErrSU3Malformed
	}
	signerID := string(container[su3HeaderLen+versionLen : contentStart])
	signer, found := signers[signerID]
	if !found || signer.SigningType != signingType {
		return nil, ErrSU3Signer
	}
	if !verifySU3Signature(signer, container[:contentEnd], container[contentEnd:]) {
		return nil, ErrSU3Signature
	}
	return container[contentStart:contentEnd], nil
}

func allZero(data []byte) bool {
	var combined byte
	for _, value := range data {
		combined |= value
	}
	return combined == 0
}

func verifySU3Signature(signer SU3Signer, signed, signature []byte) bool {
	if signer.SigningType != ivnp.SigningRSASHA512_4096 || len(signer.PublicKey) != su3RSASignatureLen || len(signature) != su3RSASignatureLen {
		return false
	}
	modulus := new(big.Int).SetBytes(signer.PublicKey)
	if modulus.Sign() <= 0 || modulus.BitLen() != su3RSASignatureLen*8 {
		return false
	}
	digest := sha512.Sum512(signed)
	publicKey := rsa.PublicKey{N: modulus, E: 65537}
	// crypto.Hash(0) makes VerifyPKCS1v15 require the exact digest bytes after
	// strict 00 01 FF...FF 00 padding, matching Java's NONEwithRSA encoding.
	return rsa.VerifyPKCS1v15(&publicKey, crypto.Hash(0), digest[:], signature) == nil
}
