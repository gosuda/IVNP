package garlic

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"gosuda.org/ivnp/networking/internal/i2np"
)

// EncryptExisting writes tag || AES-CBC(session block) into dst. deliveredTags
// is a flat sequence of 32-byte tags. Padding is drawn from crypto/rand before
// encryption so equal payloads cannot be correlated by deterministic tails.
func EncryptExisting(dst, tag, key, payload, deliveredTags []byte) ([]byte, error) {
	if len(tag) != 32 || len(dst) < 32 {
		return nil, ErrSession
	}
	copy(dst[:32], tag)
	body, err := encryptSessionBody(dst[32:], tag, key, payload, deliveredTags)
	if err != nil {
		return nil, err
	}
	return dst[:32+len(body)], nil
}

// encryptSessionBody writes just the CBC-encrypted legacy Garlic session
// block, deriving its IV from SHA256(ivMaterial).
func encryptSessionBody(dst, ivMaterial, key, payload, deliveredTags []byte) ([]byte, error) {
	if len(ivMaterial) != 32 || len(key) != 32 || len(payload) > i2np.I2PDMaxPayload || len(deliveredTags)%32 != 0 || len(deliveredTags)/32 > MaxSessionTags {
		return nil, ErrSession
	}
	const fixed = 2 + 4 + 32 + 1
	if len(deliveredTags) > i2np.I2PDMaxPayload-fixed || len(payload) > i2np.I2PDMaxPayload-fixed-len(deliveredTags) {
		return nil, ErrSession
	}
	plainLen := fixed + len(deliveredTags) + len(payload)
	cipherLen := (plainLen + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	if len(dst) < cipherLen {
		return nil, ErrSession
	}
	plain := dst[:cipherLen]
	clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(deliveredTags)/32))
	copy(plain[2:2+len(deliveredTags)], deliveredTags)
	off := 2 + len(deliveredTags)
	binary.BigEndian.PutUint32(plain[off:off+4], uint32(len(payload)))
	off += 4
	hash := sha256.Sum256(payload)
	copy(plain[off:off+32], hash[:])
	off += 33 // hash plus zero new-session-key flag
	copy(plain[off:off+len(payload)], payload)
	if _, randomErr := rand.Read(plain[plainLen:]); randomErr != nil {
		return nil, randomErr
	}
	ivHash := sha256.Sum256(ivMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var previous [aes.BlockSize]byte
	copy(previous[:], ivHash[:aes.BlockSize])
	for offset := 0; offset < len(plain); offset += aes.BlockSize {
		for i := range previous {
			plain[offset+i] ^= previous[i]
		}
		block.Encrypt(plain[offset:offset+aes.BlockSize], plain[offset:offset+aes.BlockSize])
		copy(previous[:], plain[offset:offset+aes.BlockSize])
	}
	return plain, nil
}
