package garlic

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const MaxSessionTags = 200

var ErrSession = errors.New("garlic: invalid session message")

// DecryptExisting decrypts an existing-session AES block for tag/key and
// returns the payload plus delivered tags as zero-copy views of plaintext.
// It accepts the legacy new-session-key flag but discards a replacement key;
// callers that retain delivered tags must use decryptExisting.
func DecryptExisting(dst, tag, key, ciphertext []byte) (payload []byte, tags []byte, err error) {
	payload, tags, replacement, _, err := decryptExisting(dst, tag, key, ciphertext)
	clear(replacement[:])
	return payload, tags, err
}

// decryptExisting returns a verified replacement key when the legacy
// new-session-key flag is set. The key must be associated with delivered tags,
// not used to decrypt this already-opened message.
func decryptExisting(dst, tag, key, ciphertext []byte) (payload []byte, tags []byte, replacement [32]byte, replaceKey bool, err error) {
	if len(tag) != 32 || len(key) != 32 || len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 || len(dst) < len(ciphertext) {
		return nil, nil, replacement, false, ErrSession
	}
	ivHash := sha256.Sum256(tag)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, replacement, false, err
	}
	var previous [aes.BlockSize]byte
	copy(previous[:], ivHash[:aes.BlockSize])
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		var current [aes.BlockSize]byte
		copy(current[:], ciphertext[offset:offset+aes.BlockSize])
		block.Decrypt(dst[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
		for i := range previous {
			dst[offset+i] ^= previous[i]
		}
		previous = current
	}
	if len(ciphertext) < 2 {
		return nil, nil, replacement, false, ErrSession
	}
	count := int(binary.BigEndian.Uint16(dst[:2]))
	if count > MaxSessionTags || 2+count*32+4+32+1 > len(ciphertext) {
		return nil, nil, replacement, false, ErrSession
	}
	off := 2 + count*32
	size := int(binary.BigEndian.Uint32(dst[off : off+4]))
	off += 4
	hash := dst[off : off+32]
	off += 32
	flag := dst[off]
	off++
	switch flag {
	case 0:
	case 1:
		if off+len(replacement) > len(ciphertext) {
			return nil, nil, replacement, false, ErrSession
		}
		copy(replacement[:], dst[off:off+len(replacement)])
		off += len(replacement)
		replaceKey = true
	default:
		return nil, nil, replacement, false, ErrSession
	}
	if size > len(ciphertext)-off {
		return nil, nil, replacement, false, ErrSession
	}
	payloadHash := sha256.Sum256(dst[off : off+size])
	if subtle.ConstantTimeCompare(hash, payloadHash[:]) != 1 {
		clear(replacement[:])
		return nil, nil, replacement, false, ErrSession
	}
	return dst[off : off+size], dst[2 : 2+count*32], replacement, replaceKey, nil
}
