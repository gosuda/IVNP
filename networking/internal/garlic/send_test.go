package garlic

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestEncryptExistingRoundTrip(t *testing.T) {
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 9, 8
	delivered := make([]byte, 32)
	delivered[0] = 7
	packet, err := EncryptExisting(make([]byte, 128), tag, key, []byte("payload"), delivered)
	if err != nil {
		t.Fatal(err)
	}
	first, err := EncryptExisting(make([]byte, 128), tag, key, []byte("payload"), delivered)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptExisting(make([]byte, 128), tag, key, []byte("payload"), delivered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("random padding produced deterministic ciphertext")
	}
	payload, tags, err := DecryptExisting(make([]byte, len(packet)-32), tag, key, packet[32:])
	if err != nil || !bytes.Equal(payload, []byte("payload")) || !bytes.Equal(tags, delivered) {
		t.Fatalf("round trip = %q / %x / %v", payload, tags, err)
	}
}

func TestDecryptExistingNewSessionKey(t *testing.T) {
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 1, 2
	delivered := make([]byte, 32)
	delivered[0] = 3
	replacement := bytes.Repeat([]byte{4}, 32)
	payload := []byte("replacement key")
	plainLen := 2 + len(delivered) + 4 + 32 + 1 + len(replacement) + len(payload)
	plaintext := make([]byte, (plainLen+aes.BlockSize-1)&^(aes.BlockSize-1))
	binary.BigEndian.PutUint16(plaintext[:2], 1)
	copy(plaintext[2:], delivered)
	off := 2 + len(delivered)
	binary.BigEndian.PutUint32(plaintext[off:off+4], uint32(len(payload)))
	off += 4
	hash := sha256.Sum256(payload)
	copy(plaintext[off:off+32], hash[:])
	off += 32
	plaintext[off] = 1
	off++
	copy(plaintext[off:off+len(replacement)], replacement)
	off += len(replacement)
	copy(plaintext[off:], payload)

	ciphertext := encryptSessionTestBody(t, tag, key, plaintext)
	gotPayload, gotTags, gotKey, replaceKey, err := decryptExisting(make([]byte, len(ciphertext)), tag, key, ciphertext)
	if err != nil || !replaceKey || !bytes.Equal(gotPayload, payload) || !bytes.Equal(gotTags, delivered) || !bytes.Equal(gotKey[:], replacement) {
		t.Fatalf("decrypt = payload %q, tags %x, key %x, replacement %t, err %v", gotPayload, gotTags, gotKey, replaceKey, err)
	}

	plaintext[2+len(delivered)+4+32] = 2
	if _, _, _, _, err := decryptExisting(make([]byte, len(ciphertext)), tag, key, encryptSessionTestBody(t, tag, key, plaintext)); err == nil {
		t.Fatal("accepted invalid new-session-key flag")
	}
	truncated := make([]byte, aes.BlockSize*3)
	truncated[38] = 1
	if _, _, _, _, err := decryptExisting(make([]byte, len(truncated)), tag, key, encryptSessionTestBody(t, tag, key, truncated)); err == nil {
		t.Fatal("accepted truncated replacement key")
	}
}

func legacyReplacementPacket(t *testing.T, tag, key, delivered, replacement, payload []byte) []byte {
	t.Helper()
	plainLen := 2 + len(delivered) + 4 + 32 + 1 + len(replacement) + len(payload)
	plaintext := make([]byte, (plainLen+aes.BlockSize-1)&^(aes.BlockSize-1))
	binary.BigEndian.PutUint16(plaintext[:2], uint16(len(delivered)/32))
	copy(plaintext[2:], delivered)
	off := 2 + len(delivered)
	binary.BigEndian.PutUint32(plaintext[off:off+4], uint32(len(payload)))
	off += 4
	hash := sha256.Sum256(payload)
	copy(plaintext[off:off+32], hash[:])
	off += 32
	plaintext[off] = 1
	off++
	copy(plaintext[off:off+len(replacement)], replacement)
	off += len(replacement)
	copy(plaintext[off:], payload)
	return encryptSessionTestBody(t, tag, key, plaintext)
}

func encryptSessionTestBody(t *testing.T, tag, key, plaintext []byte) []byte {
	t.Helper()
	iv := sha256.Sum256(tag)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plaintext))
	previous := iv[:aes.BlockSize]
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		for i := range aes.BlockSize {
			ciphertext[offset+i] = plaintext[offset+i] ^ previous[i]
		}
		block.Encrypt(ciphertext[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
		previous = ciphertext[offset : offset+aes.BlockSize]
	}
	return ciphertext
}
