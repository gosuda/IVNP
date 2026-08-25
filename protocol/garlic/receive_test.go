package garlic

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestReceiveExistingConsumesTagAndDecrypts(t *testing.T) {
	tag, key := make([]byte, 32), make([]byte, 32)
	tag[0], key[0] = 1, 2
	plaintext := make([]byte, 48)
	binary.BigEndian.PutUint32(plaintext[2:6], 4)
	payloadHash := sha256.Sum256([]byte("test"))
	copy(plaintext[6:38], payloadHash[:])
	copy(plaintext[39:43], []byte("test"))
	iv := sha256.Sum256(tag)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plaintext))
	previous := iv[:16]
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		for i := 0; i < aes.BlockSize; i++ {
			ciphertext[offset+i] = plaintext[offset+i] ^ previous[i]
		}
		block.Encrypt(ciphertext[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
		previous = ciphertext[offset : offset+aes.BlockSize]
	}
	store := NewTagStore(1)
	store.Put(tag, key, 10)
	payload, _, err := ReceiveExisting(make([]byte, len(ciphertext)), append(tag, ciphertext...), store, 1)
	if err != nil || !bytes.Equal(payload, []byte("test")) {
		t.Fatalf("ReceiveExisting() = %q, %v", payload, err)
	}
	if _, _, err := ReceiveExisting(make([]byte, len(ciphertext)), append(tag, ciphertext...), store, 1); err == nil {
		t.Fatal("consumed tag reused")
	}
}
