package cryptx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Vector copied from libi2pd tests/test-aeadchacha20poly1305.cpp.
func TestI2PDAEADChaCha20Poly1305Vector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	additionalData := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	expected := mustHex(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
	state, err := NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := state.SealTo(make([]byte, len(expected)), nonce, plaintext, additionalData)
	if err != nil || !bytes.Equal(sealed, expected) {
		t.Fatalf("SealTo() = %x, %v", sealed, err)
	}
	opened, err := state.OpenTo(make([]byte, len(plaintext)), nonce, sealed, additionalData)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenTo() = %q, %v", opened, err)
	}
}

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
