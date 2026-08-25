package cryptx

import (
	"bytes"
	"errors"
	"testing"
)

func TestX25519PrivateKeyReleaseSensitive(t *testing.T) {
	encoded := bytes.Repeat([]byte{0x42}, 32)
	key, err := NewX25519PrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	key.ReleaseSensitive()
	key.ReleaseSensitive()
	if key.scalar != ([32]byte{}) || !key.released {
		t.Fatal("X25519 private scalar remained after release")
	}
	var output [32]byte
	output[0] = 1
	if err = key.PublicKey(&output); !errors.Is(err, ErrSensitiveReleased) || output != ([32]byte{}) {
		t.Fatalf("PublicKey after release = %x, %v", output, err)
	}
	output[0] = 1
	if err = key.ECDH(&output, make([]byte, 32)); !errors.Is(err, ErrSensitiveReleased) || output != ([32]byte{}) {
		t.Fatalf("ECDH after release = %x, %v", output, err)
	}
}
