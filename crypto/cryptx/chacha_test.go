package cryptx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestChaCha20Poly1305UsesCallerBuffers(t *testing.T) {
	key := make([]byte, ChaChaKeySize)
	nonce := make([]byte, ChaChaNonceSize)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i + 32)
	}
	cipherState, err := NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("i2p transport frame")
	sealedStorage := make([]byte, len(plaintext)+ChaChaTagSize)
	sealed, err := cipherState.SealTo(sealedStorage, nonce, plaintext, []byte("header"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != len(sealedStorage) || &sealed[0] != &sealedStorage[0] {
		t.Fatalf("SealTo did not retain caller storage")
	}
	openedStorage := make([]byte, len(plaintext))
	opened, err := cipherState.OpenTo(openedStorage, nonce, sealed, []byte("header"))
	if err != nil || !bytes.Equal(opened, plaintext) || &opened[0] != &openedStorage[0] {
		t.Fatalf("OpenTo() = %q, %v", opened, err)
	}
	if _, err := cipherState.SealTo(sealedStorage[:len(sealedStorage)-1], nonce, plaintext, nil); !errors.Is(err, ErrDestination) {
		t.Fatalf("short output error = %v", err)
	}
}

func TestDirectChaCha20Poly1305MatchesRetainedCipher(t *testing.T) {
	key := bytes.Repeat([]byte{3}, ChaChaKeySize)
	nonce := bytes.Repeat([]byte{4}, ChaChaNonceSize)
	plaintext := bytes.Repeat([]byte{5}, 37)
	aad := bytes.Repeat([]byte{6}, 19)
	state, err := NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := state.SealTo(make([]byte, len(plaintext)+ChaChaTagSize), nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SealChaCha20Poly1305To(make([]byte, len(plaintext)+ChaChaTagSize), key, nonce, plaintext, aad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("direct seal mismatch: %x / %x, %v", got, want, err)
	}
	opened, err := OpenChaCha20Poly1305To(make([]byte, len(plaintext)), key, nonce, got, aad)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("direct open = %x, %v", opened, err)
	}
	got[len(got)-1] ^= 1
	if _, err = OpenChaCha20Poly1305To(make([]byte, len(plaintext)), key, nonce, got, aad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered direct open = %v", err)
	}
}

func TestChaCha20LengthValidation(t *testing.T) {
	if _, err := NewChaCha20Poly1305(nil); !errors.Is(err, ErrKeyLength) {
		t.Fatalf("NewChaCha20Poly1305(nil) = %v", err)
	}
	key := make([]byte, ChaChaKeySize)
	state, err := NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.SealTo(make([]byte, ChaChaTagSize), nil, nil, nil); !errors.Is(err, ErrNonceLength) {
		t.Fatalf("bad nonce error = %v", err)
	}
}

func TestI2PRawChaCha20StartsAtCounterOne(t *testing.T) {
	key := make([]byte, ChaChaKeySize)
	for index := range key {
		key[index] = byte(index)
	}
	nonce, err := hex.DecodeString("000000090000004a00000000")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := NewChaCha20Stream(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	stream.XORKeyStream(got, got)
	want, err := hex.DecodeString("10f1e7e4d13b5915500fdd1fa32071c4")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("I2P raw ChaCha20 block = %x, want %x", got, want)
	}
}

func TestChaChaReleaseZeroizesAndRejectsUse(t *testing.T) {
	key := bytes.Repeat([]byte{1}, ChaChaKeySize)
	state, err := NewChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	state.ReleaseSensitive()
	state.ReleaseSensitive()
	if state.key != [ChaChaKeySize]byte{} || !state.released {
		t.Fatal("released cipher retained key")
	}
	if _, err := state.SealTo(make([]byte, ChaChaTagSize), make([]byte, ChaChaNonceSize), nil, nil); !errors.Is(err, ErrSensitiveReleased) {
		t.Fatalf("SealTo after release = %v", err)
	}
}

func BenchmarkChaChaSealTo(b *testing.B) {
	state, err := NewChaCha20Poly1305(make([]byte, ChaChaKeySize))
	if err != nil {
		b.Fatal(err)
	}
	var nonce [ChaChaNonceSize]byte
	plaintext := make([]byte, 1024)
	dst := make([]byte, len(plaintext)+ChaChaTagSize)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := state.SealTo(dst, nonce[:], plaintext, nil); err != nil {
			b.Fatal(err)
		}
		nonce[len(nonce)-1]++
	}
}
