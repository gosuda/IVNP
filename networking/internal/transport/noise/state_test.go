package noise

import (
	"bytes"
	"errors"
	"gosuda.org/ivnp/cryptography"
	"math"
	"testing"
)

func TestSymmetricStateTranscriptAndCipher(t *testing.T) {
	left := Initialize("Noise_XK_25519_ChaChaPoly_SHA256")
	right := Initialize("Noise_XK_25519_ChaChaPoly_SHA256")
	transcript := []byte("prologue and ephemeral key")
	if err := left.MixHash(transcript); err != nil {
		t.Fatal(err)
	}
	if err := right.MixHash(transcript); err != nil {
		t.Fatal(err)
	}
	shared := bytes.Repeat([]byte{7}, 32)
	if err := left.MixKey(shared); err != nil {
		t.Fatal(err)
	}
	if err := right.MixKey(shared); err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len("payload")+16)
	sealed, err := left.EncryptAndHash(ciphertext, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := right.DecryptAndHash(make([]byte, len("payload")), sealed)
	if err != nil || string(plaintext) != "payload" {
		t.Fatalf("DecryptAndHash() = %q, %v", plaintext, err)
	}
	if left.Hash() != right.Hash() {
		t.Fatal("transcript hashes diverged")
	}
}

func TestSymmetricStateNonceLimit(t *testing.T) {
	state := Initialize("test")
	if err := state.MixKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	state.nonce = math.MaxUint64 - 1
	if _, err := state.EncryptAndHash(make([]byte, 16), nil); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("nonce error = %v", err)
	}
}

func TestKDF2ChangesBothOutputs(t *testing.T) {
	first, second := kdf2([]byte("chain"), []byte("input"))
	if first == second || first == [32]byte{} || second == [32]byte{} {
		t.Fatal("KDF outputs are not independent")
	}
}

func TestSymmetricStateReleaseZeroizesAndRejectsUse(t *testing.T) {
	state := Initialize("release")
	if err := state.MixKey(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	cipher := state.cipher
	state.ReleaseSensitive()
	state.ReleaseSensitive()
	if state.chainingKey != [32]byte{} || state.hash != [32]byte{} || state.nonce != 0 || state.hasKey || !state.released {
		t.Fatalf("released state retained key material: %#v", state)
	}
	if cipher == nil {
		t.Fatal("released Noise child cipher was lost")
	}
	if _, err := cipher.SealTo(make([]byte, cryptography.ChaChaTagSize), make([]byte, cryptography.ChaChaNonceSize), nil, nil); !errors.Is(err, cryptography.ErrSensitiveReleased) {
		t.Fatalf("released Noise child cipher remained usable: %v", err)
	}
	if _, err := state.EncryptAndHash(make([]byte, 16), nil); !errors.Is(err, cryptography.ErrSensitiveReleased) {
		t.Fatalf("EncryptAndHash after release = %v", err)
	}
}
