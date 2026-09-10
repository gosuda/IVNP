package noise

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"gosuda.org/ivnp/cryptography"
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

func TestKDF2MatchesKnownAnswerVectors(t *testing.T) {
	// Noise HKDF with SHA-256, independently evaluated with Python hmac.digest.
	tests := []struct {
		name, key, input string
		first, second    string
	}{
		{
			name: "baseline", key: "chain", input: "input",
			first:  "0ad098edfae70064fa085efc4fd36ad923fac173c7be2ebad75d8165522c2a46",
			second: "16d4e090e54c028de0a9a2441ca97f53c1160ce5337c693e5f2a993e5d0463bc",
		},
		{
			name: "changed input", key: "chain", input: "other input",
			first:  "58e0543f98b5e27bef5f176f0f55faa89090cf52119d9cad588dd7c648a71820",
			second: "24850fdc0bb9a81a8b489380fd6ef90bbd6d535b9a3593c4a57cb2384b1c5601",
		},
		{
			name: "changed chaining key", key: "other chain", input: "input",
			first:  "440b67337f7b88e5e41f00e684cb1f1a3a107d02b5cf22f3f68b08b55f3a11cc",
			second: "7c953578a22ce57c485408d07664c05be6c497f0127c0b29963c6851f2c4850b",
		},
		{
			name: "empty input", key: "chain",
			first:  "af5ca53c6b5df1f431b6d7a1b80ca4297c9efa0b2acab32869546246d0c59a82",
			second: "ee5ea8ef9b43b669fa462bc23a56e178399b426fe87744ee72d3cac4d16ef01b",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, second := kdf2([]byte(test.key), []byte(test.input))
			if got := hex.EncodeToString(first[:]); got != test.first {
				t.Errorf("first output = %s, want %s", got, test.first)
			}
			if got := hex.EncodeToString(second[:]); got != test.second {
				t.Errorf("second output = %s, want %s", got, test.second)
			}
		})
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
