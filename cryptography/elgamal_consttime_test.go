package cryptography

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
	mrand "math/rand/v2"
	"testing"
)

// decryptElGamalBigInt is the original variable-time math/big decryption. It is
// kept as a reference so the constant-time path can be checked for identical
// results, including identical rejection, across fixed and random inputs.
func decryptElGamalBigInt(dst []byte, private ElGamalPrivateKey, ciphertext []byte) ([]byte, error) {
	if len(dst) < ElGamalPlaintextSize || len(ciphertext) != ElGamalCiphertextSize || ciphertext[0] != 0 || ciphertext[257] != 0 {
		return nil, ErrElGamal
	}
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(private[:])
	if x.Sign() <= 0 || x.Cmp(pMinusTwo) > 0 {
		return nil, ErrElGamal
	}
	a := new(big.Int).SetBytes(ciphertext[1:257])
	b := new(big.Int).SetBytes(ciphertext[258:])
	if a.Sign() <= 0 || a.Cmp(p) >= 0 || b.Sign() <= 0 || b.Cmp(p) >= 0 {
		return nil, ErrElGamal
	}
	exponent := new(big.Int).Sub(p, big.NewInt(1))
	exponent.Sub(exponent, x)
	inverse := new(big.Int).Exp(a, exponent, p)
	m := new(big.Int).Mul(b, inverse)
	m.Mod(m, p)
	if m.BitLen() > 255*8 {
		return nil, ErrElGamal
	}
	var encoded [255]byte
	m.FillBytes(encoded[:])
	if encoded[0] != 0xff {
		return nil, ErrElGamal
	}
	hash := sha256.Sum256(encoded[33:])
	if subtle.ConstantTimeCompare(encoded[1:33], hash[:]) != 1 {
		return nil, ErrElGamal
	}
	copy(dst[:ElGamalPlaintextSize], encoded[33:])
	return dst[:ElGamalPlaintextSize], nil
}

func assertElGamalDecryptMatchesReference(t *testing.T, name string, private ElGamalPrivateKey, ciphertext []byte) {
	t.Helper()
	got, gotErr := DecryptElGamal(make([]byte, ElGamalPlaintextSize), private, ciphertext)
	want, wantErr := decryptElGamalBigInt(make([]byte, ElGamalPlaintextSize), private, ciphertext)
	if gotErr != wantErr || !bytes.Equal(got, want) {
		t.Fatalf("%s: DecryptElGamal() = %x, %v; reference = %x, %v", name, got, gotErr, want, wantErr)
	}
}

// elGamalCiphertextFor builds a ciphertext (a, b) for an arbitrary 255-byte
// representative m under public key y, so tests can reach every post-decryption
// branch (valid block, bad prefix, bad hash, oversize representative).
func elGamalCiphertextFor(t *testing.T, public ElGamalPublicKey, m *big.Int) []byte {
	t.Helper()
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		t.Fatal(err)
	}
	k, err := rand.Int(rand.Reader, pMinusTwo)
	if err != nil {
		t.Fatal(err)
	}
	k.Add(k, big.NewInt(1))
	y := new(big.Int).SetBytes(public[:])
	a := new(big.Int).Exp(big.NewInt(2), k, p)
	b := new(big.Int).Exp(y, k, p)
	b.Mul(b, m)
	b.Mod(b, p)
	out := make([]byte, ElGamalCiphertextSize)
	a.FillBytes(out[1:257])
	b.FillBytes(out[258:])
	return out
}

func TestElGamalConstantTimeDecryptMatchesReferenceOnEdgeCases(t *testing.T) {
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		t.Fatal(err)
	}
	var privateOne, privateMax, privateMinusOne, privateZero, privateP, privateAllOnes ElGamalPrivateKey
	privateOne[ElGamalPrivateKeySize-1] = 1
	pMinusTwo.FillBytes(privateMax[:])
	new(big.Int).Add(pMinusTwo, big.NewInt(1)).FillBytes(privateMinusOne[:])
	p.FillBytes(privateP[:])
	for i := range privateAllOnes {
		privateAllOnes[i] = 0xff
	}
	_, privateRandom, err := GenerateElGamalKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pBytes := p.FillBytes(make([]byte, 256))
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1)).FillBytes(make([]byte, 256))
	one := big.NewInt(1).FillBytes(make([]byte, 256))
	zero := make([]byte, 256)
	allOnes := bytes.Repeat([]byte{0xff}, 256)

	build := func(a, b []byte) []byte {
		out := make([]byte, ElGamalCiphertextSize)
		copy(out[1:257], a)
		copy(out[258:], b)
		return out
	}
	ciphertexts := map[string][]byte{
		"a=0":         build(zero, one),
		"b=0":         build(one, zero),
		"a=p":         build(pBytes, one),
		"b=p":         build(one, pBytes),
		"a=ff..":      build(allOnes, one),
		"b=ff..":      build(one, allOnes),
		"a=1,b=1":     build(one, one),
		"a=1,b=p-1":   build(one, pMinusOne),
		"a=p-1,b=p-1": build(pMinusOne, pMinusOne),
		"a=p-1,b=1":   build(pMinusOne, one),
		"prefix0":     append([]byte{1}, build(one, one)[1:]...),
		"short":       build(one, one)[:ElGamalCiphertextSize-1],
	}
	mid := build(one, one)
	mid[257] = 1
	ciphertexts["prefix257"] = mid

	keys := map[string]ElGamalPrivateKey{
		"x=1":      privateOne,
		"x=p-2":    privateMax,
		"x=p-1":    privateMinusOne,
		"x=0":      privateZero,
		"x=p":      privateP,
		"x=ff..":   privateAllOnes,
		"x=random": privateRandom,
	}
	for keyName, key := range keys {
		for ctName, ct := range ciphertexts {
			assertElGamalDecryptMatchesReference(t, keyName+"/"+ctName, key, ct)
		}
	}
}

func TestElGamalConstantTimeDecryptMatchesReferenceOnRandomInputs(t *testing.T) {
	iterations := 32
	if testing.Short() {
		iterations = 8
	}
	seed := mrand.Uint64()
	t.Logf("seed %d", seed)
	rng := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for i := range iterations {
		public, private, err := GenerateElGamalKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		plaintext := make([]byte, ElGamalPlaintextSize)
		for j := range plaintext {
			plaintext[j] = byte(rng.Uint32())
		}

		valid, err := EncryptElGamal(make([]byte, ElGamalCiphertextSize), public, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		assertElGamalDecryptMatchesReference(t, "valid", private, valid)
		opened, err := DecryptElGamal(make([]byte, ElGamalPlaintextSize), private, valid)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("iteration %d: round trip = %x, %v", i, opened, err)
		}

		var encoded [255]byte
		encoded[0] = 0xff
		hash := sha256.Sum256(plaintext)
		copy(encoded[1:33], hash[:])
		copy(encoded[33:], plaintext)

		badHash := encoded
		badHash[1+rng.IntN(32)] ^= byte(1 + rng.IntN(255))
		assertElGamalDecryptMatchesReference(t, "bad hash", private,
			elGamalCiphertextFor(t, public, new(big.Int).SetBytes(badHash[:])))

		badPrefix := encoded
		badPrefix[0] = byte(rng.IntN(255))
		assertElGamalDecryptMatchesReference(t, "bad prefix", private,
			elGamalCiphertextFor(t, public, new(big.Int).SetBytes(badPrefix[:])))

		oversize := new(big.Int).SetBytes(encoded[:])
		oversize.Add(oversize, new(big.Int).Lsh(big.NewInt(int64(1+rng.IntN(255))), 255*8))
		assertElGamalDecryptMatchesReference(t, "oversize", private,
			elGamalCiphertextFor(t, public, oversize))

		garbage := make([]byte, ElGamalCiphertextSize)
		for j := range garbage {
			garbage[j] = byte(rng.Uint32())
		}
		garbage[0], garbage[257] = 0, 0
		if rng.IntN(2) == 0 {
			garbage[1] &= 0x7f
			garbage[258] &= 0x7f
		}
		assertElGamalDecryptMatchesReference(t, "garbage", private, garbage)

		flipped := append([]byte(nil), valid...)
		flipped[1+rng.IntN(ElGamalCiphertextSize-1)] ^= byte(1 + rng.IntN(255))
		assertElGamalDecryptMatchesReference(t, "flipped", private, flipped)
	}
}

func BenchmarkElGamalDecrypt(b *testing.B) {
	public, private, err := GenerateElGamalKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	ciphertext, err := EncryptElGamal(make([]byte, ElGamalCiphertextSize), public, make([]byte, ElGamalPlaintextSize))
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, ElGamalPlaintextSize)
	b.Run("constant-time", func(b *testing.B) {
		for b.Loop() {
			if _, err := DecryptElGamal(dst, private, ciphertext); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("math-big-reference", func(b *testing.B) {
		for b.Loop() {
			if _, err := decryptElGamalBigInt(dst, private, ciphertext); err != nil {
				b.Fatal(err)
			}
		}
	})
}
