package cryptography

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

const (
	// ElGamalPublicKeySize is the byte length of an I2P legacy ElGamal public key.
	ElGamalPublicKeySize = 256
	// ElGamalPrivateKeySize is the byte length of an I2P legacy ElGamal private key.
	ElGamalPrivateKeySize = 256
	// ElGamalPlaintextSize is the fixed plaintext size for an I2P legacy ElGamal block.
	ElGamalPlaintextSize = 222
	// ElGamalCiphertextSize is the wire size of an encrypted I2P legacy ElGamal block.
	ElGamalCiphertextSize = 514
)

// ElGamalPublicKey is a 2048-bit ElGamal public key in big-endian byte order.
type ElGamalPublicKey [ElGamalPublicKeySize]byte

// ElGamalPrivateKey is a 2048-bit ElGamal private exponent in big-endian byte order.
type ElGamalPrivateKey [ElGamalPrivateKeySize]byte

var (
	ErrElGamal           = errors.New("cryptx: invalid ElGamal block")
	errElGamalParameters = errors.New("cryptx: invalid static ElGamal parameters")
)

// elGamalPrimeHex represents RFC 3526 MODP group 14, used by legacy I2P ElGamal.
// We keep it encoded as a string literal so package consumers cannot mutate the shared big.Int.
const elGamalPrimeHex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
	"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
	"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
	"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
	"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

func elGamalParameters() (p, pMinusTwo *big.Int, err error) {
	p, ok := new(big.Int).SetString(elGamalPrimeHex, 16)
	if !ok {
		return nil, nil, errElGamalParameters
	}
	return p, new(big.Int).Sub(p, big.NewInt(2)), nil
}

// GenerateElGamalKeyPair generates a random private exponent and corresponding public key.
func GenerateElGamalKeyPair() (public ElGamalPublicKey, private ElGamalPrivateKey, err error) {
	return generateElGamalKeyPair(rand.Reader)
}

func generateElGamalKeyPair(random io.Reader) (public ElGamalPublicKey, private ElGamalPrivateKey, err error) {
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		return public, private, err
	}
	x, err := rand.Int(random, pMinusTwo)
	if err != nil {
		return public, private, err
	}
	x.Add(x, big.NewInt(1)) // 1 <= x <= p - 2
	x.FillBytes(private[:])
	new(big.Int).Exp(big.NewInt(2), x, p).FillBytes(public[:])
	return public, private, nil
}

// ElGamalPublicFromPrivate derives the public key from an existing private key.
func ElGamalPublicFromPrivate(private ElGamalPrivateKey) (public ElGamalPublicKey, err error) {
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		return public, err
	}
	x := new(big.Int).SetBytes(private[:])
	if x.Sign() <= 0 || x.Cmp(pMinusTwo) > 0 {
		return public, ErrElGamal
	}
	new(big.Int).Exp(big.NewInt(2), x, p).FillBytes(public[:])
	return public, nil
}

// EncryptElGamal encrypts 222 bytes of plaintext for public into dst using I2P's legacy format:
// 0x00 || a[256] || 0x00 || b[256], where m = 0xff || SHA256(plaintext) || plaintext.
func EncryptElGamal(dst []byte, public ElGamalPublicKey, plaintext []byte) ([]byte, error) {
	return encryptElGamal(rand.Reader, dst, public, plaintext)
}

func encryptElGamal(random io.Reader, dst []byte, public ElGamalPublicKey, plaintext []byte) ([]byte, error) {
	if len(dst) < ElGamalCiphertextSize || len(plaintext) != ElGamalPlaintextSize {
		return nil, ErrElGamal
	}
	p, pMinusTwo, err := elGamalParameters()
	if err != nil {
		return nil, err
	}
	y := new(big.Int).SetBytes(public[:])
	if y.Sign() <= 0 || y.Cmp(p) >= 0 {
		return nil, ErrElGamal
	}
	k, err := rand.Int(random, pMinusTwo)
	if err != nil {
		return nil, err
	}
	k.Add(k, big.NewInt(1)) // 1 <= k <= p - 2

	a := new(big.Int).Exp(big.NewInt(2), k, p)
	shared := new(big.Int).Exp(y, k, p)
	var m [255]byte
	m[0] = 0xff
	hash := sha256.Sum256(plaintext)
	copy(m[1:33], hash[:])
	copy(m[33:], plaintext)
	b := new(big.Int).Mul(shared, new(big.Int).SetBytes(m[:]))
	b.Mod(b, p)

	out := dst[:ElGamalCiphertextSize]
	out[0], out[257] = 0, 0
	a.FillBytes(out[1:257])
	b.FillBytes(out[258:])
	return out, nil
}

// DecryptElGamal decrypts and validates an I2P legacy ElGamal ciphertext block.
// It verifies the 0xff prefix and embedded SHA-256 hash before returning the 222-byte plaintext.
func DecryptElGamal(dst []byte, private ElGamalPrivateKey, ciphertext []byte) ([]byte, error) {
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

	// a^(p-1-x) = a^(-x) mod p
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
