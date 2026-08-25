package cryptx

import (
	"crypto/mlkem"
	"crypto/rand"
	"errors"
)

const (
	// MLKEM768X25519 and MLKEM1024X25519 are I2P LeaseSet2 crypto type codes.
	// Their advertised static key remains X25519; the KEM public key and
	// ciphertext exist only inside the ECIES hybrid handshake.
	MLKEM768X25519  uint16 = 6
	MLKEM1024X25519 uint16 = 7
)

var (
	ErrMLKEM            = errors.New("cryptx: invalid ML-KEM input")
	ErrMLKEMUnsupported = errors.New("cryptx: unsupported ML-KEM parameter set")
)

// MLKEMParameters are the FIPS-203 lengths used inside the I2P ECIES hybrid
// e1/ekem1 sections. PublicKeySize is the ephemeral KEM encapsulation key,
// not the 32-byte static X25519 key advertised by a LeaseSet2.
type MLKEMParameters struct {
	CryptoType      uint16
	PublicKeySize   int
	CiphertextSize  int
	NoiseIdentifier string
}

// Parameters returns exact I2P hybrid handshake sizes for registered
// ML-KEM/X25519 crypto types.
func Parameters(cryptoType uint16) (MLKEMParameters, bool) {
	switch cryptoType {
	case MLKEM768X25519:
		return MLKEMParameters{CryptoType: cryptoType, PublicKeySize: mlkem.EncapsulationKeySize768, CiphertextSize: mlkem.CiphertextSize768, NoiseIdentifier: "Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256"}, true
	case MLKEM1024X25519:
		return MLKEMParameters{CryptoType: cryptoType, PublicKeySize: mlkem.EncapsulationKeySize1024, CiphertextSize: mlkem.CiphertextSize1024, NoiseIdentifier: "Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256"}, true
	default:
		return MLKEMParameters{}, false
	}
}

// MLKEMPublicKey is an immutable-by-convention encoded FIPS-203 public key.
// Bytes is copied by constructors and returned as a copy to prevent mutation
// across handshake goroutines.
type MLKEMPublicKey struct {
	cryptoType uint16
	bytes      []byte
}

func (k MLKEMPublicKey) CryptoType() uint16 { return k.cryptoType }
func (k MLKEMPublicKey) Bytes() []byte      { return append([]byte(nil), k.bytes...) }

// NewMLKEMPublicKey validates and owns a FIPS-203 KEM public key.
func NewMLKEMPublicKey(cryptoType uint16, encoded []byte) (MLKEMPublicKey, error) {
	params, known := Parameters(cryptoType)
	if !known {
		return MLKEMPublicKey{}, ErrMLKEMUnsupported
	}
	if len(encoded) != params.PublicKeySize {
		return MLKEMPublicKey{}, ErrMLKEM
	}
	switch cryptoType {
	case MLKEM768X25519:
		if _, err := mlkem.NewEncapsulationKey768(encoded); err != nil {
			return MLKEMPublicKey{}, ErrMLKEM
		}
	case MLKEM1024X25519:
		if _, err := mlkem.NewEncapsulationKey1024(encoded); err != nil {
			return MLKEMPublicKey{}, ErrMLKEM
		}
	}
	return MLKEMPublicKey{cryptoType: cryptoType, bytes: append([]byte(nil), encoded...)}, nil
}

// MLKEMPrivateKey owns the d||z seed from which a short-lived standard-library
// decapsulation key is reconstructed for each decapsulation operation.
type MLKEMPrivateKey struct {
	cryptoType uint16
	seed       [mlkem.SeedSize]byte
	released   bool
}

var _ Sensitive = (*MLKEMPrivateKey)(nil)

func (k *MLKEMPrivateKey) CryptoType() uint16 {
	if k == nil {
		return 0
	}
	return k.cryptoType
}

// GenerateMLKEM creates a FIPS-203 KEM pair for hybrid ECIES e1.
func GenerateMLKEM(cryptoType uint16) (MLKEMPublicKey, *MLKEMPrivateKey, error) {
	if _, known := Parameters(cryptoType); !known {
		return MLKEMPublicKey{}, nil, ErrMLKEMUnsupported
	}
	private := new(MLKEMPrivateKey)
	private.cryptoType = cryptoType
	if _, err := rand.Read(private.seed[:]); err != nil {
		private.ReleaseSensitive()
		return MLKEMPublicKey{}, nil, err
	}
	var public []byte
	var err error
	switch cryptoType {
	case MLKEM768X25519:
		key, keyErr := mlkem.NewDecapsulationKey768(private.seed[:])
		if keyErr != nil {
			err = keyErr
		} else {
			public = key.EncapsulationKey().Bytes()
		}
	case MLKEM1024X25519:
		key, keyErr := mlkem.NewDecapsulationKey1024(private.seed[:])
		if keyErr != nil {
			err = keyErr
		} else {
			public = key.EncapsulationKey().Bytes()
		}
	}
	if err != nil {
		private.ReleaseSensitive()
		return MLKEMPublicKey{}, nil, err
	}
	return MLKEMPublicKey{cryptoType: cryptoType, bytes: append([]byte(nil), public...)}, private, nil
}

// Encapsulate produces an ekem1 ciphertext and a fixed-size shared secret.
func Encapsulate(public MLKEMPublicKey) ([mlkem.SharedKeySize]byte, []byte, error) {
	var shared [mlkem.SharedKeySize]byte
	switch public.cryptoType {
	case MLKEM768X25519:
		key, err := mlkem.NewEncapsulationKey768(public.bytes)
		if err != nil {
			return shared, nil, ErrMLKEM
		}
		secret, ciphertext := key.Encapsulate()
		copy(shared[:], secret)
		clear(secret)
		return shared, ciphertext, nil
	case MLKEM1024X25519:
		key, err := mlkem.NewEncapsulationKey1024(public.bytes)
		if err != nil {
			return shared, nil, ErrMLKEM
		}
		secret, ciphertext := key.Encapsulate()
		copy(shared[:], secret)
		clear(secret)
		return shared, ciphertext, nil
	default:
		return shared, nil, ErrMLKEMUnsupported
	}
}

// Decapsulate recovers ekem1's shared secret. FIPS-203 decapsulation may
// return a pseudorandom secret for a correctly-sized invalid ciphertext; the
// enclosing hybrid Noise transcript authentication must reject that session.
func (k *MLKEMPrivateKey) Decapsulate(ciphertext []byte) ([mlkem.SharedKeySize]byte, error) {
	var shared [mlkem.SharedKeySize]byte
	if k == nil || k.released {
		return shared, ErrSensitiveReleased
	}
	params, known := Parameters(k.cryptoType)
	if !known {
		return shared, ErrMLKEMUnsupported
	}
	if len(ciphertext) != params.CiphertextSize {
		return shared, ErrMLKEM
	}
	var secret []byte
	var err error
	switch k.cryptoType {
	case MLKEM768X25519:
		key, keyErr := mlkem.NewDecapsulationKey768(k.seed[:])
		if keyErr != nil {
			return shared, ErrMLKEM
		}
		secret, err = key.Decapsulate(ciphertext)
	case MLKEM1024X25519:
		key, keyErr := mlkem.NewDecapsulationKey1024(k.seed[:])
		if keyErr != nil {
			return shared, ErrMLKEM
		}
		secret, err = key.Decapsulate(ciphertext)
	}
	if err != nil || len(secret) != len(shared) {
		clear(secret)
		return shared, ErrMLKEM
	}
	copy(shared[:], secret)
	clear(secret)
	return shared, nil
}

// ReleaseSensitive overwrites the retained seed and prevents reuse.
func (k *MLKEMPrivateKey) ReleaseSensitive() {
	if k == nil || k.released {
		return
	}
	clear(k.seed[:])
	k.cryptoType = 0
	k.released = true
}
