// Package ecies implements the ECIES-X25519 garlic handshake building blocks.
// It is separate from the legacy ElGamal/AES garlic codec.
package garlicecies

import (
	"errors"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/networking/internal/transport/noise"
)

var ErrHybrid = errors.New("garlic/ecies: invalid hybrid handshake section")

// HybridInitiator owns the one-use ML-KEM decapsulation key generated for the
// e1 position in an I2P IKhfs NS message. It is single-goroutine handshake
// state and must not be shared between local destinations or sessions.
type HybridInitiator struct {
	params  cryptography.MLKEMParameters
	public  cryptography.MLKEMPublicKey
	private *cryptography.MLKEMPrivateKey
}

// NewHybridInitiator creates an e1 keypair for a registered ML-KEM/X25519
// LeaseSet2 crypto type.
func NewHybridInitiator(cryptoType uint16) (*HybridInitiator, error) {
	params, known := cryptography.Parameters(cryptoType)
	if !known {
		return nil, ErrHybrid
	}
	public, private, err := cryptography.GenerateMLKEM(cryptoType)
	if err != nil {
		return nil, err
	}
	return &HybridInitiator{params: params, public: public, private: private}, nil
}

func (h *HybridInitiator) CryptoType() uint16 {
	if h == nil {
		return 0
	}
	return h.params.CryptoType
}

// ReleaseSensitive releases the one-use ML-KEM private owner.
func (h *HybridInitiator) ReleaseSensitive() {
	if h == nil {
		return
	}
	if h.private != nil {
		h.private.ReleaseSensitive()
		h.private = nil
	}
	h.params = cryptography.MLKEMParameters{}
	h.public = cryptography.MLKEMPublicKey{}
}

// EncryptE1 writes the EncryptAndHash(e1) section immediately after ECIES IK
// es. The caller then continues the static-key section at the advanced nonce.
func (h *HybridInitiator) EncryptE1(state *noise.SymmetricState, dst []byte) ([]byte, error) {
	if h == nil || state == nil {
		return nil, ErrHybrid
	}
	return state.EncryptAndHash(dst, h.public.Bytes())
}

// ConsumeEKEM decrypts the EncryptAndHash(ekem1) section immediately after
// ECIES IK ee, then MixKey()s the FIPS-203 shared secret before se.
func (h *HybridInitiator) ConsumeEKEM(state *noise.SymmetricState, dst, ciphertext []byte) error {
	if h == nil || state == nil || len(ciphertext) != h.params.CiphertextSize+16 || len(dst) < h.params.CiphertextSize {
		return ErrHybrid
	}
	kemCiphertext, err := state.DecryptAndHash(dst, ciphertext)
	if err != nil || len(kemCiphertext) != h.params.CiphertextSize {
		return ErrHybrid
	}
	if h.private == nil {
		return cryptography.ErrSensitiveReleased
	}
	defer h.private.ReleaseSensitive()
	defer func() { h.private = nil }()
	shared, err := h.private.Decapsulate(kemCiphertext)
	if err != nil {
		return err
	}
	defer clear(shared[:])
	return state.MixKey(shared[:])
}

// HybridResponder receives e1 then produces ekem1. It is single-goroutine
// handshake state and must be discarded on any transcript authentication error.
type HybridResponder struct {
	params cryptography.MLKEMParameters
	public cryptography.MLKEMPublicKey
	ready  bool
}

func NewHybridResponder(cryptoType uint16) (*HybridResponder, error) {
	params, known := cryptography.Parameters(cryptoType)
	if !known {
		return nil, cryptography.ErrMLKEMUnsupported
	}
	return &HybridResponder{params: params}, nil
}

// ReleaseSensitive clears retained hybrid handshake metadata.
func (h *HybridResponder) ReleaseSensitive() {
	if h == nil {
		return
	}
	h.params = cryptography.MLKEMParameters{}
	h.public = cryptography.MLKEMPublicKey{}
	h.ready = false
}

// ConsumeE1 decrypts and authenticates the e1 section after ECIES IK es.
func (h *HybridResponder) ConsumeE1(state *noise.SymmetricState, dst, ciphertext []byte) error {
	if h == nil || state == nil || len(ciphertext) != h.params.PublicKeySize+16 || len(dst) < h.params.PublicKeySize {
		return ErrHybrid
	}
	encoded, err := state.DecryptAndHash(dst, ciphertext)
	if err != nil || len(encoded) != h.params.PublicKeySize {
		return ErrHybrid
	}
	public, err := cryptography.NewMLKEMPublicKey(h.params.CryptoType, encoded)
	if err != nil {
		return err
	}
	h.public, h.ready = public, true
	return nil
}

// EncryptEKEM writes the EncryptAndHash(ekem1) section after ECIES IK ee,
// then MixKey()s the KEM secret before the ECIES se pattern continues.
func (h *HybridResponder) EncryptEKEM(state *noise.SymmetricState, dst []byte) ([]byte, error) {
	if h == nil || state == nil || !h.ready {
		return nil, ErrHybrid
	}
	shared, ciphertext, err := cryptography.Encapsulate(h.public)
	if err != nil {
		return nil, err
	}
	defer clear(shared[:])
	out, err := state.EncryptAndHash(dst, ciphertext)
	if err != nil {
		return nil, err
	}
	if err = state.MixKey(shared[:]); err != nil {
		return nil, err
	}
	return out, nil
}
