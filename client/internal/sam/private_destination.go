package sam

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"
)

var ErrInvalidKey = errors.New("sam: invalid private destination")

// SAM private Destinations are the binary public Destination followed by the
// encryption private key and signing private key, encoded with I2P base64. For
// Ed25519 SAM carries the 32-byte seed, not Go's 64-byte expanded key. An
// all-zero signing private key introduces an Offline Signature section:
// expires (4 BE), transient signing key type (2 BE), transient signing public
// key, authorization signature by the offline key, transient signing private
// key.
func encodePrivateDestination(destination *foundation.LocalDestination) ([]byte, error) {
	if destination == nil {
		return nil, ErrInvalidKey
	}
	state := make([]byte, destination.PrivateEncodedLen())
	n, err := destination.MarshalPrivateTo(state)
	if err != nil {
		clear(state)
		return nil, err
	}
	state = state[:n]
	defer clear(state)
	if len(state) < 2 {
		return nil, ErrInvalidKey
	}
	publicLength := int(binary.BigEndian.Uint16(state[:2]))
	if publicLength == 0 || len(state) < 2+publicLength+32 {
		return nil, ErrInvalidKey
	}
	publicRaw, err := foundation.DecodeI2PBase64(state[2 : 2+publicLength])
	if err != nil {
		return nil, ErrInvalidKey
	}
	defer clear(publicRaw)
	identity, consumed, err := foundation.ParseIdentity(publicRaw)
	if err != nil || consumed != len(publicRaw) {
		return nil, ErrInvalidKey
	}
	stateSigningLength := 0
	switch identity.SigningKeyType() {
	case foundation.SigningEdDSASHA512Ed25519:
		stateSigningLength = ed25519.PrivateKeySize
	case foundation.SigningRedDSASHA512Ed25519:
		stateSigningLength = 32
	default:
		return nil, ErrInvalidKey
	}
	offset := 2 + publicLength + stateSigningLength
	if len(state) < offset+32 {
		return nil, ErrInvalidKey
	}
	var encryption []byte
	switch identity.CryptoKeyType() {
	case foundation.CryptoX25519:
		encryption = state[offset : offset+32]
	case foundation.CryptoElGamal:
		if len(state) < offset+32+256 {
			return nil, ErrInvalidKey
		}
		encryption = state[offset+32 : offset+32+256]
	default:
		return nil, ErrInvalidKey
	}
	var signing []byte
	if offlineLength := destination.OfflinePrivateEncodedLen(); offlineLength > 0 {
		signing = make([]byte, 32+offlineLength)
		if _, err = destination.MarshalOfflinePrivateTo(signing[32:]); err != nil {
			clear(signing)
			return nil, err
		}
		defer clear(signing)
	} else {
		signing = state[2+publicLength : 2+publicLength+32]
	}
	wire := make([]byte, len(publicRaw)+len(encryption)+len(signing))
	position := copy(wire, publicRaw)
	position += copy(wire[position:], encryption)
	copy(wire[position:], signing)
	encoded := []byte(foundation.EncodeI2PBase64(wire))
	clear(wire)
	return encoded, nil
}

func zeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func decodePrivateDestination(encoded string) (*foundation.LocalDestination, error) {
	wire, err := foundation.DecodeI2PBase64([]byte(encoded))
	if err != nil {
		return nil, ErrInvalidKey
	}
	defer clear(wire)
	identity, consumed, err := foundation.ParseIdentity(wire)
	if err != nil || (identity.CryptoKeyType() != foundation.CryptoX25519 && identity.CryptoKeyType() != foundation.CryptoElGamal) {
		return nil, ErrInvalidKey
	}
	const signingLength = ed25519.SeedSize
	encryptionLength := 32
	if identity.CryptoKeyType() == foundation.CryptoElGamal {
		encryptionLength = 256
	}
	if len(wire) < consumed+encryptionLength+signingLength {
		return nil, ErrInvalidKey
	}
	encryptionPrivate := wire[consumed : consumed+encryptionLength]
	signing := wire[consumed+encryptionLength : consumed+encryptionLength+signingLength]
	offlineSection := wire[consumed+encryptionLength+signingLength:]
	var offline *offlinePrivateKey
	if zeroBytes(signing) {
		parsed, parseErr := parseOfflinePrivateKey(identity, offlineSection)
		if parseErr != nil {
			return nil, parseErr
		}
		offline = parsed
		defer offline.clear()
	} else if len(offlineSection) != 0 {
		return nil, ErrInvalidKey
	}
	privateLength := 0
	switch identity.SigningKeyType() {
	case foundation.SigningEdDSASHA512Ed25519:
		privateLength = ed25519.PrivateKeySize
	case foundation.SigningRedDSASHA512Ed25519:
		if identity.CryptoKeyType() != foundation.CryptoX25519 {
			return nil, ErrInvalidKey
		}
		privateLength = 32
	default:
		return nil, ErrInvalidKey
	}
	private := make([]byte, privateLength)
	if offline == nil {
		switch identity.SigningKeyType() {
		case foundation.SigningEdDSASHA512Ed25519:
			private = ed25519.NewKeyFromSeed(signing)
		case foundation.SigningRedDSASHA512Ed25519:
			copy(private, signing)
		}
	}
	defer clear(private)
	var x25519 []byte
	var elgamal []byte
	if identity.CryptoKeyType() == foundation.CryptoElGamal {
		generated, generateErr := ecdh.X25519().GenerateKey(rand.Reader)
		if generateErr != nil {
			return nil, ErrInvalidKey
		}
		x25519 = generated.Bytes()
		defer clear(x25519)
		elgamal = encryptionPrivate
	} else {
		x25519 = encryptionPrivate
	}
	public := []byte(foundation.EncodeI2PBase64(identity.Bytes()))
	state := make([]byte, 2+len(public)+len(private)+32+len(elgamal)+1)
	defer clear(state)
	binary.BigEndian.PutUint16(state[:2], uint16(len(public)))
	offset := 2 + copy(state[2:], public)
	offset += copy(state[offset:], private)
	offset += copy(state[offset:], x25519)
	offset += copy(state[offset:], elgamal)
	state[offset] = 0x07
	if offline != nil {
		destination, err := foundation.ImportLocalDestinationOffline(state, offline.OfflineSignature, offline.transientPrivate)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return destination, nil
	}
	destination, err := foundation.ImportLocalDestination(state)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return destination, nil
}

type offlinePrivateKey struct {
	foundation.OfflineSignature
	transientPrivate []byte
}

// clear detaches the offline key material views. The backing wire buffer is
// caller-owned and wiped by the caller, which covers these subslices.
func (o *offlinePrivateKey) clear() {
	o.PublicKey = nil
	o.Signature = nil
	o.transientPrivate = nil
}

// parseOfflinePrivateKey parses the SAM offline signature section as views over
// the caller-owned section; the caller keeps section alive and wipes it.
func parseOfflinePrivateKey(identity foundation.Identity, section []byte) (*offlinePrivateKey, error) {
	if len(section) < 6 {
		return nil, ErrInvalidKey
	}
	keyType := foundation.SigningKeyType(binary.BigEndian.Uint16(section[4:6]))
	publicLength, ok := keyType.PublicKeyLen()
	if !ok {
		return nil, ErrInvalidKey
	}
	signatureLength, ok := identity.SigningKeyType().SignatureLen()
	if !ok {
		return nil, ErrInvalidKey
	}
	if len(section) != 6+publicLength+signatureLength+ed25519.SeedSize {
		return nil, ErrInvalidKey
	}
	offset := 6
	public := section[offset : offset+publicLength]
	offset += publicLength
	signature := section[offset : offset+signatureLength]
	offset += signatureLength
	transientPrivate := section[offset:]
	return &offlinePrivateKey{
		OfflineSignature: foundation.OfflineSignature{
			Expires:   binary.BigEndian.Uint32(section[:4]),
			Type:      keyType,
			PublicKey: public,
			Signature: signature,
		},
		transientPrivate: transientPrivate,
	}, nil
}
