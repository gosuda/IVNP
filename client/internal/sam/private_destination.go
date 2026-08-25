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
// Ed25519 SAM carries the 32-byte seed, not Go's 64-byte expanded key.
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
	offset := 2 + publicLength
	var signing []byte
	switch identity.SigningKeyType() {
	case foundation.SigningEdDSASHA512Ed25519:
		if len(state) < offset+ed25519.PrivateKeySize+32 {
			return nil, ErrInvalidKey
		}
		signing = state[offset : offset+ed25519.SeedSize]
		offset += ed25519.PrivateKeySize
	case foundation.SigningRedDSASHA512Ed25519:
		if len(state) < offset+32+32 {
			return nil, ErrInvalidKey
		}
		signing = state[offset : offset+32]
		offset += 32
	default:
		return nil, ErrInvalidKey
	}
	switch identity.CryptoKeyType() {
	case foundation.CryptoX25519:
		x25519 := state[offset : offset+32]
		wire := make([]byte, len(publicRaw)+32+len(signing))
		position := copy(wire, publicRaw)
		position += copy(wire[position:], x25519)
		copy(wire[position:], signing)
		encoded := []byte(foundation.EncodeI2PBase64(wire))
		clear(wire)
		return encoded, nil
	case foundation.CryptoElGamal:
		elgamalOffset := offset + 32
		if len(state) < elgamalOffset+256 {
			return nil, ErrInvalidKey
		}
		wire := make([]byte, len(publicRaw)+256+len(signing))
		position := copy(wire, publicRaw)
		position += copy(wire[position:], state[elgamalOffset:elgamalOffset+256])
		copy(wire[position:], signing)
		encoded := []byte(foundation.EncodeI2PBase64(wire))
		clear(wire)
		return encoded, nil
	default:
		return nil, ErrInvalidKey
	}
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
	if len(wire) != consumed+encryptionLength+signingLength {
		return nil, ErrInvalidKey
	}
	encryptionPrivate := wire[consumed : consumed+encryptionLength]
	signing := wire[consumed+encryptionLength:]
	var private []byte
	switch identity.SigningKeyType() {
	case foundation.SigningEdDSASHA512Ed25519:
		private = ed25519.NewKeyFromSeed(signing)
	case foundation.SigningRedDSASHA512Ed25519:
		if identity.CryptoKeyType() != foundation.CryptoX25519 {
			return nil, ErrInvalidKey
		}
		private = append([]byte(nil), signing...)
	default:
		return nil, ErrInvalidKey
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
	destination, err := foundation.ImportLocalDestination(state)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return destination, nil
}
