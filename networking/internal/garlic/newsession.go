package garlic

import (
	"crypto/rand"

	"gosuda.org/ivnp/cryptography"
)

const newSessionBlockSize = cryptography.ElGamalPlaintextSize

// EncryptNew creates a peer-interoperable legacy I2P ElGamal/AES new-session
// message. Its ElGamal plaintext is exactly
// sessionKey[32] || preIV[32] || randomPadding[158]; the returned session key
// is caller-owned and is needed to send later existing-session messages using
// the delivered tags.
func EncryptNew(dst []byte, recipient cryptography.ElGamalPublicKey, payload, deliveredTags []byte) (packet []byte, sessionKey [32]byte, err error) {
	if len(dst) < cryptography.ElGamalCiphertextSize {
		return nil, sessionKey, ErrSession
	}
	var block [newSessionBlockSize]byte
	if _, err = rand.Read(block[:]); err != nil {
		return nil, sessionKey, err
	}
	copy(sessionKey[:], block[:len(sessionKey)])
	if _, err = cryptography.EncryptElGamal(dst[:cryptography.ElGamalCiphertextSize], recipient, block[:]); err != nil {
		return nil, sessionKey, err
	}
	body, err := encryptSessionBody(dst[cryptography.ElGamalCiphertextSize:], block[32:64], sessionKey[:], payload, deliveredTags)
	if err != nil {
		return nil, sessionKey, err
	}
	return dst[:cryptography.ElGamalCiphertextSize+len(body)], sessionKey, nil
}

// ReceiveNew validates and decrypts a legacy I2P ElGamal/AES new-session
// message. On success sessionKey is the key paired with every returned
// delivered tag; payload and deliveredTags are caller-owned dst views.
func ReceiveNew(dst, packet []byte, private cryptography.ElGamalPrivateKey) (payload, deliveredTags []byte, sessionKey [32]byte, err error) {
	if len(packet) <= cryptography.ElGamalCiphertextSize {
		return nil, nil, sessionKey, ErrSession
	}
	var block [newSessionBlockSize]byte
	if _, err = cryptography.DecryptElGamal(block[:], private, packet[:cryptography.ElGamalCiphertextSize]); err != nil {
		return nil, nil, sessionKey, err
	}
	copy(sessionKey[:], block[:len(sessionKey)])
	var replacement [32]byte
	var replaceKey bool
	payload, deliveredTags, replacement, replaceKey, err = decryptExisting(dst, block[32:64], sessionKey[:], packet[cryptography.ElGamalCiphertextSize:])
	if err != nil {
		clear(replacement[:])
		return nil, nil, [32]byte{}, err
	}
	if replaceKey {
		clear(sessionKey[:])
		sessionKey = replacement
	}
	clear(replacement[:])
	return payload, deliveredTags, sessionKey, nil
}

// DecryptNew decrypts the AES portion of a new ElGamal/AES session after the
// caller has authenticated and decrypted the 514-byte ElGamal block. preIV is
// the 32-byte value from that block; its SHA-256 prefix is the AES IV.
func DecryptNew(dst, sessionKey, preIV, ciphertext []byte) (payload, deliveredTags []byte, err error) {
	return DecryptExisting(dst, preIV, sessionKey, ciphertext)
}
