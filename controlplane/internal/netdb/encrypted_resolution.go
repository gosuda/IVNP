package netdb

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"time"

	"gosuda.org/ivnp/foundation"
)

// DecryptEncryptedLeaseSet verifies, decrypts, and validates an ELS2 for the
// specified unblinded destination. It never accepts a plaintext downgrade.
func DecryptEncryptedLeaseSet(set foundation.NetworkDatabaseEncryptedLeaseSet, identity foundation.Identity, secret []byte, authorization ELSClientAuthorization, nowMillis uint64) (foundation.NetworkDatabaseLeaseSet2, error) {
	if set.SigningType != foundation.SigningRedDSASHA512Ed25519 || set.Flags != 0 || set.Expires == 0 {
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	valid, err := set.Verify()
	if err != nil || !valid {
		return foundation.NetworkDatabaseLeaseSet2{}, ErrInvalidSignature
	}
	now := nowMillis / 1000
	if now < uint64(set.Published) || now >= uint64(set.Published)+uint64(set.Expires) {
		return foundation.NetworkDatabaseLeaseSet2{}, foundation.NetworkDatabaseErrELSExpired
	}
	kind := identity.SigningKeyType()
	public, rest := identity.SigningKeyParts()
	if len(rest) != 0 {
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	blinded, err := foundation.BlindEncryptedLeaseSetPublic(kind, public, time.Unix(int64(set.Published), 0), secret)
	if err != nil || !bytes.Equal(blinded[:], set.BlindedPublicKey) {
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	subcredential, err := foundation.EncryptedLeaseSetSubcredential(kind, public, blinded[:])
	if err != nil {
		return foundation.NetworkDatabaseLeaseSet2{}, err
	}
	outerInput := make([]byte, 36)
	copy(outerInput, subcredential[:])
	binary.BigEndian.PutUint32(outerInput[32:], set.Published)
	layer1, err := elsDecrypt(set.EncryptedData, outerInput, "ELS2_L1K")
	clear(outerInput)
	if err != nil || len(layer1) < 1 {
		clear(layer1)
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	flags := layer1[0]
	var authCookie []byte
	off := 1
	switch flags {
	case elsAuthNone:
	case elsAuthDH:
		if !authorization.UseDH || len(layer1) < off+34 {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
		ephemeral := layer1[off : off+32]
		off += 32
		count := int(binary.BigEndian.Uint16(layer1[off : off+2]))
		off += 2
		if count == 0 || len(layer1) < off+40*count {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
		}
		private, dhErr := ecdh.X25519().NewPrivateKey(authorization.DHPrivate[:])
		peer, peerErr := ecdh.X25519().NewPublicKey(ephemeral)
		if dhErr != nil || peerErr != nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
		shared, dhErr := private.ECDH(peer)
		if dhErr != nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
		input := make([]byte, 0, 100)
		input = append(input, shared...)
		input = append(input, authorization.DHPublic[:]...)
		input = append(input, subcredential[:]...)
		var timestamp [4]byte
		binary.BigEndian.PutUint32(timestamp[:], set.Published)
		input = append(input, timestamp[:]...)
		key, nonce, id, deriveErr := elsClientMaterial(ephemeral, input, "ELS2_XCA")
		clear(input)
		clear(shared)
		if deriveErr != nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, deriveErr
		}
		for index := range count {
			entry := layer1[off+40*index : off+40*(index+1)]
			if bytes.Equal(entry[:8], id[:]) {
				authCookie = make([]byte, 32)
				if err = elsStream(authCookie, entry[8:], key[:], nonce[:]); err != nil {
					clear(layer1)
					clear(authCookie)
					return foundation.NetworkDatabaseLeaseSet2{}, err
				}
				break
			}
		}
		off += 40 * count
		if authCookie == nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
	case elsAuthPSK:
		if !authorization.UsePSK || len(layer1) < off+34 {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
		salt := layer1[off : off+32]
		off += 32
		count := int(binary.BigEndian.Uint16(layer1[off : off+2]))
		off += 2
		if count == 0 || len(layer1) < off+40*count {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
		}
		input := make([]byte, 0, 68)
		input = append(input, authorization.PSK[:]...)
		input = append(input, subcredential[:]...)
		var timestamp [4]byte
		binary.BigEndian.PutUint32(timestamp[:], set.Published)
		input = append(input, timestamp[:]...)
		key, nonce, id, deriveErr := elsClientMaterial(salt, input, "ELS2PSKA")
		clear(input)
		if deriveErr != nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, deriveErr
		}
		for index := range count {
			entry := layer1[off+40*index : off+40*(index+1)]
			if bytes.Equal(entry[:8], id[:]) {
				authCookie = make([]byte, 32)
				if err = elsStream(authCookie, entry[8:], key[:], nonce[:]); err != nil {
					clear(layer1)
					clear(authCookie)
					return foundation.NetworkDatabaseLeaseSet2{}, err
				}
				break
			}
		}
		off += 40 * count
		if authCookie == nil {
			clear(layer1)
			return foundation.NetworkDatabaseLeaseSet2{}, ErrELSAuthorization
		}
	default:
		clear(layer1)
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	if len(layer1) <= off+32 {
		clear(layer1)
		clear(authCookie)
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	innerInput := make([]byte, 0, len(authCookie)+36)
	innerInput = append(innerInput, authCookie...)
	innerInput = append(innerInput, subcredential[:]...)
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], set.Published)
	innerInput = append(innerInput, timestamp[:]...)
	inner, err := elsDecrypt(layer1[off:], innerInput, "ELS2_L2K")
	clear(layer1)
	clear(innerInput)
	clear(authCookie)
	clear(subcredential[:])
	if err != nil || len(inner) < 2 || foundation.I2NPStoreType(inner[0]) != foundation.I2NPStoreLeaseSet2 {
		clear(inner)
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	parsed, err := foundation.NetworkDatabaseParseLeaseSet2(inner[1:])
	if err != nil {
		clear(inner)
		return foundation.NetworkDatabaseLeaseSet2{}, err
	}
	verified, err := parsed.Verify()
	if err != nil || !verified || parsed.Header.Destination.Hash() != identity.Hash() || parsed.Header.Published != set.Published || parsed.Header.Expires != set.Expires {
		clear(inner)
		return foundation.NetworkDatabaseLeaseSet2{}, ErrEncryptedLeaseSet
	}
	leases := parsed.Leases()
	for {
		lease, more, leaseErr := leases.Next()
		if leaseErr != nil {
			clear(inner)
			return foundation.NetworkDatabaseLeaseSet2{}, leaseErr
		}
		if !more {
			break
		}
		if uint64(lease.EndDate) <= now {
			clear(inner)
			return foundation.NetworkDatabaseLeaseSet2{}, foundation.NetworkDatabaseErrELSExpired
		}
	}
	return parsed, nil
}
