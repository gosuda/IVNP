package netdb

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/i2np"
)

var (
	ErrEncryptedLeaseSet = errors.New("netdb: invalid encrypted LeaseSet")
	ErrELSAuthorization  = errors.New("netdb: encrypted LeaseSet authorization failed")
	ErrELSExpired        = errors.New("netdb: encrypted LeaseSet is expired or not current")
)

const (
	elsAuthNone uint8 = 0
	elsAuthDH   uint8 = 1
	elsAuthPSK  uint8 = 3
)

// EncryptedLeaseSetAuthorization is the destination policy carried in durable
// state by callers. Exactly one client mode may be configured; no entries means
// public ELS2 decryption. Client keys are copied by the constructor.
type EncryptedLeaseSetAuthorization struct {
	DHClients  [][32]byte
	PSKClients [][32]byte
}

// ELSClientAuthorization supplies a client credential while decrypting ELS2.
// DHPrivate must have the corresponding DHPublic; PSK is a 32-byte shared key.
type ELSClientAuthorization struct {
	DHPrivate [32]byte
	DHPublic  [32]byte
	PSK       [32]byte
	UseDH     bool
	UsePSK    bool
}

// LocalEncryptedLeaseSet owns ELS2 policy and delegates the signed inner LS2
// construction to the same local LS2 producer used by public publication.
type LocalEncryptedLeaseSet struct {
	destination *foundation.LocalDestination
	inner       *LocalLeaseSet2
	secret      []byte
	dhClients   [][32]byte
	pskClients  [][32]byte
	random      io.Reader
	mu          sync.RWMutex
	released    bool
}

func NewLocalEncryptedLeaseSet(destination *foundation.LocalDestination, inner *LocalLeaseSet2, authorization EncryptedLeaseSetAuthorization, secret []byte) (*LocalEncryptedLeaseSet, error) {
	newLocalEncryptedLeaseSetRejected := destination == nil || inner == nil
	if !newLocalEncryptedLeaseSetRejected {
		newLocalEncryptedLeaseSetRejected = (len(authorization.DHClients) != 0 && len(authorization.PSKClients) != 0)
	}
	if newLocalEncryptedLeaseSetRejected {
		return nil, ErrEncryptedLeaseSet
	}
	clientCount := len(authorization.DHClients) + len(authorization.PSKClients)
	if clientCount > 0xffff || 1+32+2+40*clientCount+33 >= MaxLeaseSetBytes {
		return nil, ErrEncryptedLeaseSet
	}
	identity, err := destination.Identity()
	if err != nil || identity.Hash() != inner.Hash() {
		return nil, ErrEncryptedLeaseSet
	}
	kind := identity.SigningKeyType()
	if kind != foundation.SigningEdDSASHA512Ed25519 && kind != foundation.SigningRedDSASHA512Ed25519 {
		return nil, ErrEncryptedLeaseSet
	}
	return &LocalEncryptedLeaseSet{
		destination: destination,
		inner:       inner,
		secret:      append([]byte(nil), secret...),
		dhClients:   append([][32]byte(nil), authorization.DHClients...),
		pskClients:  append([][32]byte(nil), authorization.PSKClients...),
		random:      rand.Reader,
	}, nil
}

func (s *LocalEncryptedLeaseSet) Hash(date time.Time) (foundation.Hash, error) {
	if s == nil {
		return foundation.Hash{}, ErrEncryptedLeaseSet
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.released {
		return foundation.Hash{}, ErrEncryptedLeaseSet
	}
	private, public, err := s.destination.EncryptedLeaseSetBlinding(date, s.secret)
	defer clear(private[:])
	if err != nil {
		return foundation.Hash{}, err
	}
	var data [34]byte
	binary.BigEndian.PutUint16(data[:2], uint16(foundation.SigningRedDSASHA512Ed25519))
	copy(data[2:], public[:])
	return foundation.Sum(data[:]), nil
}

// ReleaseSensitive clears copied ELS2 blinding and client authorization
// material. It is idempotent and prevents any later publication.
func (s *LocalEncryptedLeaseSet) ReleaseSensitive() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.released {
		clear(s.secret)
		for index := range s.dhClients {
			clear(s.dhClients[index][:])
		}
		for index := range s.pskClients {
			clear(s.pskClients[index][:])
		}
		clear(s.dhClients)
		clear(s.pskClients)
		s.secret, s.dhClients, s.pskClients = nil, nil, nil
		s.destination, s.inner, s.random = nil, nil, nil
		s.released = true
	}
	s.mu.Unlock()
}

func elsHash(personalization string, data []byte) [32]byte {
	var output [32]byte
	h := sha256.New()
	h.Write([]byte(personalization))
	h.Write(data)
	copy(output[:], h.Sum(nil))
	return output
}

func elsHKDF(salt, input []byte, info string, dst []byte) error {
	_, err := io.ReadFull(hkdf.New(sha256.New, input, salt, []byte(info)), dst)
	return err
}

func elsStream(dst, src, key, nonce []byte) error {
	stream, err := cryptography.NewChaCha20Stream(key, nonce)
	if err != nil {
		return err
	}
	stream.SetCounter(1)
	stream.XORKeyStream(dst, src)
	return nil
}

func elsEncrypt(input []byte, saltInput []byte, info string) ([]byte, error) {
	return elsEncryptWithRandom(input, saltInput, info, rand.Reader)
}

func elsEncryptWithRandom(input []byte, saltInput []byte, info string, random io.Reader) ([]byte, error) {
	output := make([]byte, 32+len(input))
	if _, err := io.ReadFull(random, output[:32]); err != nil {
		clear(output)
		return nil, err
	}
	var keys [44]byte
	defer clear(keys[:])
	if err := elsHKDF(output[:32], saltInput, info, keys[:]); err != nil {
		clear(output)
		return nil, err
	}
	if err := elsStream(output[32:], input, keys[:32], keys[32:]); err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}

func elsDecrypt(input []byte, saltInput []byte, info string) ([]byte, error) {
	if len(input) < 32 {
		return nil, ErrEncryptedLeaseSet
	}
	output := make([]byte, len(input)-32)
	var keys [44]byte
	if err := elsHKDF(input[:32], saltInput, info, keys[:]); err != nil {
		return nil, err
	}
	err := elsStream(output, input[32:], keys[:32], keys[32:])
	clear(keys[:])
	if err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}

func elsClientMaterial(salt, input []byte, info string) (key [32]byte, nonce [12]byte, id [8]byte, err error) {
	var material [52]byte
	err = elsHKDF(salt, input, info, material[:])
	if err == nil {
		copy(key[:], material[:32])
		copy(nonce[:], material[32:44])
		copy(id[:], material[44:])
	}
	clear(material[:])
	return
}

// MarshalTo constructs and signs exact ELS2 layers. nowMillis is reduced only
// at the wire boundary; expiration is inherited from the inner LS2 leases.
func (s *LocalEncryptedLeaseSet) MarshalTo(dst []byte, nowMillis uint64) (written int, err error) {
	if s == nil || nowMillis/1000 > uint64(^uint32(0)) {
		return 0, ErrEncryptedLeaseSet
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.released {
		return 0, ErrEncryptedLeaseSet
	}
	var (
		private, blinded, subcredential, authCookie [32]byte
		innerBuffer, innerPlaintext, layer1         []byte
		innerInput, innerCiphertext                 []byte
		outerInput, outerCiphertext                 []byte
	)
	defer func() {
		clear(private[:])
		clear(blinded[:])
		clear(subcredential[:])
		clear(authCookie[:])
		clear(innerBuffer)
		clear(innerPlaintext)
		clear(layer1)
		clear(innerInput)
		clear(innerCiphertext)
		clear(outerInput)
		clear(outerCiphertext)
		if err != nil {
			clear(dst)
		}
	}()

	identity, err := s.destination.Identity()
	if err != nil {
		return 0, err
	}
	innerBuffer = make([]byte, MaxLeaseSetBytes)
	innerLength, err := s.inner.MarshalTo(innerBuffer, nowMillis, s.destination.Sign)
	if err != nil {
		return 0, err
	}
	innerPlaintext = make([]byte, innerLength+1)
	innerPlaintext[0] = byte(i2np.StoreLeaseSet2)
	copy(innerPlaintext[1:], innerBuffer[:innerLength])
	published := uint32(nowMillis / 1000)
	private, blinded, err = s.destination.EncryptedLeaseSetBlinding(time.Unix(int64(published), 0).UTC(), s.secret)
	if err != nil {
		return 0, err
	}
	subcredential, err = foundation.EncryptedLeaseSetSubcredential(identity.SigningKeyType(), s.destination.SigningPublic(), blinded[:])
	if err != nil {
		return 0, err
	}
	if len(s.dhClients) == 0 && len(s.pskClients) == 0 {
		layer1 = []byte{elsAuthNone}
	} else {
		if _, err = io.ReadFull(s.random, authCookie[:]); err != nil {
			return 0, err
		}
		if len(s.dhClients) != 0 {
			privateDH, dhErr := ecdh.X25519().GenerateKey(s.random)
			if dhErr != nil {
				return 0, dhErr
			}
			layer1 = make([]byte, 1+32+2+40*len(s.dhClients))
			layer1[0] = elsAuthDH
			dhPublic := privateDH.PublicKey().Bytes()
			copy(layer1[1:33], dhPublic)
			binary.BigEndian.PutUint16(layer1[33:35], uint16(len(s.dhClients)))
			off := 35
			for _, client := range s.dhClients {
				deriveErr := func() error {
					clientKey, keyErr := ecdh.X25519().NewPublicKey(client[:])
					if keyErr != nil {
						return keyErr
					}
					shared, keyErr := privateDH.ECDH(clientKey)
					if keyErr != nil {
						return keyErr
					}
					defer clear(shared)
					input := make([]byte, 0, 32+32+32+4)
					defer func() { clear(input) }()
					input = append(input, shared...)
					input = append(input, client[:]...)
					input = append(input, subcredential[:]...)
					var timestamp [4]byte
					binary.BigEndian.PutUint32(timestamp[:], published)
					input = append(input, timestamp[:]...)
					key, nonce, id, keyErr := elsClientMaterial(dhPublic, input, "ELS2_XCA")
					defer clear(key[:])
					defer clear(nonce[:])
					defer clear(id[:])
					if keyErr != nil {
						return keyErr
					}
					copy(layer1[off:off+8], id[:])
					return elsStream(layer1[off+8:off+40], authCookie[:], key[:], nonce[:])
				}()
				if deriveErr != nil {
					return 0, deriveErr
				}
				off += 40
			}
		} else {
			layer1 = make([]byte, 1+32+2+40*len(s.pskClients))
			layer1[0] = elsAuthPSK
			if _, err = io.ReadFull(s.random, layer1[1:33]); err != nil {
				return 0, err
			}
			binary.BigEndian.PutUint16(layer1[33:35], uint16(len(s.pskClients)))
			off := 35
			for _, client := range s.pskClients {
				deriveErr := func() error {
					input := make([]byte, 0, 32+32+4)
					defer func() { clear(input) }()
					input = append(input, client[:]...)
					input = append(input, subcredential[:]...)
					var timestamp [4]byte
					binary.BigEndian.PutUint32(timestamp[:], published)
					input = append(input, timestamp[:]...)
					key, nonce, id, keyErr := elsClientMaterial(layer1[1:33], input, "ELS2PSKA")
					defer clear(key[:])
					defer clear(nonce[:])
					defer clear(id[:])
					if keyErr != nil {
						return keyErr
					}
					copy(layer1[off:off+8], id[:])
					return elsStream(layer1[off+8:off+40], authCookie[:], key[:], nonce[:])
				}()
				if deriveErr != nil {
					return 0, deriveErr
				}
				off += 40
			}
		}
	}
	innerInput = make([]byte, 0, len(authCookie)+32+4)
	if layer1[0] != elsAuthNone {
		innerInput = append(innerInput, authCookie[:]...)
	}
	innerInput = append(innerInput, subcredential[:]...)
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], published)
	innerInput = append(innerInput, timestamp[:]...)
	innerCiphertext, err = elsEncryptWithRandom(innerPlaintext, innerInput, "ELS2_L2K", s.random)
	if err != nil {
		return 0, err
	}
	layer1 = append(layer1, innerCiphertext...)
	outerInput = make([]byte, 36)
	copy(outerInput, subcredential[:])
	binary.BigEndian.PutUint32(outerInput[32:], published)
	outerCiphertext, err = elsEncryptWithRandom(layer1, outerInput, "ELS2_L1K", s.random)
	if err != nil {
		return 0, err
	}
	if len(outerCiphertext) > 0xffff {
		return 0, ErrEncryptedLeaseSet
	}
	return s.finishOuter(dst, blinded, &private, published, outerCiphertext)
}

func (s *LocalEncryptedLeaseSet) finishOuter(dst []byte, blinded [32]byte, private *[32]byte, published uint32, outerCiphertext []byte) (written int, err error) {
	latest := uint64(0)
	s.inner.mu.RLock()
	for _, lease := range s.inner.leases {
		if uint64(lease.EndDate) > latest {
			latest = uint64(lease.EndDate)
		}
	}
	s.inner.mu.RUnlock()
	if latest <= uint64(published) || latest-uint64(published) > uint64(^uint16(0)) {
		return 0, ErrEncryptedLeaseSet
	}
	expires := uint16(latest - uint64(published))
	unsignedLength := 2 + 32 + 4 + 2 + 2 + 2 + len(outerCiphertext)
	if len(dst) < unsignedLength+64 {
		return 0, foundation.ErrDestinationSmall
	}
	off := 0
	binary.BigEndian.PutUint16(dst[off:off+2], uint16(foundation.SigningRedDSASHA512Ed25519))
	off += 2
	copy(dst[off:off+32], blinded[:])
	off += 32
	binary.BigEndian.PutUint32(dst[off:off+4], published)
	off += 4
	binary.BigEndian.PutUint16(dst[off:off+2], expires)
	off += 2
	binary.BigEndian.PutUint16(dst[off:off+2], 0)
	off += 2
	binary.BigEndian.PutUint16(dst[off:off+2], uint16(len(outerCiphertext)))
	off += 2
	copy(dst[off:], outerCiphertext)
	off += len(outerCiphertext)
	signed := make([]byte, off+1)
	defer clear(signed)
	signed[0] = byte(i2np.StoreEncryptedLeaseSet)
	copy(signed[1:], dst[:off])
	signature, err := foundation.Red25519Sign(*private, signed)
	if err != nil {
		return 0, err
	}
	copy(dst[off:], signature)
	return off + len(signature), nil
}
