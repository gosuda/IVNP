// Package securestore provides encrypted storage for router identity keys and destination secrets.
package securestore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"unicode/utf8"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
	filesystemstore "gosuda.org/ivnp/state/internal/filesystem_store"
)

const (
	// DefaultMaxStateBytes bounds an encrypted state file, including its header.
	DefaultMaxStateBytes = 64 << 10
	// DefaultMaxDestinations bounds named local destinations in one bundle.
	DefaultMaxDestinations = 64
	// DefaultMaxNameBytes bounds a UTF-8 destination name.
	DefaultMaxNameBytes = 64

	stateVersion           = 2
	masterKeySize          = 32
	nonceSize              = 12
	headerSize             = len(stateMagic) + 1 + nonceSize
	routerIdentityMaxBytes = foundation.IdentityBaseLength + foundation.CertificateHeader + 4
)

var (
	stateMagic = [...]byte{'I', 'V', 'N', 'P'}

	ErrStoreConfig   = errors.New("state: invalid store configuration")
	ErrInvalidState  = errors.New("state: invalid encrypted state")
	ErrInvalidBundle = errors.New("state: invalid identity bundle")
	ErrInvalidKey    = errors.New("state: invalid master key")
	ErrStateLocked   = errors.New("state: state directory is already locked")
)

// Bundle holds persistent private key material for a router and its local destinations.
type Bundle struct {
	Router             foundation.LocalRouterAddress
	NTCP2StaticPrivate []byte
	NTCP2StaticIV      []byte
	SSU2StaticPrivate  []byte
	SSU2IntroKey       []byte
	// Destinations stores legacy ElGamal destination material for backward migration.
	Destinations map[string]foundation.LocalAddress
	// DestinationPrivate holds serialized LocalDestination private key bytes.
	DestinationPrivate        map[string][]byte
	EncryptedLeaseSetPolicies map[string]EncryptedLeaseSetPolicy
	// DestinationAddressPolicies holds client access credentials for remote encrypted LeaseSets.
	DestinationAddressPolicies map[string][]RemoteELSAuthorization
}

// EncryptedLeaseSetPolicy defines access control (secret and client keys) for a local encrypted LeaseSet.
type EncryptedLeaseSetPolicy struct {
	Secret     []byte
	DHClients  [][32]byte
	PSKClients [][32]byte
}

// RemoteELSAuthorizationKind identifies the authorization method used to decrypt a remote LeaseSet2.
type RemoteELSAuthorizationKind uint8

const (
	RemoteELSAuthorizationNone RemoteELSAuthorizationKind = iota
	RemoteELSAuthorizationDH
	RemoteELSAuthorizationPSK
)

// RemoteELSAuthorization holds access credentials for decrypting a remote destination's encrypted LeaseSet.
type RemoteELSAuthorization struct {
	Identity  []byte
	Secret    []byte
	Kind      RemoteELSAuthorizationKind
	DHPrivate [32]byte
	DHPublic  [32]byte
	PSK       [32]byte
}

// ReleaseSensitive zeroes all sensitive private keys in the bundle.
func (b *Bundle) ReleaseSensitive() {
	if b == nil {
		return
	}
	clear(b.Router.RouterIdentity)
	clear(b.Router.SigningPublic)
	clear(b.Router.SigningPrivate)
	clear(b.Router.X25519Public[:])
	clear(b.Router.X25519Private[:])
	clear(b.NTCP2StaticPrivate)
	clear(b.NTCP2StaticIV)
	clear(b.SSU2StaticPrivate)
	clear(b.SSU2IntroKey)
	for name, address := range b.Destinations {
		clear(address.Destination)
		clear(address.SigningPublic)
		clear(address.SigningPrivate)
		clear(address.EncryptionPublic[:])
		clear(address.EncryptionPrivate[:])
		b.Destinations[name] = address
		delete(b.Destinations, name)
	}
	for name, private := range b.DestinationPrivate {
		clear(private)
		delete(b.DestinationPrivate, name)
	}
	for name, policy := range b.EncryptedLeaseSetPolicies {
		clear(policy.Secret)
		for index := range policy.DHClients {
			clear(policy.DHClients[index][:])
		}
		for index := range policy.PSKClients {
			clear(policy.PSKClients[index][:])
		}
		b.EncryptedLeaseSetPolicies[name] = policy
		delete(b.EncryptedLeaseSetPolicies, name)
	}
	for name, policies := range b.DestinationAddressPolicies {
		for index := range policies {
			clear(policies[index].Identity)
			clear(policies[index].Secret)
			clear(policies[index].DHPrivate[:])
			clear(policies[index].DHPublic[:])
			clear(policies[index].PSK[:])
		}
		delete(b.DestinationAddressPolicies, name)
	}
	*b = Bundle{}
}

// Store manages AES-256-GCM encrypted persistence of a state Bundle to disk.
type Store struct {
	StatePath     string
	MasterKeyPath string

	MaxStateBytes   int
	MaxDestinations int
	MaxNameBytes    int

	mu sync.Mutex
}

// NewStore creates a Store with default limits.
func NewStore(statePath, masterKeyPath string) (*Store, error) {
	store := &Store{
		StatePath:       statePath,
		MasterKeyPath:   masterKeyPath,
		MaxStateBytes:   DefaultMaxStateBytes,
		MaxDestinations: DefaultMaxDestinations,
		MaxNameBytes:    DefaultMaxNameBytes,
	}
	if err := store.validConfig(); err != nil {
		return nil, err
	}
	return store, nil
}

// Load decrypts and deserializes the state bundle from disk.
func (s *Store) Load() (Bundle, error) {
	if s == nil {
		return Bundle{}, ErrStoreConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Save serializes and encrypts the state bundle, atomically writing it to disk.
func (s *Store) Save(bundle Bundle) error {
	if s == nil {
		return ErrStoreConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(bundle)
}

// LoadOrCreate loads existing state, or generates and saves a new random identity bundle if absent.
func (s *Store) LoadOrCreate() (Bundle, error) {
	if s == nil {
		return Bundle{}, ErrStoreConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validConfig(); err != nil {
		return Bundle{}, err
	}
	file, err := s.openPrivateFile(s.StatePath)
	if err == nil {
		file.Close()
		key, keyErr := s.openPrivateFile(s.MasterKeyPath)
		if keyErr != nil {
			if errors.Is(keyErr, os.ErrNotExist) {
				return Bundle{}, ErrInvalidState
			}
			return Bundle{}, keyErr
		}
		key.Close()
		return s.load()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, err
	}
	key, err := s.openPrivateFile(s.MasterKeyPath)
	if err == nil {
		key.Close()
		return Bundle{}, ErrInvalidState
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, err
	}

	bundle, err := generateBundle()
	if err != nil {
		return Bundle{}, err
	}
	if err := s.save(bundle); err != nil {
		return Bundle{}, err
	}
	return cloneBundle(bundle), nil
}

func (s *Store) load() (Bundle, error) {
	if err := s.validConfig(); err != nil {
		return Bundle{}, err
	}
	key, err := s.loadMasterKey()
	if err != nil {
		return Bundle{}, err
	}
	defer clear(key)

	data, err := s.readState()
	if err != nil {
		return Bundle{}, err
	}
	if len(data) < headerSize || !bytes.Equal(data[:len(stateMagic)], stateMagic[:]) || data[len(stateMagic)] != stateVersion {
		return Bundle{}, ErrInvalidState
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != nonceSize {
		return Bundle{}, fmt.Errorf("%w: AEAD unavailable", ErrInvalidState)
	}
	plaintext, err := aead.Open(nil, data[len(stateMagic)+1:headerSize], data[headerSize:], data[:len(stateMagic)+1])
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: authentication failed", ErrInvalidState)
	}
	defer clear(plaintext)
	bundle, err := s.decodeBundle(plaintext)
	if err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (s *Store) save(bundle Bundle) error {
	if err := s.validConfig(); err != nil {
		return err
	}
	if file, err := s.openPrivateFile(s.StatePath); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	plaintext, err := s.encodeBundle(bundle)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	key, err := s.loadOrCreateMasterKey()
	if err != nil {
		return err
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != nonceSize {
		return fmt.Errorf("%w: AEAD unavailable", ErrInvalidState)
	}
	data := make([]byte, headerSize, headerSize+len(plaintext)+aead.Overhead())
	copy(data, stateMagic[:])
	data[len(stateMagic)] = stateVersion
	if _, err := io.ReadFull(rand.Reader, data[len(stateMagic)+1:headerSize]); err != nil {
		return err
	}
	data = aead.Seal(data, data[len(stateMagic)+1:headerSize], plaintext, data[:len(stateMagic)+1])
	if len(data) > s.maxStateBytes() {
		clear(data)
		return fmt.Errorf("%w: encoded state exceeds limit", ErrInvalidBundle)
	}
	defer clear(data)
	if _, err := ensureParent(s.StatePath); err != nil {
		return err
	}
	if err := filesystemstore.WriteAtomic(s.StatePath, data, 0o600, s.maxStateBytes()); err != nil {
		return err
	}
	return nil
}

func (s *Store) readState() ([]byte, error) {
	file, err := s.openPrivateFile(s.StatePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := filesystemstore.ReadBoundedFile(file, int64(s.maxStateBytes()))
	if err != nil {
		if errors.Is(err, filesystemstore.ErrTooLarge) {
			return nil, fmt.Errorf("%w: file exceeds limit", ErrInvalidState)
		}
		return nil, err
	}
	return data, nil
}

func (s *Store) loadMasterKey() ([]byte, error) {
	file, err := s.openPrivateFile(s.MasterKeyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	key, err := filesystemstore.ReadBoundedFile(file, masterKeySize)
	if err != nil {
		return nil, err
	}
	if len(key) != masterKeySize {
		clear(key)
		return nil, ErrInvalidKey
	}
	return key, nil
}

func (s *Store) loadOrCreateMasterKey() ([]byte, error) {
	key, err := s.loadMasterKey()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dir, err := ensureParent(s.MasterKeyPath)
	if err != nil {
		return nil, err
	}
	key = make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		clear(key)
		return nil, err
	}
	file, err := os.OpenFile(s.MasterKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		statErr := file.Chmod(0o600)
		info, infoErr := file.Stat()
		if statErr ==

			nil {
			statErr = infoErr
		}
		if statErr ==
			nil {
			statErr = validatePrivateFile(info)

		}
		written, writeErr := 0, statErr
		if writeErr == nil {
			written, writeErr = file.Write(key)
		}
		if writeErr == nil && written != len(key) {
			writeErr = io.ErrShortWrite
		}

		if writeErr == nil {
			writeErr = file.
				Sync()
		}
		if closeErr := file.Close(); writeErr == nil {
			writeErr = closeErr
		}

		if writeErr == nil {
			writeErr = filesystemstore.
				SyncDir(dir)
		}
		if writeErr != nil {
			_ = os.Remove(s.MasterKeyPath)
			clear(key)
			return nil, writeErr
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrExist) {
		clear(key)
		return nil, err
	}
	clear(key)
	return s.loadMasterKey()
}

func (s *Store) encodeBundle(bundle Bundle) ([]byte, error) {
	if err := s.validateBundle(bundle); err != nil {
		return nil, err
	}
	capacity := 2 + len(bundle.Router.RouterIdentity) + ed25519.PrivateKeySize + 32 + 32 + aes.BlockSize + 32 + 32 + 2 + 2
	for name, address := range bundle.Destinations {
		capacity += 1 + len(name) + 2 + len(address.Destination) + ed25519.PrivateKeySize + cryptography.ElGamalPrivateKeySize
	}
	for name, policy := range bundle.EncryptedLeaseSetPolicies {
		capacity += 1 + len(name) + 2 + len(policy.Secret) + 1 + 2 + 32*(len(policy.DHClients)+len(policy.PSKClients))
	}
	for name, private := range bundle.DestinationPrivate {
		capacity += 1 + len(name) + 2 + len(private)
	}
	for name, policies := range bundle.DestinationAddressPolicies {
		capacity += 1 + len(name) + 2
		for _, policy := range policies {
			capacity += 2 + len(policy.Identity) + 2 + len(policy.Secret) + 1 + 96
		}
	}
	if capacity > s.maxStateBytes() {
		return nil, fmt.Errorf("%w: encoded state exceeds limit", ErrInvalidBundle)
	}
	out := make([]byte, 0, capacity)
	out = appendRouterAddress(out, bundle.Router)
	out = append(out, bundle.NTCP2StaticPrivate...)
	out = append(out, bundle.NTCP2StaticIV...)
	out = append(out, bundle.SSU2StaticPrivate...)
	out = append(out, bundle.SSU2IntroKey...)
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(bundle.Destinations)))
	out = append(out, count[:]...)
	names := make([]string, 0, len(bundle.Destinations))
	for name := range bundle.Destinations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, byte(len(name)))
		out = append(out, name...)
		out = appendAddress(out, bundle.Destinations[name])
	}
	var policyCount [2]byte
	binary.BigEndian.PutUint16(policyCount[:], uint16(len(bundle.EncryptedLeaseSetPolicies)))
	out = append(out, policyCount[:]...)
	policyNames := make([]string, 0, len(bundle.EncryptedLeaseSetPolicies))
	for name := range bundle.EncryptedLeaseSetPolicies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	for _, name := range policyNames {
		policy := bundle.EncryptedLeaseSetPolicies[name]
		out = append(out, byte(len(name)))
		out = append(out, name...)
		var encoded [2]byte
		binary.BigEndian.PutUint16(encoded[:], uint16(len(policy.Secret)))
		out = append(out, encoded[:]...)
		out = append(out, policy.Secret...)
		if len(policy.DHClients) != 0 {
			out = append(out, 1)
			binary.BigEndian.PutUint16(encoded[:], uint16(len(policy.DHClients)))
			out = append(out, encoded[:]...)
			for _, client := range policy.DHClients {
				out = append(out, client[:]...)
			}
		} else {
			out = append(out, 2)
			binary.BigEndian.PutUint16(encoded[:], uint16(len(policy.PSKClients)))
			out = append(out, encoded[:]...)
			for _, client := range policy.PSKClients {
				out = append(out, client[:]...)
			}
		}
	}
	var privateCount [2]byte
	binary.BigEndian.PutUint16(privateCount[:], uint16(len(bundle.DestinationPrivate)))
	out = append(out, privateCount[:]...)
	privateNames := make([]string, 0, len(bundle.DestinationPrivate))
	for name := range bundle.DestinationPrivate {
		privateNames = append(privateNames, name)
	}
	sort.Strings(privateNames)
	for _, name := range privateNames {
		private := bundle.DestinationPrivate[name]
		out = append(out, byte(len(name)))
		out = append(out, name...)
		binary.BigEndian.PutUint16(privateCount[:], uint16(len(private)))
		out = append(out, privateCount[:]...)
		out = append(out, private...)
	}
	var addressPolicyCount [2]byte
	binary.BigEndian.PutUint16(addressPolicyCount[:], uint16(len(bundle.DestinationAddressPolicies)))
	out = append(out, addressPolicyCount[:]...)
	addressPolicyNames := make([]string, 0, len(bundle.DestinationAddressPolicies))
	for name := range bundle.DestinationAddressPolicies {
		addressPolicyNames = append(addressPolicyNames, name)
	}
	sort.Strings(addressPolicyNames)
	for _, name := range addressPolicyNames {
		policies := bundle.DestinationAddressPolicies[name]
		out = append(out, byte(len(name)))
		out = append(out, name...)
		binary.BigEndian.PutUint16(addressPolicyCount[:], uint16(len(policies)))
		out = append(out, addressPolicyCount[:]...)
		for _, policy := range policies {
			binary.BigEndian.PutUint16(addressPolicyCount[:], uint16(len(policy.Identity)))
			out = append(out, addressPolicyCount[:]...)
			out = append(out, policy.Identity...)
			binary.BigEndian.PutUint16(addressPolicyCount[:], uint16(len(policy.Secret)))
			out = append(out, addressPolicyCount[:]...)
			out = append(out, policy.Secret...)
			out = append(out, byte(policy.Kind))
			out = append(out, policy.DHPrivate[:]...)
			out = append(out, policy.DHPublic[:]...)
			out = append(out, policy.PSK[:]...)
		}
	}
	return out, nil
}

func (s *Store) decodeBundle(data []byte) (Bundle, error) {
	if len(data) > s.maxStateBytes() {
		return Bundle{}, fmt.Errorf("%w: decoded state exceeds limit", ErrInvalidState)
	}
	var bundle Bundle
	var err error
	bundle.Router, data, err = parseRouterAddress(data)
	if err != nil {
		return Bundle{}, invalidState(err)
	}
	if len(data) < 32+aes.BlockSize+32+32+2 {
		return Bundle{}, ErrInvalidState
	}
	bundle.NTCP2StaticPrivate = append([]byte(nil), data[:32]...)
	data = data[32:]
	bundle.NTCP2StaticIV = append([]byte(nil), data[:aes.BlockSize]...)
	data = data[aes.BlockSize:]
	bundle.SSU2StaticPrivate = append([]byte(nil), data[:32]...)
	data = data[32:]
	bundle.SSU2IntroKey = append([]byte(nil), data[:32]...)
	data = data[32:]
	count := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if count > s.maxDestinations() {
		return Bundle{}, ErrInvalidState
	}
	bundle.Destinations = make(map[string]foundation.LocalAddress, count)
	for range count {
		if len(data) < 1 {
			return Bundle{}, ErrInvalidState
		}
		nameLen := int(data[0])
		data = data[1:]
		if nameLen == 0 || nameLen > s.maxNameBytes() || nameLen > len(data) {
			return Bundle{}, ErrInvalidState
		}
		name := string(data[:nameLen])
		data = data[nameLen:]
		if !utf8.ValidString(name) {
			return Bundle{}, ErrInvalidState
		}
		if _, exists := bundle.Destinations[name]; exists {
			return Bundle{}, ErrInvalidState
		}
		address, remaining, err := parseAddress(data)
		if err != nil {
			return Bundle{}, invalidState(err)
		}
		bundle.Destinations[name] = address
		data = remaining
	}
	bundle.EncryptedLeaseSetPolicies = make(map[string]EncryptedLeaseSetPolicy)
	bundle.DestinationPrivate = make(map[string][]byte)
	bundle.DestinationAddressPolicies = make(map[string][]RemoteELSAuthorization)
	// Version-2 bundles ended exactly after destinations; the optional tails
	// are backwards-compatible policy and private-destination extensions.
	if len(data) != 0 {
		if len(data) < 2 {
			return Bundle{}, ErrInvalidState
		}
		policyCount := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if policyCount > s.maxDestinations() {
			return Bundle{}, ErrInvalidState
		}
		for range policyCount {
			if len(data) < 1 {
				return Bundle{}, ErrInvalidState
			}
			nameLen := int(data[0])
			data = data[1:]
			if nameLen == 0 || nameLen > s.maxNameBytes() || nameLen > len(data) {
				return Bundle{}, ErrInvalidState
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			if !utf8.ValidString(name) || len(data) < 2 {
				return Bundle{}, ErrInvalidState
			}
			secretLen := int(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			if secretLen > len(data) || len(data) < secretLen+3 {
				return Bundle{}, ErrInvalidState
			}
			policy := EncryptedLeaseSetPolicy{Secret: append([]byte(nil), data[:secretLen]...)}
			data = data[secretLen:]
			mode := data[0]
			count := int(binary.BigEndian.Uint16(data[1:3]))
			data = data[3:]
			decodeBundleRejected := (mode != 1 && mode != 2) || count > s.maxDestinations()
			if !decodeBundleRejected {
				decodeBundleRejected = len(data) < 32*count
			}
			if decodeBundleRejected {
				return Bundle{}, ErrInvalidState
			}
			clients := make([][32]byte, count)
			for index := range clients {
				copy(clients[index][:], data[index*32:(index+1)*32])
			}
			data = data[32*count:]
			if mode == 1 {
				policy.DHClients = clients
			} else {
				policy.PSKClients = clients
			}
			if _, exists := bundle.EncryptedLeaseSetPolicies[name]; exists {
				return Bundle{}, ErrInvalidState
			}
			bundle.EncryptedLeaseSetPolicies[name] = policy
		}
	}
	if len(data) != 0 {
		if len(data) < 2 {
			return Bundle{}, ErrInvalidState
		}
		privateCount := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if privateCount > s.maxDestinations() {
			return Bundle{}, ErrInvalidState
		}
		for range privateCount {
			if len(data) < 1 {
				return Bundle{}, ErrInvalidState
			}
			nameLen := int(data[0])
			data = data[1:]
			if nameLen == 0 || nameLen > s.maxNameBytes() || nameLen > len(data) {
				return Bundle{}, ErrInvalidState
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			if !utf8.ValidString(name) || bundle.Destinations[name].Destination != nil || bundle.DestinationPrivate[name] != nil || len(data) < 2 {
				return Bundle{}, ErrInvalidState
			}
			privateLen := int(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			if privateLen == 0 || privateLen > len(data) {
				return Bundle{}, ErrInvalidState
			}
			private := append([]byte(nil), data[:privateLen]...)
			data = data[privateLen:]
			destination, importErr := foundation.ImportLocalDestination(private)
			if importErr != nil {
				clear(private)
				return Bundle{}, ErrInvalidState
			}
			destination.ReleaseSensitive()
			bundle.DestinationPrivate[name] = private
		}
	}
	if len(data) != 0 {
		if len(data) < 2 {
			return Bundle{}, ErrInvalidState
		}
		addressPolicyCount := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if addressPolicyCount > s.maxDestinations() {
			return Bundle{}, ErrInvalidState
		}
		for range addressPolicyCount {
			if len(data) < 3 {
				return Bundle{}, ErrInvalidState
			}
			nameLen := int(data[0])
			data = data[1:]
			if nameLen == 0 || nameLen > s.maxNameBytes() || nameLen > len(data) {
				return Bundle{}, ErrInvalidState
			}
			name := string(data[:nameLen])
			data = data[nameLen:]
			count := int(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
			decodeBundleRejected := !utf8.ValidString(name) || (bundle.Destinations[name].Destination == nil && bundle.DestinationPrivate[name] == nil) || count == 0
			if !decodeBundleRejected {
				decodeBundleRejected = count > s.maxDestinations()
			}
			if decodeBundleRejected {
				return Bundle{}, ErrInvalidState
			}
			policies := make([]RemoteELSAuthorization, count)
			seen := make(map[foundation.Hash]struct{}, count)
			for index := range policies {
				if len(data) < 2 {
					return Bundle{}, ErrInvalidState
				}
				identityLen := int(binary.BigEndian.Uint16(data[:2]))
				data = data[2:]
				if identityLen == 0 || identityLen > len(data) || len(data) < identityLen+2 {
					return Bundle{}, ErrInvalidState
				}
				identityBytes := append([]byte(nil), data[:identityLen]...)
				data = data[identityLen:]
				identity, consumed, err := foundation.ParseIdentity(identityBytes)
				if err != nil || consumed != len(identityBytes) {
					clear(identityBytes)
					return Bundle{}, ErrInvalidState
				}
				secretLen := int(binary.BigEndian.Uint16(data[:2]))
				data = data[2:]
				if secretLen > len(data) || len(data) < secretLen+1+96 {
					clear(identityBytes)
					return Bundle{}, ErrInvalidState
				}
				policies[index].Identity = identityBytes
				policies[index].Secret = append([]byte(nil), data[:secretLen]...)
				data = data[secretLen:]
				policies[index].Kind = RemoteELSAuthorizationKind(data[0])
				data = data[1:]
				copy(policies[index].DHPrivate[:], data[:32])
				copy(policies[index].DHPublic[:], data[32:64])
				copy(policies[index].PSK[:], data[64:96])
				data = data[96:]
				hash := identity.Hash()
				if _, exists := seen[hash]; exists {
					return Bundle{}, ErrInvalidState
				}
				seen[hash] = struct{}{}
			}
			if _, exists := bundle.DestinationAddressPolicies[name]; exists {
				return Bundle{}, ErrInvalidState
			}
			bundle.DestinationAddressPolicies[name] = policies
		}
	}
	if len(data) != 0 {
		return Bundle{}, ErrInvalidState
	}
	if err := s.validateBundle(bundle); err != nil {
		return Bundle{}, invalidState(err)
	}
	return bundle, nil
}

func (s *Store) validateBundle(bundle Bundle) error {
	if err := validateRouterAddress(bundle.Router); err != nil {
		return fmt.Errorf("router: %w", err)
	}
	if len(bundle.NTCP2StaticPrivate) != 32 || len(bundle.NTCP2StaticIV) != aes.BlockSize || len(bundle.SSU2StaticPrivate) != 32 || len(bundle.SSU2IntroKey) != 32 {
		return fmt.Errorf("transport length: %w", ErrInvalidBundle)
	}
	if _, err := ecdh.X25519().NewPrivateKey(bundle.NTCP2StaticPrivate); err != nil {
		return fmt.Errorf("ntcp key: %w", ErrInvalidBundle)
	}
	if _, err := ecdh.X25519().NewPrivateKey(bundle.SSU2StaticPrivate); err != nil {
		return fmt.Errorf("ssu key: %w", ErrInvalidBundle)
	}
	if len(bundle.Destinations)+len(bundle.DestinationPrivate) > s.maxDestinations() {
		return fmt.Errorf("destination count: %w", ErrInvalidBundle)
	}
	for name, address := range bundle.Destinations {
		if name == "" || len(name) > s.maxNameBytes() || !utf8.ValidString(name) || bundle.DestinationPrivate[name] != nil {
			return fmt.Errorf("legacy destination name %q: %w", name, ErrInvalidBundle)
		}
		if err := validateAddress(address); err != nil {
			return fmt.Errorf("legacy destination %q: %w", name, err)
		}
	}
	for name, private := range bundle.DestinationPrivate {
		if name == "" || len(name) > s.maxNameBytes() || !utf8.ValidString(name) || len(private) == 0 || bundle.Destinations[name].Destination != nil {
			return ErrInvalidBundle
		}
		destination, err := foundation.ImportLocalDestination(private)
		if err != nil {
			return ErrInvalidBundle
		}
		destination.ReleaseSensitive()
	}
	if len(bundle.EncryptedLeaseSetPolicies) > len(bundle.Destinations)+len(bundle.DestinationPrivate) {
		return ErrInvalidBundle
	}
	for name, policy := range bundle.EncryptedLeaseSetPolicies {
		clientCount := len(policy.DHClients) + len(policy.PSKClients)
		validateBundleRejected := (bundle.Destinations[name].Destination == nil && bundle.DestinationPrivate[name] == nil) ||
			len(policy.Secret) > 0xffff || len(policy.DHClients) > 0xffff || len(policy.PSKClients) > 0xffff ||
			(len(policy.DHClients) != 0 && len(policy.PSKClients) != 0)
		if !validateBundleRejected {
			validateBundleRejected = 1+32+2+40*clientCount+33 >= 1<<16
		}
		if validateBundleRejected {
			return ErrInvalidBundle
		}
	}
	if len(bundle.DestinationAddressPolicies) > len(bundle.Destinations)+len(bundle.DestinationPrivate) {
		return ErrInvalidBundle
	}
	var zero [32]byte
	for name, policies := range bundle.DestinationAddressPolicies {
		validateBundleRejected := (bundle.Destinations[name].Destination == nil && bundle.DestinationPrivate[name] == nil) || len(policies) == 0
		if !validateBundleRejected {
			validateBundleRejected = len(policies) > s.maxDestinations()
		}
		if validateBundleRejected {
			return ErrInvalidBundle
		}
		seen := make(map[foundation.Hash]struct{}, len(policies))
		for _, policy := range policies {
			identity, consumed, err := foundation.ParseIdentity(policy.Identity)
			if err != nil || consumed != len(policy.Identity) || len(policy.Secret) > 0xffff {
				return ErrInvalidBundle
			}
			hash := identity.Hash()
			if _, exists := seen[hash]; exists {
				return ErrInvalidBundle
			}
			seen[hash] = struct{}{}
			switch policy.Kind {
			case RemoteELSAuthorizationNone:
				if policy.DHPrivate != zero || policy.DHPublic != zero || policy.PSK != zero {
					return ErrInvalidBundle
				}
			case RemoteELSAuthorizationDH:
				private, privateErr := ecdh.X25519().NewPrivateKey(policy.DHPrivate[:])
				public, publicErr := ecdh.X25519().NewPublicKey(policy.DHPublic[:])
				if privateErr != nil || publicErr != nil || !bytes.Equal(private.PublicKey().Bytes(), public.Bytes()) || policy.PSK != zero {
					return ErrInvalidBundle
				}
			case RemoteELSAuthorizationPSK:
				if policy.DHPrivate != zero || policy.DHPublic != zero {
					return ErrInvalidBundle
				}
			default:
				return ErrInvalidBundle
			}
		}
	}
	return nil
}

func validateAddress(address foundation.LocalAddress) error {
	identity, err := foundation.ParseDestination(address.Destination)
	if err != nil || !bytes.Equal(address.Destination, []byte(foundation.EncodeI2PBase64(identity.Bytes()))) || identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519 || identity.CryptoKeyType() != foundation.CryptoElGamal {
		return ErrInvalidBundle
	}
	if address.Hash != identity.Hash() || len(address.SigningPublic) != ed25519.PublicKeySize || len(address.SigningPrivate) != ed25519.PrivateKeySize || len(address.EncryptionPublic) != cryptography.ElGamalPublicKeySize || len(address.EncryptionPrivate) != cryptography.ElGamalPrivateKeySize {
		return ErrInvalidBundle
	}
	signingFirst, signingRest := identity.SigningKeyParts()
	cryptoFirst, cryptoRest := identity.CryptoKeyParts()
	if len(signingRest) != 0 || len(cryptoRest) != 0 || !bytes.Equal(address.SigningPublic, signingFirst) || !bytes.Equal(address.EncryptionPublic[:], cryptoFirst) {
		return ErrInvalidBundle
	}
	canonicalPrivate := ed25519.NewKeyFromSeed(address.SigningPrivate[:ed25519.SeedSize])
	if !bytes.Equal(canonicalPrivate, address.SigningPrivate) || !bytes.Equal(canonicalPrivate[ed25519.SeedSize:], address.SigningPublic) {
		return ErrInvalidBundle
	}
	// Encrypting and decrypting a fixed valid legacy block verifies the stored
	// ElGamal exponent against the public key as well as validating its range.
	plaintext := make([]byte, cryptography.ElGamalPlaintextSize)
	ciphertext, err := cryptography.EncryptElGamal(make([]byte, cryptography.ElGamalCiphertextSize), address.EncryptionPublic, plaintext)
	if err != nil {
		return ErrInvalidBundle
	}
	decrypted, err := cryptography.DecryptElGamal(make([]byte, cryptography.ElGamalPlaintextSize), address.EncryptionPrivate, ciphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		return ErrInvalidBundle
	}
	return nil
}

func appendRouterAddress(dst []byte, address foundation.LocalRouterAddress) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(address.RouterIdentity)))
	dst = append(dst, length[:]...)
	dst = append(dst, address.RouterIdentity...)
	dst = append(dst, address.SigningPrivate...)
	return append(dst, address.X25519Private[:]...)
}

func parseRouterAddress(data []byte) (foundation.LocalRouterAddress, []byte, error) {
	if len(data) < 2 {
		return foundation.LocalRouterAddress{}, nil, ErrInvalidState
	}
	identityLength := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if identityLength == 0 || identityLength > routerIdentityMaxBytes || len(data) < identityLength+ed25519.PrivateKeySize+32 {
		return foundation.LocalRouterAddress{}, nil, ErrInvalidState
	}
	address := foundation.LocalRouterAddress{
		RouterIdentity: append([]byte(nil), data[:identityLength]...),
		SigningPrivate: append(ed25519.PrivateKey(nil), data[identityLength:identityLength+ed25519.PrivateKeySize]...),
	}
	copy(address.X25519Private[:], data[identityLength+ed25519.PrivateKeySize:identityLength+ed25519.PrivateKeySize+32])
	data = data[identityLength+ed25519.PrivateKeySize+32:]
	identity, consumed, err := foundation.ParseIdentity(address.RouterIdentity)
	if err != nil || consumed != len(address.RouterIdentity) {
		return foundation.LocalRouterAddress{}, nil, ErrInvalidState
	}
	signing, signingRest := identity.SigningKeyParts()
	crypto, cryptoRest := identity.CryptoKeyParts()
	if len(signingRest) != 0 || len(cryptoRest) != 0 || len(signing) != ed25519.PublicKeySize || len(crypto) != len(address.X25519Public) {
		return foundation.LocalRouterAddress{}, nil, ErrInvalidState
	}
	address.Hash = identity.Hash()
	address.SigningPublic = append(ed25519.PublicKey(nil), signing...)
	copy(address.X25519Public[:], crypto)
	return address, data, nil
}

func validateRouterAddress(address foundation.LocalRouterAddress) error {
	if len(address.RouterIdentity) == 0 || len(address.RouterIdentity) > routerIdentityMaxBytes {
		return ErrInvalidBundle
	}
	identity, consumed, err := foundation.ParseIdentity(address.RouterIdentity)
	validateRouterAddressRejected := err != nil || consumed != len(address.RouterIdentity) || !bytes.Equal(address.RouterIdentity, identity.Bytes()) ||
		identity.Certificate().Type != foundation.CertificateKey || identity.SigningKeyType() != foundation.SigningEdDSASHA512Ed25519
	if !validateRouterAddressRejected {
		validateRouterAddressRejected = identity.CryptoKeyType() != foundation.CryptoX25519
	}
	if validateRouterAddressRejected {
		return ErrInvalidBundle
	}
	if address.Hash != identity.Hash() || len(address.SigningPublic) != ed25519.PublicKeySize || len(address.SigningPrivate) != ed25519.PrivateKeySize {
		return ErrInvalidBundle
	}
	signing, signingRest := identity.SigningKeyParts()
	crypto, cryptoRest := identity.CryptoKeyParts()
	if len(signingRest) != 0 || len(cryptoRest) != 0 || !bytes.Equal(address.SigningPublic, signing) || !bytes.Equal(address.X25519Public[:], crypto) {
		return ErrInvalidBundle
	}
	canonicalPrivate := ed25519.NewKeyFromSeed(address.SigningPrivate[:ed25519.SeedSize])
	if !bytes.Equal(canonicalPrivate, address.SigningPrivate) || !bytes.Equal(canonicalPrivate[ed25519.SeedSize:], address.SigningPublic) {
		return ErrInvalidBundle
	}
	x25519, err := ecdh.X25519().NewPrivateKey(address.X25519Private[:])
	if err != nil || !bytes.Equal(x25519.PublicKey().Bytes(), address.X25519Public[:]) {
		return ErrInvalidBundle
	}
	return nil
}

func appendAddress(dst []byte, address foundation.LocalAddress) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(address.Destination)))
	dst = append(dst, length[:]...)
	dst = append(dst, address.Destination...)
	dst = append(dst, address.SigningPrivate...)
	return append(dst, address.EncryptionPrivate[:]...)
}

func parseAddress(data []byte) (foundation.LocalAddress, []byte, error) {
	if len(data) < 2 {
		return foundation.LocalAddress{}, nil, ErrInvalidState
	}
	destinationLength := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if destinationLength == 0 || destinationLength > 2048 || len(data) < destinationLength+ed25519.PrivateKeySize+cryptography.ElGamalPrivateKeySize {
		return foundation.LocalAddress{}, nil, ErrInvalidState
	}
	address := foundation.LocalAddress{
		Destination:       append([]byte(nil), data[:destinationLength]...),
		SigningPrivate:    append(ed25519.PrivateKey(nil), data[destinationLength:destinationLength+ed25519.PrivateKeySize]...),
		EncryptionPrivate: cryptography.ElGamalPrivateKey(data[destinationLength+ed25519.PrivateKeySize : destinationLength+ed25519.PrivateKeySize+cryptography.ElGamalPrivateKeySize]),
	}
	data = data[destinationLength+ed25519.PrivateKeySize+cryptography.ElGamalPrivateKeySize:]
	identity, err := foundation.ParseDestination(address.Destination)
	if err != nil {
		return foundation.LocalAddress{}, nil, ErrInvalidState
	}
	signing, signingRest := identity.SigningKeyParts()
	crypto, cryptoRest := identity.CryptoKeyParts()
	if len(signingRest) != 0 || len(cryptoRest) != 0 || len(signing) != ed25519.PublicKeySize || len(crypto) != cryptography.ElGamalPublicKeySize {
		return foundation.LocalAddress{}, nil, ErrInvalidState
	}
	address.Hash = identity.Hash()
	address.SigningPublic = append(ed25519.PublicKey(nil), signing...)
	copy(address.EncryptionPublic[:], crypto)
	return address, data, nil
}

func generateBundle() (Bundle, error) {
	router, err := foundation.GenerateLocalRouterAddress()
	if err != nil {
		return Bundle{}, err
	}
	ntcp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	ssu, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{
		Router:                    router,
		NTCP2StaticPrivate:        append([]byte(nil), ntcp.Bytes()...),
		NTCP2StaticIV:             make([]byte, aes.BlockSize),
		SSU2StaticPrivate:         append([]byte(nil), ssu.Bytes()...),
		SSU2IntroKey:              make([]byte, 32),
		Destinations:              make(map[string]foundation.LocalAddress),
		DestinationPrivate:        make(map[string][]byte),
		EncryptedLeaseSetPolicies: make(map[string]EncryptedLeaseSetPolicy),
	}
	if _, err := io.ReadFull(rand.Reader, bundle.NTCP2StaticIV); err != nil {
		return Bundle{}, err
	}
	if _, err := io.ReadFull(rand.Reader, bundle.SSU2IntroKey); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (s *Store) validConfig() error {
	validConfigRejected := s.StatePath == "" || s.MasterKeyPath == "" || filepath.Clean(s.StatePath) == filepath.Clean(s.MasterKeyPath) || s.MaxStateBytes < 0 || s.MaxDestinations < 0
	if !validConfigRejected {
		validConfigRejected = s.MaxNameBytes < 0
	}
	if validConfigRejected {
		return ErrStoreConfig
	}
	if s.maxStateBytes() < headerSize+aes.BlockSize || s.maxDestinations() > 1<<16-1 || s.maxNameBytes() > 255 {
		return ErrStoreConfig
	}
	return nil
}

func (s *Store) maxStateBytes() int {
	if s.MaxStateBytes == 0 {
		return DefaultMaxStateBytes
	}
	return s.MaxStateBytes
}

func (s *Store) maxDestinations() int {
	if s.MaxDestinations == 0 {
		return DefaultMaxDestinations
	}
	return s.MaxDestinations
}

func (s *Store) maxNameBytes() int {
	if s.MaxNameBytes == 0 {
		return DefaultMaxNameBytes
	}
	return s.MaxNameBytes
}
func (s *Store) openPrivateFile(path string) (*os.File, error) {
	if _, err := ensureParent(path); err != nil {
		return nil, err
	}
	file, info, err := filesystemstore.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(info); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validatePrivateFile(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return ErrInvalidState
	}
	return nil
}

func ensureParent(path string) (string, error) {
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	file, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o022 != 0 {
		return "", ErrInvalidState
	}
	return dir, nil
}

func cloneBundle(bundle Bundle) Bundle {
	cloned := Bundle{
		Router:                     cloneRouterAddress(bundle.Router),
		NTCP2StaticPrivate:         append([]byte(nil), bundle.NTCP2StaticPrivate...),
		NTCP2StaticIV:              append([]byte(nil), bundle.NTCP2StaticIV...),
		SSU2StaticPrivate:          append([]byte(nil), bundle.SSU2StaticPrivate...),
		SSU2IntroKey:               append([]byte(nil), bundle.SSU2IntroKey...),
		Destinations:               make(map[string]foundation.LocalAddress, len(bundle.Destinations)),
		DestinationPrivate:         make(map[string][]byte, len(bundle.DestinationPrivate)),
		EncryptedLeaseSetPolicies:  make(map[string]EncryptedLeaseSetPolicy, len(bundle.EncryptedLeaseSetPolicies)),
		DestinationAddressPolicies: make(map[string][]RemoteELSAuthorization, len(bundle.DestinationAddressPolicies)),
	}
	for name, address := range bundle.Destinations {
		cloned.Destinations[name] = cloneAddress(address)
	}
	for name, private := range bundle.DestinationPrivate {
		cloned.DestinationPrivate[name] = append([]byte(nil), private...)
	}
	for name, policy := range bundle.EncryptedLeaseSetPolicies {
		cloned.EncryptedLeaseSetPolicies[name] = EncryptedLeaseSetPolicy{
			Secret:     append([]byte(nil), policy.Secret...),
			DHClients:  append([][32]byte(nil), policy.DHClients...),
			PSKClients: append([][32]byte(nil), policy.PSKClients...),
		}
	}
	for name, policies := range bundle.DestinationAddressPolicies {
		clonedPolicies := make([]RemoteELSAuthorization, len(policies))
		for index, policy := range policies {
			clonedPolicies[index] = RemoteELSAuthorization{
				Identity:  append([]byte(nil), policy.Identity...),
				Secret:    append([]byte(nil), policy.Secret...),
				Kind:      policy.Kind,
				DHPrivate: policy.DHPrivate,
				DHPublic:  policy.DHPublic,
				PSK:       policy.PSK,
			}
		}
		cloned.DestinationAddressPolicies[name] = clonedPolicies
	}
	return cloned
}

func cloneRouterAddress(address foundation.LocalRouterAddress) foundation.LocalRouterAddress {
	return foundation.LocalRouterAddress{
		RouterIdentity: append([]byte(nil), address.RouterIdentity...),
		Hash:           address.Hash,
		SigningPublic:  append(ed25519.PublicKey(nil), address.SigningPublic...),
		SigningPrivate: append(ed25519.PrivateKey(nil), address.SigningPrivate...),
		X25519Public:   address.X25519Public,
		X25519Private:  address.X25519Private,
	}
}

func cloneAddress(address foundation.LocalAddress) foundation.LocalAddress {
	cloned := foundation.LocalAddress{
		Destination:       append([]byte(nil), address.Destination...),
		Hash:              address.Hash,
		SigningPublic:     append(ed25519.PublicKey(nil), address.SigningPublic...),
		SigningPrivate:    append(ed25519.PrivateKey(nil), address.SigningPrivate...),
		EncryptionPublic:  address.EncryptionPublic,
		EncryptionPrivate: address.EncryptionPrivate,
	}
	return cloned
}

func clear(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func invalidState(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidState, err)
}
