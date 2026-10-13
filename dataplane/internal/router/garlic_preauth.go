package router

import (
	"crypto/sha256"
	"sync"

	"gosuda.org/ivnp/foundation"
)

const (
	// A full 256-destination scan fits in one source's budget, but further
	// unauthenticated scans are bounded even when message IDs change.
	garlicCryptoWindowMillis           = uint64(1000)
	garlicCryptoGlobalWorkLimit        = 512
	garlicCryptoSourceWorkLimit        = 256
	garlicInvalidCiphertextLifetime    = uint64(30_000)
	garlicInvalidCiphertextCapacity    = 1024
)

type garlicCryptoReservation struct {
	digest     [32]byte
	generation uint64
}

type garlicCachedCiphertext struct {
	position   uint16
	expires    uint64
	generation uint64
}

// garlicPreauthLimiter bounds recipient-key operations, not ordinary
// authenticated session packets. All counters and replay slots are bounded.
type garlicPreauthLimiter struct {
	mu        sync.Mutex
	window    uint64
	used      int
	perSource map[foundation.Hash]uint16
	cached    map[[32]byte]garlicCachedCiphertext
	recent    [garlicInvalidCiphertextCapacity][32]byte
	next      uint64
}

// begin reserves an encrypted payload before the first unauthenticated
// decrypt. The caller must forget its reservation unless every recipient
// rejects the ciphertext; confirmed misses stay cached for a short period.
func (l *garlicPreauthLimiter) begin(ciphertext []byte, now uint64) (garlicCryptoReservation, bool) {
	reservation := garlicCryptoReservation{digest: sha256.Sum256(ciphertext)}
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry, exists := l.cached[reservation.digest]; exists && now < entry.expires {
		return reservation, false
	}
	if l.cached == nil {
		l.cached = make(map[[32]byte]garlicCachedCiphertext)
	}
	position := uint16(l.next % garlicInvalidCiphertextCapacity)
	old := l.recent[position]
	if entry, exists := l.cached[old]; exists && entry.position == position {
		delete(l.cached, old)
	}
	l.next++
	reservation.generation = l.next
	l.recent[position] = reservation.digest
	l.cached[reservation.digest] = garlicCachedCiphertext{
		position: position, expires: saturatingAdd(now, garlicInvalidCiphertextLifetime),
		generation: reservation.generation,
	}
	return reservation, true
}

// forget removes a successful or budget-rejected reservation. A stale request
// cannot remove a newer reservation for the same ciphertext.
func (l *garlicPreauthLimiter) forget(reservation garlicCryptoReservation) {
	l.mu.Lock()
	if entry, exists := l.cached[reservation.digest]; exists && entry.generation == reservation.generation {
		delete(l.cached, reservation.digest)
	}
	l.mu.Unlock()
}

// allowWork charges one destination-key decrypt attempt, including all
// enabled New Session formats, before cryptography begins. Unidentified or
// tunneled sources share a single bucket and cannot assert a new identity.
func (l *garlicPreauthLimiter) allowWork(source I2NPSource, now uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	window := now / garlicCryptoWindowMillis
	if window < l.window {
		return false
	}
	if window > l.window {
		l.window = window
		l.used = 0
		clear(l.perSource)
	}
	if l.used >= garlicCryptoGlobalWorkLimit {
		return false
	}
	var peer foundation.Hash
	if source.Direct {
		peer = source.Peer
	}
	if l.perSource[peer] >= garlicCryptoSourceWorkLimit {
		return false
	}
	if l.perSource == nil {
		l.perSource = make(map[foundation.Hash]uint16)
	}
	l.used++
	l.perSource[peer]++
	return true
}
