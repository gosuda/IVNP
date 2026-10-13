package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

const (
	// Each inbound circuit uses at most 256 KiB of replay state. The filter
	// never rotates, so old cells stay rejected for the circuit's entire life.
	cellReplayBits   = 1 << 21
	cellReplayWords  = cellReplayBits / 64
	cellReplayHashes = 5
)

// cellReplayFilter tracks ciphertexts for one inbound circuit generation.
// Bloom-filter false positives drop cells rather than admitting a replay.
// Storage is allocated only when the first cell arrives.
type cellReplayFilter struct {
	mu    sync.Mutex
	words []uint64
}

// seen atomically records ciphertext and reports whether it may have appeared
// before. Caller must validate its fixed tunnel-cell length first.
func (filter *cellReplayFilter) seen(ciphertext []byte) bool {
	digest := sha256.Sum256(ciphertext)
	first := binary.LittleEndian.Uint64(digest[:8])
	step := binary.LittleEndian.Uint64(digest[8:16]) | 1

	filter.mu.Lock()
	defer filter.mu.Unlock()
	if filter.words == nil {
		filter.words = make([]uint64, cellReplayWords)
	}
	seen := true
	for index := uint64(0); index < cellReplayHashes; index++ {
		bit := (first + index*step) & (cellReplayBits - 1)
		word := &filter.words[bit/64]
		mask := uint64(1) << (bit & 63)
		if *word&mask == 0 {
			seen = false
			*word |= mask
		}
	}
	return seen
}
