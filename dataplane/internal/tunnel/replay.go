package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	cellReplayLayers       = 6
	cellReplayFirstBits    = 1 << 16
	cellReplayHashes       = 7
	cellReplayBitsPerEntry = 24
)

var (
	ErrTunnelReplay         = errors.New("tunnel: replayed tunnel data cell")
	ErrTunnelReplayCapacity = errors.New("tunnel: tunnel data replay filter exhausted")
)

// cellReplayFilter is owned by exactly one installed inbound circuit. All
// generations retain their own history until the last packet releases them.
// Successive Bloom filters grow with traffic without evicting older entries.
// When the final filter fills, new cells fail closed instead of resetting the
// replay history. Bloom false positives drop packets but never admit replays.
type cellReplayFilter struct {
	mu      sync.Mutex
	layers  [cellReplayLayers]cellReplayLayer
	current uint8
}

type cellReplayLayer struct {
	words    []uint64
	inserted int
}

func cellReplayLayerBits(index uint8) int {
	return cellReplayFirstBits << (2 * index)
}

// admit marks a cell before any transform, forwarding, or endpoint delivery.
// As specified by I2P, IV XOR the first ciphertext block also rejects the
// IV/first-block swap used in tunnel-message tagging attacks.
func (filter *cellReplayFilter) admit(data []byte) error {
	var tag [tunnelIVLen]byte
	for index := range tag {
		tag[index] = data[index] ^ data[index+tunnelIVLen]
	}
	digest := sha256.Sum256(tag[:])
	first := binary.LittleEndian.Uint64(digest[:8])
	step := binary.LittleEndian.Uint64(digest[8:16]) | 1

	filter.mu.Lock()
	defer filter.mu.Unlock()
	for index := range filter.layers {
		if filter.layers[index].contains(first, step) {
			return ErrTunnelReplay
		}
	}

	layer := &filter.layers[filter.current]
	if layer.words == nil {
		layer.words = make([]uint64, cellReplayLayerBits(filter.current)/64)
	}
	if layer.inserted >= len(layer.words)*64/cellReplayBitsPerEntry {
		if filter.current == cellReplayLayers-1 {
			return ErrTunnelReplayCapacity
		}
		filter.current++
		layer = &filter.layers[filter.current]
		layer.words = make([]uint64, cellReplayLayerBits(filter.current)/64)
	}
	layer.add(first, step)
	layer.inserted++
	return nil
}

func (layer *cellReplayLayer) contains(first, step uint64) bool {
	if len(layer.words) == 0 {
		return false
	}
	mask := uint64(len(layer.words)*64 - 1)
	for index := uint64(0); index < cellReplayHashes; index++ {
		bit := (first + index*step) & mask
		if layer.words[bit/64]&(uint64(1)<<(bit&63)) == 0 {
			return false
		}
	}
	return true
}

func (layer *cellReplayLayer) add(first, step uint64) {
	mask := uint64(len(layer.words)*64 - 1)
	for index := uint64(0); index < cellReplayHashes; index++ {
		bit := (first + index*step) & mask
		layer.words[bit/64] |= uint64(1) << (bit & 63)
	}
}
