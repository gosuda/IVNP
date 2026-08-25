package tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"gosuda.org/ivnp/internal/packet"
	"gosuda.org/ivnp/networking/internal/i2np"
)

const (
	// TunnelPayloadLen is the fixed encrypted tunnel block carried by an I2NP
	// TunnelData message. The cleartext layout is IV || checksum || nonzero
	// padding || zero delimiter || delivery blocks.
	TunnelPayloadLen  = i2np.TunnelDataPayloadLen
	tunnelIVLen       = 16
	tunnelChecksumLen = 4
	maxBlockBytes     = TunnelPayloadLen - tunnelIVLen - tunnelChecksumLen - 1
)

var (
	ErrGatewayPayload = errors.New("tunnel: invalid tunnel gateway payload")
	ErrGatewayBlock   = errors.New("tunnel: invalid tunnel gateway block")
	ErrGatewayOutput  = errors.New("tunnel: insufficient tunnel gateway output storage")
)

// Gateway packs delivery blocks into fixed-size TunnelData messages. Padding is
// supplied by the caller so an application can source it from its tunnel
// cryptographic context. A nil padding reader uses crypto/rand.Reader.
type Gateway struct {
	padding io.Reader
}

func NewGateway(padding io.Reader) *Gateway {
	if padding ==

		nil {
		padding = rand.Reader
	}

	return &Gateway{padding: padding}
}

// Encode writes one complete *unencrypted* I2NP TunnelData payload into dst.
// Its 1,024-byte tunnel region follows i2pd's layout: an IV, the four-byte
// SHA-256 checksum of delivery blocks plus IV, nonzero padding, a zero
// delimiter, and delivery blocks. A circuit applies layer transforms to
// out[4:] only after this method returns.
func (g *Gateway) Encode(tunnelID uint32, blocks []Block, dst *packet.Buffer) error {
	if tunnelID == 0 {
		return i2np.ErrInvalidTunnelID
	}
	if dst == nil {
		return ErrGatewayOutput
	}
	available, ok := dst.AvailablePayload()
	if !ok || available < i2np.TunnelDataMessageLen {
		return ErrGatewayOutput
	}

	n := 0
	for _, block := range blocks {
		m, err := blockLen(block)
		if err != nil || m > maxBlockBytes-n {
			return ErrGatewayBlock
		}
		n += m
	}

	out, ok := dst.Append(i2np.TunnelDataMessageLen)
	if !ok {
		return ErrGatewayOutput
	}
	binary.BigEndian.PutUint32(out[:4], tunnelID)
	data := out[4:]
	reader := rand.Reader
	if g != nil && g.padding != nil {
		reader = g.padding
	}
	if _, err := io.ReadFull(reader, data[:tunnelIVLen]); err != nil {
		return err
	}
	padding := data[tunnelIVLen+tunnelChecksumLen : len(data)-n-1]
	if err := readNonZero(reader, padding); err != nil {
		return err
	}
	blocksStart := tunnelIVLen + tunnelChecksumLen + len(padding) + 1
	data[blocksStart-1] = 0
	encoded := data[blocksStart:]
	offset := 0
	for _, block := range blocks {
		m, _ := marshalBlock(encoded[offset:], block)
		offset += m
	}
	checksum := tunnelChecksum(encoded, data[:tunnelIVLen])
	copy(data[tunnelIVLen:tunnelIVLen+tunnelChecksumLen], checksum[:tunnelChecksumLen])
	return nil
}

// Fragment splits block into initial and follow-on blocks and writes each in a
// separate fixed-size TunnelData payload. dst is caller-owned and may contain
// more buffers than required; the returned count identifies the buffers written.
func (g *Gateway) Fragment(tunnelID uint32, block Block, dst []*packet.Buffer) (int, error) {
	if tunnelID == 0 {
		return 0, i2np.ErrInvalidTunnelID
	}
	if block.FollowOn || block.Delivery > DeliveryRouter || len(block.Data) == 0 || len(block.Data) > i2np.I2PDMaxPayload {
		return 0, ErrGatewayBlock
	}

	firstHeader, err := firstBlockLen(block, true)
	if err != nil {
		return 0, err
	}
	if len(block.Data) <= maxBlockBytes-firstHeader {
		block.Last = true
		if len(dst) == 0 {
			return 0, ErrGatewayOutput
		}
		return 1, g.Encode(tunnelID, []Block{block}, dst[0])
	}

	firstData := maxBlockBytes - firstHeader
	needed := 1 + (len(block.Data)-firstData+maxBlockBytes-7-1)/(maxBlockBytes-7)
	if needed > 64 || len(dst) < needed {
		return 0, ErrGatewayOutput
	}

	if block.MessageID == 0 {
		var encoded [4]byte
		if err := readNonZero(g.padding, encoded[:]); err != nil {
			return 0, err
		}
		block.MessageID = binary.BigEndian.Uint32(encoded[:])
	}

	first := block
	first.Last = false
	first.Data = block.Data[:firstData]
	if err := g.Encode(tunnelID, []Block{first}, dst[0]); err != nil {
		return 0, err
	}

	offset := firstData
	for fragment := 1; offset < len(block.Data); fragment++ {
		end := min(offset+maxBlockBytes-7, len(block.Data))
		follow := Block{
			FollowOn:  true,
			MessageID: block.MessageID,
			Fragment:  uint8(fragment),
			Last:      end == len(block.Data),
			Data:      block.Data[offset:end],
		}
		if err := g.Encode(tunnelID, []Block{follow}, dst[fragment]); err != nil {
			return fragment, err
		}
		offset = end
	}
	return needed, nil
}

func readNonZero(reader io.Reader, dst []byte) error {
	if _, err := io.ReadFull(reader, dst); err != nil {
		return err
	}
	for i := range dst {
		if dst[i] == 0 {
			// Replacing zero keeps padding nonzero without an unbounded retry
			// loop when the caller supplies a deterministic reader.
			dst[i] = 1
		}
	}
	return nil
}

func tunnelChecksum(blocks, iv []byte) [sha256.Size]byte {
	var input [TunnelPayloadLen + tunnelIVLen]byte
	n := copy(input[:], blocks)
	n += copy(input[n:], iv)
	return sha256.Sum256(input[:n])
}

func firstBlockLen(block Block, fragmented bool) (int, error) {
	if block.Delivery > DeliveryRouter || block.FollowOn {
		return 0, ErrGatewayBlock
	}
	n := 1 + 2
	switch block.Delivery {
	case DeliveryTunnel:
		if block.TunnelID == 0 {
			return 0, ErrGatewayBlock
		}
		n += 36
	case DeliveryRouter:
		n += 32
	}
	if fragmented {
		n += 4
	}
	return n, nil
}

func blockLen(block Block) (int, error) {
	if len(block.Data) == 0 || len(block.Data) > 1<<16-1 {
		return 0, ErrGatewayBlock
	}
	if block.FollowOn {
		if block.Fragment == 0 || block.Fragment > 63 {
			return 0, ErrGatewayBlock
		}
		return 1 + 4 + 2 + len(block.Data), nil
	}
	n, err := firstBlockLen(block, !block.Last)
	if err != nil {
		return 0, err
	}
	return n + len(block.Data), nil
}

func marshalBlock(dst []byte, block Block) (int, error) {
	n, err := blockLen(block)
	if err != nil || len(dst) < n {
		return 0, ErrGatewayBlock
	}
	if block.FollowOn {
		dst[0] = 0x80 | block.Fragment<<1
		if block.Last {
			dst[0] |= 1
		}
		binary.BigEndian.PutUint32(dst[1:5], block.MessageID)
		binary.BigEndian.PutUint16(dst[5:7], uint16(len(block.Data)))
		copy(dst[7:], block.Data)
		return n, nil
	}

	fragmented := !block.Last
	flag := byte(block.Delivery << 5)
	if fragmented {
		flag |= 0x08
	}
	dst[0] = flag
	off := 1
	switch block.Delivery {
	case DeliveryTunnel:
		binary.BigEndian.PutUint32(dst[off:off+4], block.TunnelID)
		copy(dst[off+4:off+36], block.Gateway[:])
		off += 36
	case DeliveryRouter:
		copy(dst[off:off+32], block.Gateway[:])
		off += 32
	}
	if fragmented {
		binary.BigEndian.PutUint32(dst[off:off+4], block.MessageID)
		off += 4
	}
	binary.BigEndian.PutUint16(dst[off:off+2], uint16(len(block.Data)))
	off += 2
	copy(dst[off:], block.Data)
	return n, nil
}

// Endpoint parses a decrypted TunnelData payload. Complete unfragmented blocks
// alias payload; reassembled messages are newly allocated by Reassembler.
type Endpoint struct {
	mu      sync.Mutex
	reasm   *Reassembler
	maxMeta int
	clock   uint64
	meta    map[uint32]deliveryMeta
}

type deliveryMeta struct {
	block   Block
	touched uint64
}

func NewEndpoint(maxEntries, maxMessage int) *Endpoint {
	if maxEntries <= 0 {
		maxEntries = 128
	}
	return &Endpoint{
		reasm:   NewReassembler(maxEntries, maxMessage),
		maxMeta: maxEntries,
		meta:    make(map[uint32]deliveryMeta),
	}
}

// Parse reads a complete 1028-byte I2NP TunnelData payload and writes completed
// deliveries to out. It returns ErrGatewayOutput if out cannot hold all
// completed deliveries. Follow-on fragments may arrive before their initial
// fragment; no delivery is emitted until both delivery metadata and every
// fragment are present.
func (e *Endpoint) Parse(payload []byte, out []Block) (int, error) {
	message, err := i2np.ParseTunnelData(payload)
	if err != nil {
		return 0, err
	}
	data := message.Data
	if len(data) != TunnelPayloadLen {
		return 0, ErrGatewayPayload
	}
	checksum := data[tunnelIVLen : tunnelIVLen+tunnelChecksumLen]
	iv := data[:tunnelIVLen]
	start := tunnelIVLen + tunnelChecksumLen
	for start < len(data) && data[start] != 0 {
		start++
	}
	if start == len(data) {
		return 0, ErrGatewayPayload
	}
	blocks := data[start+1:]
	expected := tunnelChecksum(blocks, iv)
	if subtle.ConstantTimeCompare(checksum, expected[:tunnelChecksumLen]) != 1 {
		return 0, ErrGatewayPayload
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock++
	it := NewBlockIterator(data[start+1:])
	n := 0
	for {
		block, ok, err := it.Next()
		if err != nil {
			return n, err
		}
		if !ok {
			return n, nil
		}
		if block.FollowOn {
			if block.Fragment == 0 {
				return n, ErrGatewayBlock
			}
			complete, done, err := e.reasm.Add(Fragment{MessageID: block.MessageID, Number: block.Fragment, Last: block.Last, Data: block.Data})
			if err != nil {
				return n, err
			}
			if done {
				meta, exists := e.meta[block.MessageID]
				if !exists {
					return n, ErrFragment
				}
				if n == len(out) {
					return n, ErrGatewayOutput
				}
				meta.block.Data, meta.block.Last = complete, true
				out[n] = meta.block
				n++
				delete(e.meta, block.MessageID)
			}
			continue
		}
		if block.Last {
			if n == len(out) {
				return n, ErrGatewayOutput
			}
			out[n] = block
			n++
			continue
		}

		if err := e.remember(block); err != nil {
			return n, err
		}
		complete, done, err := e.reasm.Add(Fragment{MessageID: block.MessageID, Number: 0, Data: block.Data})
		if err != nil {
			return n, err
		}
		if done {
			meta := e.meta[block.MessageID]
			if n == len(out) {
				return n, ErrGatewayOutput
			}
			meta.block.Data, meta.block.Last = complete, true
			out[n] = meta.block
			n++
			delete(e.meta, block.MessageID)
		}
	}
}

func (e *Endpoint) remember(block Block) error {
	block.Data = nil
	if prior, exists := e.meta[block.MessageID]; exists {
		if prior.block.Delivery != block.Delivery || prior.block.Gateway != block.Gateway || prior.block.TunnelID != block.TunnelID {
			return ErrFragment
		}
		prior.touched = e.clock
		e.meta[block.MessageID] = prior
		return nil
	}
	if len(e.meta) == e.maxMeta {
		var oldestID uint32
		var oldest uint64 = ^uint64(0)
		for id, item := range e.meta {
			if item.touched < oldest {
				oldestID, oldest = id, item.touched
			}
		}
		delete(e.meta, oldestID)
	}
	e.meta[block.MessageID] = deliveryMeta{block: block, touched: e.clock}
	return nil
}

// Expire removes retained fragment metadata and incomplete reassemblies not
// touched since the supplied endpoint clock tick.
func (e *Endpoint) Expire(cutoff uint64) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := e.reasm.Expire(cutoff)
	for id, item := range e.meta {
		if item.touched <= cutoff {
			delete(e.meta, id)
			removed++
		}
	}
	return removed
}
