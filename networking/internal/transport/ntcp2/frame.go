// Package ntcp2 implements the authenticated NTCP2 data-phase frame codec.
package ntcp2

import (
	"encoding/binary"
	"errors"
	cryptx "gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
	"math"
)

const (
	FrameLengthLen    = 2
	FrameTagLen       = cryptx.ChaChaTagSize
	MinEncryptedFrame = FrameTagLen
	MaxEncryptedFrame = 1<<16 - 1
	MaxPlaintextFrame = MaxEncryptedFrame - FrameTagLen
	BlockHeaderLen    = 3
	MaxBlockData      = MaxPlaintextFrame - BlockHeaderLen

	BlockDateTime    = 0
	BlockOptions     = 1
	BlockRouterInfo  = 2
	BlockI2NP        = 3
	BlockTermination = 4
	BlockPadding     = 254
)

var (
	ErrFrameLength    = errors.New("ntcp2: invalid frame length")
	ErrFrameTooLarge  = errors.New("ntcp2: frame exceeds protocol maximum")
	ErrNonceExhausted = errors.New("ntcp2: ChaCha nonce exhausted")
	ErrBlockOrder     = errors.New("ntcp2: invalid block ordering")
	ErrBlockLength    = errors.New("ntcp2: invalid block length")
)

// SipState is the directional SipHash-2-4 state used to mask NTCP2 frame
// lengths. Keys and IV are decoded little-endian from the handshake KDF.
type SipState struct {
	k0 uint64
	k1 uint64
	iv uint64
}

func NewSipState(key, iv []byte) (SipState, error) {
	if len(key) != 16 || len(iv) != 8 {
		return SipState{}, ErrFrameLength
	}
	return SipState{k0: binary.LittleEndian.Uint64(key[:8]), k1: binary.LittleEndian.Uint64(key[8:]), iv: binary.LittleEndian.Uint64(iv)}, nil
}

func (s *SipState) nextMask() uint16 {
	s.iv = sipHash24(s.k0, s.k1, s.iv)
	return uint16(s.iv)
}

// Direction owns one unidirectional post-handshake cipher state. It is not
// safe for concurrent use; one transport goroutine must own each direction.
type Direction struct {
	cipher   *cryptx.ChaCha20Poly1305
	sip      SipState
	nonce    uint64
	nonceBuf [cryptx.ChaChaNonceSize]byte
	released bool
}

var _ cryptx.Sensitive = (*Direction)(nil)

func NewDirection(chachaKey, sipKey, sipIV []byte) (*Direction, error) {
	cipher, err := cryptx.NewChaCha20Poly1305(chachaKey)
	if err != nil {
		return nil, err
	}
	sip, err := NewSipState(sipKey, sipIV)
	if err != nil {
		cipher.ReleaseSensitive()
		return nil, err
	}
	return &Direction{cipher: cipher, sip: sip}, nil
}

// ReleaseSensitive overwrites IVNP-owned frame key state.
func (d *Direction) ReleaseSensitive() {
	if d == nil || d.released {
		return
	}
	if d.cipher != nil {
		d.cipher.ReleaseSensitive()
		d.cipher = nil
	}
	d.sip = SipState{}
	d.nonce = 0
	clear(d.nonceBuf[:])
	d.released = true
}

// SealTo writes obfuscated length || ChaChaPoly frame to dst. plaintext must
// already contain a complete sequence of NTCP2 blocks.
func (d *Direction) SealTo(dst, plaintext []byte) ([]byte, error) {
	if d == nil || d.released {
		return nil, cryptx.ErrSensitiveReleased
	}
	if len(plaintext) > MaxPlaintextFrame {
		return nil, ErrFrameTooLarge
	}
	if d.nonce >= math.MaxUint64-1 {
		return nil, ErrNonceExhausted
	}
	frameLen := len(plaintext) + FrameTagLen
	if len(dst) < FrameLengthLen+frameLen {
		return nil, wire.ErrShortBuffer
	}
	binary.LittleEndian.PutUint64(d.nonceBuf[4:], d.nonce)
	if _, err := d.cipher.SealTo(dst[FrameLengthLen:FrameLengthLen+frameLen], d.nonceBuf[:], plaintext, nil); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(dst[:FrameLengthLen], uint16(frameLen)^d.sip.nextMask())
	d.nonce++
	return dst[:FrameLengthLen+frameLen], nil
}

// OpenTo authenticates and decrypts one complete obfuscated NTCP2 frame.
func (d *Direction) OpenTo(dst, input []byte) ([]byte, error) {
	if d == nil || d.released {
		return nil, cryptx.ErrSensitiveReleased
	}
	if len(input) < FrameLengthLen {
		return nil, wire.ErrShortBuffer
	}
	frameLen := int(binary.BigEndian.Uint16(input[:FrameLengthLen]) ^ d.sip.nextMask())
	if frameLen < MinEncryptedFrame || frameLen > MaxEncryptedFrame {
		return nil, ErrFrameLength
	}
	if len(input)-FrameLengthLen != frameLen {
		return nil, wire.ErrShortBuffer
	}
	if d.nonce >= math.MaxUint64-1 {
		return nil, ErrNonceExhausted
	}
	binary.LittleEndian.PutUint64(d.nonceBuf[4:], d.nonce)
	plain, err := d.cipher.OpenTo(dst, d.nonceBuf[:], input[FrameLengthLen:], nil)
	if err != nil {
		return nil, err
	}
	d.nonce++
	return plain, nil
}

// Block is a zero-copy NTCP2 data-phase block.
type Block struct {
	Type uint8
	Data []byte
}

// BlockIterator validates each block's uint16 length before exposing its data.
type BlockIterator struct {
	rest       []byte
	terminated bool
	padded     bool
}

func NewBlockIterator(plaintext []byte) BlockIterator { return BlockIterator{rest: plaintext} }

func (it *BlockIterator) Next() (Block, bool, error) {
	if len(it.rest) == 0 {
		return Block{}, false, nil
	}
	if it.padded || (it.terminated && it.rest[0] != BlockPadding) {
		return Block{}, false, ErrBlockOrder
	}
	if len(it.rest) < BlockHeaderLen {
		return Block{}, false, wire.ErrShortBuffer
	}
	kind := it.rest[0]
	n := int(binary.BigEndian.Uint16(it.rest[1:3]))
	if n > len(it.rest)-BlockHeaderLen {
		return Block{}, false, ErrBlockLength
	}
	block := Block{Type: kind, Data: it.rest[BlockHeaderLen : BlockHeaderLen+n]}
	it.rest = it.rest[BlockHeaderLen+n:]
	if kind == BlockPadding {
		it.padded = true
	}
	if kind == BlockTermination {
		it.terminated = true
	}
	if it.padded && len(it.rest) != 0 {
		return Block{}, false, ErrBlockOrder
	}
	if it.terminated && len(it.rest) != 0 && it.rest[0] != BlockPadding {
		return Block{}, false, ErrBlockOrder
	}
	return block, true, nil
}

// ValidateBlocks checks complete block grammar and mandatory DateTime size.
func ValidateBlocks(plaintext []byte) error {
	iterator := NewBlockIterator(plaintext)
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if block.Type == BlockDateTime && len(block.Data) != 4 {
			return ErrBlockLength
		}
	}
}

// sipHash24 computes SipHash-2-4 over exactly eight little-endian input bytes.
func sipHash24(k0, k1, message uint64) uint64 {
	v0 := uint64(0x736f6d6570736575) ^ k0
	v1 := uint64(0x646f72616e646f6d) ^ k1
	v2 := uint64(0x6c7967656e657261) ^ k0
	v3 := uint64(0x7465646279746573) ^ k1
	v3 ^= message
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= message
	// SipHash finalizes a complete eight-byte input block with a separate
	// length block. The input length is eight, so its little-endian tail is
	// exactly 8 << 56.
	tail := uint64(8) << 56
	v3 ^= tail
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= tail
	v2 ^= 0xff
	for range 4 {
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32
	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2
	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0
	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32
	return v0, v1, v2, v3
}
