// Package ssu2 implements strict SSU2 header protection and data-packet AEAD.
package ssu2

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20"
	"gosuda.org/ivnp/crypto/cryptx"
	"gosuda.org/ivnp/internal/wire"
)

const (
	Version          = 2
	NetworkID        = 2
	ShortHeaderLen   = 16
	LongHeaderLen    = 32
	MinPacketLen     = 40
	MaxIPv4PacketLen = 1472
	MaxIPv6PacketLen = 1452
	PacketTagLen     = cryptx.ChaChaTagSize
)

var (
	ErrPacketLength     = errors.New("ssu2: invalid packet length")
	ErrPacketType       = errors.New("ssu2: invalid packet type")
	ErrNetwork          = errors.New("ssu2: unsupported network or version")
	ErrHeaderProtection = errors.New("ssu2: header protection input is too short")
)

// PacketType is the SSU2 packet type encoded in header byte 12.
type PacketType uint8

const (
	SessionRequest   PacketType = 0
	SessionCreated   PacketType = 1
	SessionConfirmed PacketType = 2
	Data             PacketType = 6
	PeerTest         PacketType = 7
	Retry            PacketType = 9
	TokenRequest     PacketType = 10
	HolePunch        PacketType = 11
)

// LongHeader is used before a session exists and for out-of-session services.
type LongHeader struct {
	DestinationID uint64
	PacketNumber  uint32
	Type          PacketType
	Version       uint8
	NetworkID     uint8
	Flags         uint8
	SourceID      uint64
	Token         uint64
}

func ParseLongHeader(src []byte, expectedNetwork uint8) (LongHeader, error) {
	if len(src) < LongHeaderLen {
		return LongHeader{}, wire.ErrShortBuffer
	}
	header := LongHeader{
		DestinationID: binary.BigEndian.Uint64(src[:8]),
		PacketNumber:  binary.BigEndian.Uint32(src[8:12]),
		Type:          PacketType(src[12]),
		Version:       src[13],
		NetworkID:     src[14],
		Flags:         src[15],
		SourceID:      binary.BigEndian.Uint64(src[16:24]),
		Token:         binary.BigEndian.Uint64(src[24:32]),
	}
	if header.Version != Version || header.NetworkID != expectedNetwork || header.Flags != 0 {
		return LongHeader{}, ErrNetwork
	}
	switch header.Type {
	case SessionRequest, SessionCreated, PeerTest, Retry, TokenRequest, HolePunch:
		return header, nil
	default:
		return LongHeader{}, ErrPacketType
	}
}

func (h LongHeader) MarshalTo(dst []byte) error {
	if len(dst) < LongHeaderLen {
		return wire.ErrShortBuffer
	}
	if h.Version != Version || h.Flags != 0 {
		return ErrNetwork
	}
	binary.BigEndian.PutUint64(dst[:8], h.DestinationID)
	binary.BigEndian.PutUint32(dst[8:12], h.PacketNumber)
	dst[12], dst[13], dst[14], dst[15] = byte(h.Type), h.Version, h.NetworkID, h.Flags
	binary.BigEndian.PutUint64(dst[16:24], h.SourceID)
	binary.BigEndian.PutUint64(dst[24:32], h.Token)
	return nil
}

// ShortHeader is used by SessionConfirmed and data-phase packets.
type ShortHeader struct {
	DestinationID uint64
	PacketNumber  uint32
	Type          PacketType
	Fragment      uint8  // SessionConfirmed only
	Flags         uint16 // SessionConfirmed or Data flags
}

func ParseShortHeader(src []byte) (ShortHeader, error) {
	if len(src) < ShortHeaderLen {
		return ShortHeader{}, wire.ErrShortBuffer
	}
	header := ShortHeader{DestinationID: binary.BigEndian.Uint64(src[:8]), PacketNumber: binary.BigEndian.Uint32(src[8:12]), Type: PacketType(src[12]), Fragment: src[13], Flags: binary.BigEndian.Uint16(src[14:16])}
	switch header.Type {
	case SessionConfirmed:
		if header.PacketNumber != 0 || header.Fragment>>4 == 15 || header.Fragment&0x0f == 0 || header.Flags != 0 {
			return ShortHeader{}, ErrPacketType
		}
	case Data:
		if header.Fragment&0xfe != 0 || header.Flags != 0 {
			return ShortHeader{}, ErrPacketType
		}
	default:
		return ShortHeader{}, ErrPacketType
	}
	return header, nil
}

func (h ShortHeader) MarshalTo(dst []byte) error {
	if len(dst) < ShortHeaderLen {
		return wire.ErrShortBuffer
	}
	binary.BigEndian.PutUint64(dst[:8], h.DestinationID)
	binary.BigEndian.PutUint32(dst[8:12], h.PacketNumber)
	dst[12], dst[13] = byte(h.Type), h.Fragment
	binary.BigEndian.PutUint16(dst[14:16], h.Flags)
	return nil
}

// ProtectHeader XORs SSU2 header-protection masks in place. For Session
// Request/Created set extra to 48 (long-header tail plus ephemeral key); for
// other long headers set it to 16; data and SessionConfirmed use zero.
func ProtectHeader(packet, headerKey1, headerKey2 []byte, extra int) error {
	if len(headerKey1) != cryptx.ChaChaKeySize || len(headerKey2) != cryptx.ChaChaKeySize || len(packet) < MinPacketLen || len(packet) > MaxIPv4PacketLen {
		return ErrHeaderProtection
	}
	if extra != 0 && (extra != 16 && extra != 48) {
		return ErrHeaderProtection
	}
	if len(packet) < ShortHeaderLen+extra {
		return ErrHeaderProtection
	}
	if err := xorHeaderMask(packet[:8], headerKey1, packet[len(packet)-24:len(packet)-12]); err != nil {
		return err
	}
	if err := xorHeaderMask(packet[8:16], headerKey2, packet[len(packet)-12:]); err != nil {
		return err
	}
	if extra != 0 {
		var zeroNonce [cryptx.ChaChaNonceSize]byte
		stream, err := chacha20.NewUnauthenticatedCipher(headerKey2, zeroNonce[:])
		if err != nil {
			return err
		}
		stream.SetCounter(1)
		stream.XORKeyStream(packet[16:16+extra], packet[16:16+extra])
	}
	return nil
}

func xorHeaderMask(dst, key, nonce []byte) error {
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}
	stream.SetCounter(1)
	var mask [8]byte
	stream.XORKeyStream(mask[:], mask[:])
	for i := range mask {
		dst[i] ^= mask[i]
	}
	return nil
}

// DataCipher owns one SSU2 data-direction AEAD and its two header keys. Its
// methods serialize callers so the reusable nonce buffer never escapes to the
// generic AEAD interface.
type DataCipher struct {
	aead       *cryptx.ChaCha20Poly1305
	headerKey1 [cryptx.ChaChaKeySize]byte
	headerKey2 [cryptx.ChaChaKeySize]byte
	mu         sync.Mutex
	nonce      [cryptx.ChaChaNonceSize]byte
	released   bool
}

var _ cryptx.Sensitive = (*DataCipher)(nil)

func NewDataCipher(dataKey, headerKey1, headerKey2 []byte) (*DataCipher, error) {
	aead, err := cryptx.NewChaCha20Poly1305(dataKey)
	if err != nil {
		return nil, err
	}
	if len(headerKey1) != cryptx.ChaChaKeySize || len(headerKey2) != cryptx.ChaChaKeySize {
		aead.ReleaseSensitive()
		return nil, cryptx.ErrKeyLength
	}
	result := &DataCipher{aead: aead}
	copy(result.headerKey1[:], headerKey1)
	copy(result.headerKey2[:], headerKey2)
	return result, nil
}

// ReleaseSensitive serializes with data operations then clears all retained
// IVNP-owned data and header key material.
func (c *DataCipher) ReleaseSensitive() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return
	}
	if c.aead != nil {
		c.aead.ReleaseSensitive()
		c.aead = nil
	}
	clear(c.headerKey1[:])
	clear(c.headerKey2[:])
	clear(c.nonce[:])
	c.released = true
}

// SealDataTo writes an authenticated, header-protected SSU2 data packet. The
// caller supplies the packet number; retransmissions must use a new number.
func (c *DataCipher) SealDataTo(dst []byte, header ShortHeader, plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, cryptx.ErrSensitiveReleased
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return nil, cryptx.ErrSensitiveReleased
	}
	if header.Type != Data || header.Fragment&0xfe != 0 || header.Flags != 0 || len(plaintext) < 8 {
		return nil, ErrPacketLength
	}
	total := ShortHeaderLen + len(plaintext) + PacketTagLen
	if total > MaxIPv4PacketLen {
		return nil, ErrPacketLength
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	if err := header.MarshalTo(dst[:ShortHeaderLen]); err != nil {
		return nil, err
	}
	clear(c.nonce[:])
	binary.LittleEndian.PutUint64(c.nonce[4:], uint64(header.PacketNumber))
	if _, err := c.aead.SealTo(dst[ShortHeaderLen:total], c.nonce[:], plaintext, dst[:ShortHeaderLen]); err != nil {
		return nil, err
	}
	if err := ProtectHeader(dst[:total], c.headerKey1[:], c.headerKey2[:], 0); err != nil {
		return nil, err
	}
	return dst[:total], nil
}

// OpenDataTo removes header protection in place, validates the short header,
// and authenticates the encrypted data packet into dst.
func (c *DataCipher) OpenDataTo(dst, packet []byte) (ShortHeader, []byte, error) {
	if c == nil {
		return ShortHeader{}, nil, cryptx.ErrSensitiveReleased
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return ShortHeader{}, nil, cryptx.ErrSensitiveReleased
	}
	if len(packet) < MinPacketLen || len(packet) > MaxIPv4PacketLen {
		return ShortHeader{}, nil, ErrPacketLength
	}
	if err := ProtectHeader(packet, c.headerKey1[:], c.headerKey2[:], 0); err != nil {
		return ShortHeader{}, nil, err
	}
	header, err := ParseShortHeader(packet[:ShortHeaderLen])
	if err != nil {
		return ShortHeader{}, nil, err
	}
	clear(c.nonce[:])
	binary.LittleEndian.PutUint64(c.nonce[4:], uint64(header.PacketNumber))
	plain, err := c.aead.OpenTo(dst, c.nonce[:], packet[ShortHeaderLen:], packet[:ShortHeaderLen])
	if err != nil {
		return ShortHeader{}, nil, err
	}
	return header, plain, nil
}

// SameConnectionID verifies the protocol's required distinct endpoint IDs.
func SameConnectionID(left, right uint64) bool {
	return subtle.ConstantTimeEq(int32(left>>32), int32(right>>32)) == 1 && subtle.ConstantTimeEq(int32(left), int32(right)) == 1
}
