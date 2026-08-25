package garlic

import (
	"encoding/binary"

	"gosuda.org/ivnp/internal/wire"
	"gosuda.org/ivnp/protocol/i2np"
)

const (
	cloveCertificateLen    = 3
	cloveMetadataLen       = 4 + 8 + cloveCertificateLen
	cloveSetMetadataLen    = cloveCertificateLen + 4 + 8
	cloveSetPrefixLen      = 1
	cloveDeliveryFlagsMask = 0x0f
)

// EncodedLen returns the number of bytes in d's legacy Garlic delivery
// instruction. MarshalTo validates that its fields can be represented.
func (d Delivery) EncodedLen() int {
	n := 1
	if d.Encrypted {
		n += 32
	}
	if d.Type != DeliveryLocal {
		n += 32
	}
	if d.Type == DeliveryTunnel {
		n += 4
	}
	if d.Delay != 0 {
		n += 4
	}
	return n
}

func (d Delivery) valid() bool {
	if d.Type > DeliveryTunnel || (d.Encrypted && len(d.SessionKey) != 32) {
		return false
	}
	return d.Type != DeliveryTunnel || d.TunnelID != 0
}

// MarshalTo writes d's legacy Garlic delivery instruction into dst without
// allocating.
func (d Delivery) MarshalTo(dst []byte) (int, error) {
	if !d.valid() {
		return 0, ErrDelivery
	}
	if len(dst) < d.EncodedLen() {
		return 0, wire.ErrShortBuffer
	}

	flags := byte(d.Type << 5)
	if d.Encrypted {
		flags |= 0x80
	}
	if d.Delay != 0 {
		flags |= 0x10
	}
	if flags&cloveDeliveryFlagsMask != 0 {
		return 0, ErrDelivery
	}
	dst[0] = flags
	off := 1
	if d.Encrypted {
		off += copy(dst[off:], d.SessionKey)
	}
	if d.Type != DeliveryLocal {
		off += copy(dst[off:], d.To[:])
	}
	if d.Type == DeliveryTunnel {
		binary.BigEndian.PutUint32(dst[off:off+4], d.TunnelID)
		off += 4
	}
	if d.Delay != 0 {
		binary.BigEndian.PutUint32(dst[off:off+4], d.Delay)
		off += 4
	}
	return off, nil
}

// EncodedLen returns the number of bytes in c's legacy Garlic clove. MarshalTo
// validates the delivery instruction and embedded standard I2NP frame.
func (c Clove) EncodedLen() int {
	return c.Delivery.EncodedLen() + c.Message.EncodedLen() + cloveMetadataLen
}

func (c Clove) valid() error {
	if !c.Delivery.valid() {
		return ErrDelivery
	}
	if len(c.Message.Payload) > i2np.I2PDMaxPayload {
		return i2np.ErrPayloadTooLarge
	}
	return nil
}

// MarshalTo writes c as a legacy Garlic clove. The embedded I2NP message uses
// the standard header and checksum required by Garlic clove framing.
func (c Clove) MarshalTo(dst []byte) (int, error) {
	if err := c.valid(); err != nil {
		return 0, err
	}
	if len(dst) < c.EncodedLen() {
		return 0, wire.ErrShortBuffer
	}

	off, err := c.Delivery.MarshalTo(dst)
	if err != nil {
		return 0, err
	}
	messageLen, err := c.Message.MarshalTo(dst[off:])
	if err != nil {
		return 0, err
	}
	off += messageLen
	binary.BigEndian.PutUint32(dst[off:off+4], c.ID)
	off += 4
	binary.BigEndian.PutUint64(dst[off:off+8], c.Expiration)
	off += 8
	// Each legacy clove carries a NULL certificate.
	dst[off] = 0
	dst[off+1] = 0
	dst[off+2] = 0
	off += cloveCertificateLen
	return off, nil
}

// CloveSetEncodedLen returns the bytes required to encode cloves as one legacy
// Garlic clove set, including its NULL certificate and trailing metadata.
func CloveSetEncodedLen(cloves []Clove) (int, error) {
	if len(cloves) > 255 {
		return 0, ErrClove
	}
	n := cloveSetPrefixLen + cloveSetMetadataLen
	for _, clove := range cloves {
		if err := clove.valid(); err != nil {
			return 0, err
		}
		cloveLen := clove.EncodedLen()
		if cloveLen > int(^uint(0)>>1)-n {
			return 0, ErrClove
		}
		n += cloveLen
	}
	return n, nil
}

// MarshalCloveSetTo writes a legacy Garlic clove set with a NULL certificate
// into caller-owned dst without allocating.
func MarshalCloveSetTo(dst []byte, cloves []Clove, messageID uint32, expiration uint64) (int, error) {
	n, err := CloveSetEncodedLen(cloves)
	if err != nil {
		return 0, err
	}
	if len(dst) < n {
		return 0, wire.ErrShortBuffer
	}

	dst[0] = byte(len(cloves))
	off := cloveSetPrefixLen
	for _, clove := range cloves {
		used, err := clove.MarshalTo(dst[off:])
		if err != nil {
			return 0, err
		}
		off += used
	}
	// A clove set is terminated by a NULL certificate.
	dst[off] = 0
	dst[off+1] = 0
	dst[off+2] = 0
	off += cloveCertificateLen
	binary.BigEndian.PutUint32(dst[off:off+4], messageID)
	off += 4
	binary.BigEndian.PutUint64(dst[off:off+8], expiration)
	off += 8
	return off, nil
}

// EncodedLen returns the number of bytes in the parsed clove set.
func (s CloveSet) EncodedLen() int {
	return cloveSetPrefixLen + len(s.cloves) + cloveSetMetadataLen
}

// MarshalTo copies the parsed legacy clove set into caller-owned dst without
// allocating.
func (s CloveSet) MarshalTo(dst []byte) (int, error) {
	if len(dst) < s.EncodedLen() {
		return 0, wire.ErrShortBuffer
	}
	dst[0] = s.count
	off := cloveSetPrefixLen
	off += copy(dst[off:], s.cloves)
	dst[off] = 0
	dst[off+1] = 0
	dst[off+2] = 0
	off += cloveCertificateLen
	binary.BigEndian.PutUint32(dst[off:off+4], s.MessageID)
	off += 4
	binary.BigEndian.PutUint64(dst[off:off+8], s.Expiration)
	off += 8
	return off, nil
}
