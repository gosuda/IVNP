// Package i2np implements zero-allocation parsing and marshaling of I2P Network Protocol messages.
package i2np

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/internal/wire"
)

const (
	StandardHeaderLen    = 16
	LegacyShortHeaderLen = 5
	TransportHeaderLen   = 9

	MaxWirePayload = 1<<16 - 1
	MaxWireFrame   = StandardHeaderLen + MaxWirePayload

	I2PDMessageBufferBytes = 62_708
	I2PDReservedPrefix     = 2
	I2PDMaxPayload         = I2PDMessageBufferBytes - I2PDReservedPrefix - StandardHeaderLen
	I2PDMaxFrame           = StandardHeaderLen + I2PDMaxPayload

	MaxRouterInfoBytes = 4 * 1024

	TunnelDataPayloadLen     = 1024
	TunnelDataMessageLen     = 4 + TunnelDataPayloadLen
	TunnelGatewayHeaderLen   = 6
	MaxTunnelGatewayEmbedded = I2PDMaxPayload - TunnelGatewayHeaderLen

	BuildRecordLen          = 528
	ShortBuildRecordLen     = 218
	FixedBuildRecords       = 8
	MaxVariableBuildRecords = 8

	MaxDatabaseLookupExcluded = 512
	MaxDatabaseReplyTags      = 32
	MaxDatabaseSearchPeers    = 255

	MaxDatabaseLookupPayload      = 17_512
	MaxDatabaseSearchReplyPayload = 32 + 1 + MaxDatabaseSearchPeers*32 + 32
)

var (
	ErrPayloadTooLarge  = errors.New("i2np: payload exceeds configured limit")
	ErrChecksum         = errors.New("i2np: payload checksum mismatch")
	ErrMalformed        = errors.New("i2np: malformed message")
	ErrUnknownStoreType = errors.New("i2np: unsupported database store type")
	ErrInvalidTunnelID  = errors.New("i2np: zero tunnel ID")
)

// MessageType identifies an I2NP payload layout.
type MessageType uint8

const (
	DatabaseStore            MessageType = 1
	DatabaseLookup           MessageType = 2
	DatabaseSearchReply      MessageType = 3
	DeliveryStatus           MessageType = 10
	Garlic                   MessageType = 11
	TunnelData               MessageType = 18
	TunnelGateway            MessageType = 19
	Data                     MessageType = 20
	TunnelBuild              MessageType = 21
	TunnelBuildReply         MessageType = 22
	VariableTunnelBuild      MessageType = 23
	VariableTunnelBuildReply MessageType = 24
	ShortTunnelBuild         MessageType = 25
	OutboundTunnelBuildReply MessageType = 26
	TunnelTest               MessageType = 231
)

// Header is the logical content of a standard or transport I2NP header.
type Header struct {
	Type       MessageType
	ID         uint32
	Expiration uint64 // milliseconds for standard, seconds for short headers
}

// Message is a checked standard I2NP frame.
type Message struct {
	Header  Header
	Payload []byte
}

func (m Message) EncodedLen() int { return StandardHeaderLen + len(m.Payload) }

// Parse decodes a standard I2NP message with checksum verification.
func Parse(src []byte) (Message, int, error) {
	return parseStandard(src, I2PDMaxPayload, true)
}

// ParseWire decodes a standard I2NP message up to the maximum wire payload size.
func ParseWire(src []byte) (Message, int, error) {
	return parseStandard(src, MaxWirePayload, true)
}

// ParseUnchecked decodes an I2NP message without validating the checksum byte.
func ParseUnchecked(src []byte) (Message, int, error) {
	return parseStandard(src, I2PDMaxPayload, false)
}

func parseStandard(src []byte, payloadLimit int, checksum bool) (Message, int, error) {
	if len(src) < StandardHeaderLen {
		return Message{}, 0, wire.ErrShortBuffer
	}
	payloadLen := int(binary.BigEndian.Uint16(src[13:15]))
	if payloadLen > payloadLimit {
		return Message{}, 0, ErrPayloadTooLarge
	}
	if payloadLen > len(src)-StandardHeaderLen {
		return Message{}, 0, wire.ErrShortBuffer
	}
	payload := src[StandardHeaderLen : StandardHeaderLen+payloadLen]
	if checksum && sha256.Sum256(payload)[0] != src[15] {
		return Message{}, 0, ErrChecksum
	}
	return Message{
		Header: Header{
			Type:       MessageType(src[0]),
			ID:         binary.BigEndian.Uint32(src[1:5]),
			Expiration: binary.BigEndian.Uint64(src[5:13]),
		},
		Payload: payload,
	}, StandardHeaderLen + payloadLen, nil
}

// MarshalTo writes a standard I2NP frame and checksum.
func (m Message) MarshalTo(dst []byte) (int, error) {
	return marshalStandard(dst, m.Header, m.Payload, I2PDMaxPayload)
}

// MarshalWireTo writes an I2NP frame allowing up to the uint16 maximum size.
func (m Message) MarshalWireTo(dst []byte) (int, error) {
	return marshalStandard(dst, m.Header, m.Payload, MaxWirePayload)
}

func marshalStandard(dst []byte, header Header, payload []byte, payloadLimit int) (int, error) {
	if len(payload) > payloadLimit {
		return 0, ErrPayloadTooLarge
	}
	if len(dst) < StandardHeaderLen+len(payload) {
		return 0, wire.ErrShortBuffer
	}
	_ = dst[StandardHeaderLen-1] // Collapse fixed-header bounds checks into one.
	dst[0] = byte(header.Type)
	binary.BigEndian.PutUint32(dst[1:5], header.ID)
	binary.BigEndian.PutUint64(dst[5:13], header.Expiration)
	binary.BigEndian.PutUint16(dst[13:15], uint16(len(payload)))
	dst[15] = sha256.Sum256(payload)[0]
	copy(dst[StandardHeaderLen:], payload)
	return StandardHeaderLen + len(payload), nil
}

// ShortHeader is the legacy SSU I2NP header. Its frame length is supplied by
// the authenticated transport encapsulation.
type ShortHeader struct {
	Type       MessageType
	Expiration uint64 // milliseconds since Unix epoch, centered in the encoded second
}

func ParseLegacyShortHeader(src []byte) (ShortHeader, error) {
	if len(src) < LegacyShortHeaderLen {
		return ShortHeader{}, wire.ErrShortBuffer
	}
	return ShortHeader{Type: MessageType(src[0]), Expiration: DecodeTransportExpiration(binary.BigEndian.Uint32(src[1:5]))}, nil
}

// TransportHeader is the NTCP2, SSU2, and ECIES garlic nine-byte header.
type TransportHeader struct {
	Type       MessageType
	ID         uint32
	Expiration uint64 // milliseconds since Unix epoch, centered in the encoded second
}

func ParseTransportHeader(src []byte) (TransportHeader, error) {
	if len(src) < TransportHeaderLen {
		return TransportHeader{}, wire.ErrShortBuffer
	}
	return TransportHeader{
		Type:       MessageType(src[0]),
		ID:         binary.BigEndian.Uint32(src[1:5]),
		Expiration: DecodeTransportExpiration(binary.BigEndian.Uint32(src[5:9])),
	}, nil
}

// EncodeTransportExpiration rounds a millisecond timestamp to nearest seconds for transport wire encoding.
func EncodeTransportExpiration(milliseconds uint64) (uint32, bool) {
	const max = uint64(^uint32(0))
	if milliseconds > max*1000+499 {
		return 0, false
	}
	return uint32((milliseconds + 500) / 1000), true
}

// DecodeTransportExpiration converts a transport seconds timestamp to milliseconds.
func DecodeTransportExpiration(seconds uint32) uint64 {
	return uint64(seconds)*1000 + 500
}

// StoreType identifies the data carried by a DatabaseStore message.
type StoreType uint8

const (
	StoreRouterInfo        StoreType = 0
	StoreLeaseSet          StoreType = 1
	StoreLeaseSet2         StoreType = 3
	StoreEncryptedLeaseSet StoreType = 5
	StoreMetaLeaseSet      StoreType = 7
)

// DatabaseStoreMessage represents a parsed DatabaseStore payload.
type DatabaseStoreMessage struct {
	Key           foundation.Hash
	Type          StoreType
	RawType       uint8
	ReplyToken    uint32
	ReplyTunnelID uint32
	ReplyGateway  foundation.Hash
	Data          []byte
}

// ParseDatabaseStore decodes a DatabaseStore message payload.
func ParseDatabaseStore(payload []byte) (DatabaseStoreMessage, error) {
	if len(payload) > I2PDMaxPayload {
		return DatabaseStoreMessage{}, ErrPayloadTooLarge
	}
	if len(payload) < 37 {
		return DatabaseStoreMessage{}, wire.ErrShortBuffer
	}
	var out DatabaseStoreMessage
	copy(out.Key[:], payload[:32])
	if out.Key == (foundation.Hash{}) {
		return DatabaseStoreMessage{}, ErrMalformed
	}
	out.RawType = payload[32]
	out.Type = StoreType(out.RawType & 0x0f)
	switch out.Type {
	case StoreRouterInfo, StoreLeaseSet, StoreLeaseSet2, StoreEncryptedLeaseSet, StoreMetaLeaseSet:
	default:
		return DatabaseStoreMessage{}, ErrUnknownStoreType
	}
	out.ReplyToken = binary.BigEndian.Uint32(payload[33:37])
	off := 37
	if out.ReplyToken != 0 {
		if len(payload)-off < 36 {
			return DatabaseStoreMessage{}, wire.ErrShortBuffer
		}
		out.ReplyTunnelID = binary.BigEndian.Uint32(payload[off : off+4])
		copy(out.ReplyGateway[:], payload[off+4:off+36])
		off += 36
	}
	if out.Type == StoreRouterInfo {
		if len(payload)-off < 2 {
			return DatabaseStoreMessage{}, wire.ErrShortBuffer
		}
		size := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		// Compressed size is not the RouterInfo object size. NetDB enforces
		// MaxRouterInfoBytes while inflating the authenticated store.
		if size != len(payload)-off {
			return DatabaseStoreMessage{}, ErrMalformed
		}
	}
	if off == len(payload) {
		return DatabaseStoreMessage{}, ErrMalformed
	}
	out.Data = payload[off:]
	return out, nil
}

const (
	lookupDelivery  = 1 << 0
	lookupEncrypted = 1 << 1
	lookupTypeMask  = 0x0c
	lookupECIES     = 1 << 4
)

// DatabaseLookupMessage represents a parsed DatabaseLookup payload.
type DatabaseLookupMessage struct {
	Key            foundation.Hash
	From           foundation.Hash
	Flags          uint8
	ReplyTunnelID  uint32
	Excluded       []byte
	ReplyKey       []byte
	ReplyTags      []byte
	ReplyTagLen    uint8
	ReplyPublicKey []byte
}

func (m DatabaseLookupMessage) ExcludedCount() int { return len(m.Excluded) / foundation.HashLength }
func (m DatabaseLookupMessage) ReplyTagCount() int {
	if m.ReplyTagLen == 0 {
		return 0
	}
	return len(m.ReplyTags) / int(m.ReplyTagLen)
}

// ReplyThroughTunnel reports whether replies must be delivered through the reply tunnel.
func (m DatabaseLookupMessage) ReplyThroughTunnel() bool { return m.Flags&lookupDelivery != 0 }

// ReplyEncrypted reports whether the lookup requires an encrypted reply.
func (m DatabaseLookupMessage) ReplyEncrypted() bool {
	return m.Flags&(lookupEncrypted|lookupECIES) != 0
}

// ReplyUsesECIES reports whether the request supplied an ECIES reply key and tag.
func (m DatabaseLookupMessage) ReplyUsesECIES() bool {
	return m.Flags&(lookupEncrypted|lookupECIES) == lookupECIES
}

// ReplyUsesECIESPublicKey reports whether the request uses ECIES public key encryption.
func (m DatabaseLookupMessage) ReplyUsesECIESPublicKey() bool {
	return m.Flags&(lookupEncrypted|lookupECIES) == lookupEncrypted|lookupECIES
}

// ReplyEncryptionMode returns the reply encryption flag bits.
func (m DatabaseLookupMessage) ReplyEncryptionMode() uint8 {
	return m.Flags & (lookupEncrypted | lookupECIES)
}

// LookupType returns the two-bit wire lookup type.
func (m DatabaseLookupMessage) LookupType() uint8 { return (m.Flags & lookupTypeMask) >> 2 }

// ParseDatabaseLookup decodes a DatabaseLookup message payload.
func ParseDatabaseLookup(payload []byte) (DatabaseLookupMessage, error) {
	if len(payload) > MaxDatabaseLookupPayload || len(payload) > I2PDMaxPayload {
		return DatabaseLookupMessage{}, ErrPayloadTooLarge
	}
	if len(payload) < 67 {
		return DatabaseLookupMessage{}, wire.ErrShortBuffer
	}
	var out DatabaseLookupMessage
	copy(out.Key[:], payload[:32])
	copy(out.From[:], payload[32:64])
	out.Flags = payload[64]
	off := 65
	if out.Flags&lookupDelivery != 0 {
		if len(payload)-off < 4 {
			return DatabaseLookupMessage{}, wire.ErrShortBuffer
		}
		out.ReplyTunnelID = binary.BigEndian.Uint32(payload[off : off+4])
		if out.ReplyTunnelID == 0 {
			return DatabaseLookupMessage{}, ErrInvalidTunnelID
		}
		off += 4
	}
	if len(payload)-off < 2 {
		return DatabaseLookupMessage{}, wire.ErrShortBuffer
	}
	excludedCount := int(binary.BigEndian.Uint16(payload[off : off+2]))
	if excludedCount > MaxDatabaseLookupExcluded {
		return DatabaseLookupMessage{}, ErrPayloadTooLarge
	}
	off += 2
	excludedLen := excludedCount * foundation.HashLength
	if excludedLen > len(payload)-off {
		return DatabaseLookupMessage{}, wire.ErrShortBuffer
	}
	out.Excluded = payload[off : off+excludedLen]
	off += excludedLen

	// Either reply-encryption flag carries reply fields. An ECIES flag selects
	// the ECIES reply encoding, including when the legacy encryption flag is
	// also present.
	if out.Flags&(lookupEncrypted|lookupECIES) == 0 {
		if off != len(payload) {
			return DatabaseLookupMessage{}, ErrMalformed
		}
		return out, nil
	}
	if out.ReplyUsesECIESPublicKey() {
		if len(payload)-off < 32 {
			return DatabaseLookupMessage{}, wire.ErrShortBuffer
		}
		if len(payload)-off != 32 {
			return DatabaseLookupMessage{}, ErrMalformed
		}
		out.ReplyPublicKey = payload[off:]
		return out, nil
	}

	if len(payload)-off < 33 {
		return DatabaseLookupMessage{}, wire.ErrShortBuffer
	}
	out.ReplyKey = payload[off : off+32]
	off += 32
	tags := int(payload[off])
	off++

	tagLen := 32
	if out.Flags&lookupECIES != 0 {
		if tags != 1 {
			return DatabaseLookupMessage{}, ErrMalformed
		}
		tagLen = 8
	} else if tags == 0 || tags > MaxDatabaseReplyTags {
		return DatabaseLookupMessage{}, ErrMalformed
	}
	tagsLen := tags * tagLen
	if tagsLen > len(payload)-off {
		return DatabaseLookupMessage{}, wire.ErrShortBuffer
	}
	if tagsLen != len(payload)-off {
		return DatabaseLookupMessage{}, ErrMalformed
	}
	out.ReplyTags = payload[off : off+tagsLen]
	out.ReplyTagLen = uint8(tagLen)
	return out, nil
}

// DatabaseSearchReplyMessage is a validated, zero-copy search reply.
type DatabaseSearchReplyMessage struct {
	Key   foundation.Hash
	Peers []byte // exactly PeerCount() adjacent Hash values
	From  foundation.Hash
}

func (m DatabaseSearchReplyMessage) PeerCount() int { return len(m.Peers) / foundation.HashLength }

func ParseDatabaseSearchReply(payload []byte) (DatabaseSearchReplyMessage, error) {
	if len(payload) > MaxDatabaseSearchReplyPayload {
		return DatabaseSearchReplyMessage{}, ErrPayloadTooLarge
	}
	if len(payload) < 65 {
		return DatabaseSearchReplyMessage{}, wire.ErrShortBuffer
	}
	count := int(payload[32])
	expected := 32 + 1 + count*foundation.HashLength + 32
	if len(payload) != expected {
		return DatabaseSearchReplyMessage{}, ErrMalformed
	}
	var out DatabaseSearchReplyMessage
	copy(out.Key[:], payload[:32])
	out.Peers = payload[33 : 33+count*foundation.HashLength]
	copy(out.From[:], payload[len(payload)-32:])
	return out, nil
}

// DeliveryStatusMessage and TunnelTestMessage share the same fixed payload
// layout: a uint32 message ID and a uint64 timestamp.
type DeliveryStatusMessage struct {
	MessageID uint32
	Timestamp uint64
}

func ParseDeliveryStatus(payload []byte) (DeliveryStatusMessage, error) {
	if len(payload) != 12 {
		return DeliveryStatusMessage{}, ErrMalformed
	}
	return DeliveryStatusMessage{MessageID: binary.BigEndian.Uint32(payload[:4]), Timestamp: binary.BigEndian.Uint64(payload[4:12])}, nil
}

func ParseTunnelTest(payload []byte) (DeliveryStatusMessage, error) {
	return ParseDeliveryStatus(payload)
}

// GarlicMessage is the opaque encrypted body carried by a Garlic message.
type GarlicMessage struct{ Encrypted []byte }

func ParseGarlic(payload []byte) (GarlicMessage, error) {
	if len(payload) < 4 {
		return GarlicMessage{}, wire.ErrShortBuffer
	}
	n := uint64(binary.BigEndian.Uint32(payload[:4]))
	if n > uint64(I2PDMaxPayload-4) {
		return GarlicMessage{}, ErrPayloadTooLarge
	}
	if n != uint64(len(payload)-4) {
		return GarlicMessage{}, ErrMalformed
	}
	return GarlicMessage{Encrypted: payload[4:]}, nil
}

// TunnelDataMessage has exactly one 1024-byte encrypted tunnel block.
type TunnelDataMessage struct {
	TunnelID uint32
	Data     []byte
}

func ParseTunnelData(payload []byte) (TunnelDataMessage, error) {
	if len(payload) != TunnelDataMessageLen {
		return TunnelDataMessage{}, ErrMalformed
	}
	id := binary.BigEndian.Uint32(payload[:4])
	if id == 0 {
		return TunnelDataMessage{}, ErrInvalidTunnelID
	}
	return TunnelDataMessage{TunnelID: id, Data: payload[4:]}, nil
}

// TunnelGatewayMessage wraps exactly one complete standard I2NP frame.
type TunnelGatewayMessage struct {
	TunnelID uint32
	Embedded Message
}

func ParseTunnelGateway(payload []byte) (TunnelGatewayMessage, error) {
	if len(payload) < TunnelGatewayHeaderLen {
		return TunnelGatewayMessage{}, wire.ErrShortBuffer
	}
	id := binary.BigEndian.Uint32(payload[:4])
	if id == 0 {
		return TunnelGatewayMessage{}, ErrInvalidTunnelID
	}
	n := int(binary.BigEndian.Uint16(payload[4:6]))
	if n > MaxTunnelGatewayEmbedded {
		return TunnelGatewayMessage{}, ErrPayloadTooLarge
	}
	if n != len(payload)-TunnelGatewayHeaderLen {
		return TunnelGatewayMessage{}, ErrMalformed
	}
	embedded, used, err := ParseUnchecked(payload[TunnelGatewayHeaderLen:])
	if err != nil {
		return TunnelGatewayMessage{}, err
	}
	if used != n {
		return TunnelGatewayMessage{}, ErrMalformed
	}
	return TunnelGatewayMessage{TunnelID: id, Embedded: embedded}, nil
}

// DataMessage wraps arbitrary clove data under a fixed uint32 size prefix.
type DataMessage struct{ Data []byte }

func ParseData(payload []byte) (DataMessage, error) {
	if len(payload) < 4 {
		return DataMessage{}, wire.ErrShortBuffer
	}
	n := uint64(binary.BigEndian.Uint32(payload[:4]))
	if n > uint64(I2PDMaxPayload-4) {
		return DataMessage{}, ErrPayloadTooLarge
	}
	if n != uint64(len(payload)-4) {
		return DataMessage{}, ErrMalformed
	}
	return DataMessage{Data: payload[4:]}, nil
}

// BuildRecords is a validated fixed-size tunnel build record sequence.
type BuildRecords struct {
	Count     uint8
	RecordLen uint16
	Records   []byte
}

func ParseBuildRecords(kind MessageType, payload []byte) (BuildRecords, error) {
	count := 0
	recordLen := 0
	prefix := 0
	switch kind {
	case TunnelBuild, TunnelBuildReply:
		count, recordLen = FixedBuildRecords, BuildRecordLen
	case VariableTunnelBuild, VariableTunnelBuildReply:
		if len(payload) == 0 {
			return BuildRecords{}, wire.ErrShortBuffer
		}
		count, recordLen, prefix = int(payload[0]), BuildRecordLen, 1
	case ShortTunnelBuild, OutboundTunnelBuildReply:
		if len(payload) == 0 {
			return BuildRecords{}, wire.ErrShortBuffer
		}
		count, recordLen, prefix = int(payload[0]), ShortBuildRecordLen, 1
	default:
		return BuildRecords{}, ErrMalformed
	}
	if count < 1 || count > MaxVariableBuildRecords {
		return BuildRecords{}, ErrMalformed
	}
	expected := prefix + count*recordLen
	if len(payload) != expected {
		return BuildRecords{}, ErrMalformed
	}
	return BuildRecords{Count: uint8(count), RecordLen: uint16(recordLen), Records: payload[prefix:]}, nil
}

// ValidatePayload checks that the payload bytes conform to the structure of the given I2NP message type.
func ValidatePayload(kind MessageType, payload []byte) error {
	switch kind {
	case DatabaseStore:
		_, err := ParseDatabaseStore(payload)
		return err
	case DatabaseLookup:
		_, err := ParseDatabaseLookup(payload)
		return err
	case DatabaseSearchReply:
		_, err := ParseDatabaseSearchReply(payload)
		return err
	case DeliveryStatus:
		_, err := ParseDeliveryStatus(payload)
		return err
	case Garlic:
		_, err := ParseGarlic(payload)
		return err
	case TunnelData:
		_, err := ParseTunnelData(payload)
		return err
	case TunnelGateway:
		_, err := ParseTunnelGateway(payload)
		return err
	case Data:
		_, err := ParseData(payload)
		return err
	case TunnelBuild, TunnelBuildReply, VariableTunnelBuild, VariableTunnelBuildReply, ShortTunnelBuild, OutboundTunnelBuildReply:
		_, err := ParseBuildRecords(kind, payload)
		return err
	case TunnelTest:
		_, err := ParseTunnelTest(payload)
		return err
	default:
		return ErrMalformed
	}
}
