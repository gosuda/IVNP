package ssu2

import (
	"encoding/binary"
	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/internal/wire"
)

// BuildTokenRequest creates an authenticated SSU2 TokenRequest. The payload
// must contain a DateTime block; sourceID is Alice's connection ID.
func BuildTokenRequest(dst, introKey []byte, destinationID, sourceID uint64, packetNumber uint32, payload []byte) ([]byte, error) {
	return buildOutOfSession(dst, introKey, LongHeader{
		DestinationID: destinationID,
		PacketNumber:  packetNumber,
		Type:          TokenRequest,
		Version:       Version,
		NetworkID:     NetworkID,
		SourceID:      sourceID,
	}, payload)
}

// ParseTokenRequest authenticates one caller-owned TokenRequest packet.
func ParseTokenRequest(packet, introKey []byte) (LongHeader, []byte, error) {
	return parseOutOfSession(packet, introKey, TokenRequest)
}

// ParseOutOfSession authenticates a caller-owned TokenRequest, Retry, Peer
// Test, or Hole Punch packet. The returned payload aliases packet and is valid
// only until the caller reuses it.
func ParseOutOfSession(packet, introKey []byte) (LongHeader, []byte, error) {
	return parseOutOfSession(packet, introKey, 0)
}

// BuildRetry creates an authenticated SSU2 Retry containing Bob's connection
// ID and the token bound by the receiver to the source UDP endpoint.
func BuildRetry(dst, introKey []byte, destinationID, sourceID, token uint64, packetNumber uint32, payload []byte) ([]byte, error) {
	return buildOutOfSession(dst, introKey, LongHeader{
		DestinationID: destinationID,
		PacketNumber:  packetNumber,
		Type:          Retry,
		Version:       Version,
		NetworkID:     NetworkID,
		SourceID:      sourceID,
		Token:         token,
	}, payload)
}

// ParseRetry authenticates one caller-owned Retry packet.
func ParseRetry(packet, introKey []byte) (LongHeader, []byte, error) {
	return parseOutOfSession(packet, introKey, Retry)
}

// BuildPeerTest creates an authenticated out-of-session SSU2 Peer Test packet
// for phases 5-7. The IDs must come from PeerTestConnectionIDs for the test
// block nonce.
func BuildPeerTest(dst, introKey []byte, destinationID, sourceID uint64, packetNumber uint32, payload []byte) ([]byte, error) {
	return buildOutOfSession(dst, introKey, LongHeader{
		DestinationID: destinationID,
		PacketNumber:  packetNumber,
		Type:          PeerTest,
		Version:       Version,
		NetworkID:     NetworkID,
		SourceID:      sourceID,
	}, payload)
}

// ParsePeerTest authenticates one caller-owned out-of-session Peer Test packet.
func ParsePeerTest(packet, introKey []byte) (LongHeader, []byte, error) {
	return parseOutOfSession(packet, introKey, PeerTest)
}

// BuildHolePunch creates an authenticated out-of-session SSU2 Hole Punch.
// The IDs must come from RelayConnectionIDs for the relay nonce. The header
// token is ignored by Alice; the Session Request token is in the Relay
// Response payload block.
func BuildHolePunch(dst, introKey []byte, destinationID, sourceID, token uint64, packetNumber uint32, payload []byte) ([]byte, error) {
	return buildOutOfSession(dst, introKey, LongHeader{
		DestinationID: destinationID,
		PacketNumber:  packetNumber,
		Type:          HolePunch,
		Version:       Version,
		NetworkID:     NetworkID,
		SourceID:      sourceID,
		Token:         token,
	}, payload)
}

// ParseHolePunch authenticates one caller-owned out-of-session Hole Punch.
func ParseHolePunch(packet, introKey []byte) (LongHeader, []byte, error) {
	return parseOutOfSession(packet, introKey, HolePunch)
}

func buildOutOfSession(dst, introKey []byte, header LongHeader, payload []byte) ([]byte, error) {
	if len(introKey) != cryptography.ChaChaKeySize || header.DestinationID == 0 || header.SourceID == 0 || SameConnectionID(header.DestinationID, header.SourceID) || !validOutOfSessionPayload(header.Type, payload) {
		return nil, ErrHandshake
	}
	switch header.Type {
	case TokenRequest, Retry, PeerTest, HolePunch:
	default:
		return nil, ErrPacketType
	}
	total := LongHeaderLen + len(payload) + PacketTagLen
	if total < MinPacketLen || total > MaxIPv4PacketLen {
		return nil, ErrPacketLength
	}
	if len(dst) < total {
		return nil, wire.ErrShortBuffer
	}
	if err := header.MarshalTo(dst[:LongHeaderLen]); err != nil {
		return nil, err
	}
	var nonce [cryptography.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(header.PacketNumber))
	aead, err := cryptography.NewChaCha20Poly1305(introKey)
	if err != nil {
		return nil, err
	}
	if _, err = aead.SealTo(dst[LongHeaderLen:total], nonce[:], payload, dst[:LongHeaderLen]); err != nil {
		return nil, err
	}
	if err = maskHeaderExtension(dst[16:LongHeaderLen], introKey); err != nil {
		return nil, err
	}
	if err = ProtectHeader(dst[:total], introKey, introKey, 0); err != nil {
		return nil, err
	}
	return dst[:total], nil
}

func parseOutOfSession(packet, introKey []byte, expected PacketType) (LongHeader, []byte, error) {
	if len(packet) < LongHeaderLen+PacketTagLen+8 || len(packet) > MaxIPv4PacketLen || len(introKey) != cryptography.ChaChaKeySize {
		return LongHeader{}, nil, ErrHandshake
	}
	if err := ProtectHeader(packet, introKey, introKey, 0); err != nil {
		return LongHeader{}, nil, err
	}
	if err := maskHeaderExtension(packet[16:LongHeaderLen], introKey); err != nil {
		return LongHeader{}, nil, err
	}
	header, err := ParseLongHeader(packet[:LongHeaderLen], NetworkID)
	parseOutOfSessionRejected := err != nil || (expected != 0 && header.Type != expected) || header.DestinationID == 0
	if !parseOutOfSessionRejected {
		parseOutOfSessionRejected = header.SourceID == 0
	}
	if parseOutOfSessionRejected {
		return LongHeader{}, nil, ErrHandshake
	}
	switch header.Type {
	case TokenRequest, Retry, PeerTest, HolePunch:
	default:
		return LongHeader{}, nil, ErrHandshake
	}
	var nonce [cryptography.ChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(header.PacketNumber))
	aead, err := cryptography.NewChaCha20Poly1305(introKey)
	if err != nil {
		return LongHeader{}, nil, err
	}
	plaintext := packet[LongHeaderLen : len(packet)-PacketTagLen]
	plain, err := aead.OpenTo(plaintext, nonce[:], packet[LongHeaderLen:], packet[:LongHeaderLen])
	if err != nil || !validOutOfSessionPayload(header.Type, plain) {
		return LongHeader{}, nil, ErrHandshake
	}
	return header, plain, nil
}

func validOutOfSessionPayload(kind PacketType, payload []byte) bool {
	switch kind {
	case PeerTest:
		iterator := NewBlockIterator(payload)
		var hasDateTime, hasPeerTest bool
		for {
			block, ok, err := iterator.Next()
			if err != nil {
				return false
			}
			if !ok {
				return hasDateTime && hasPeerTest
			}
			switch block.Type {
			case BlockDateTime:
				if hasDateTime {
					return false
				}
				hasDateTime = true
			case BlockPeerTest:
				if hasPeerTest {
					return false
				}
				if _, err = ParsePeerTestBlock(block.Data); err != nil {
					return false
				}
				hasPeerTest = true
			case BlockPadding:
			default:
				return false
			}
		}
	case HolePunch:
		return validHolePunchPayload(payload)
	default:
		return validHandshakePayload(payload)
	}
}

func validHolePunchPayload(payload []byte) bool {
	iterator := NewBlockIterator(payload)
	var dateTime, address, response bool
	for {
		block, ok, err := iterator.Next()
		if err != nil {
			return false
		}
		if !ok {
			return dateTime && address && response
		}
		switch block.Type {
		case BlockDateTime:
			if dateTime {
				return false
			}
			dateTime = true
		case BlockAddress:
			if address {
				return false
			}
			address = true
		case BlockRelayResponse:
			if response {
				return false
			}
			if _, err = ParseRelayResponseBlock(block.Data); err != nil {
				return false
			}
			response = true
		case BlockPadding:
		default:
			return false
		}
	}
}

func maskHeaderExtension(extension, introKey []byte) error {
	if len(extension) != 16 {
		return ErrHandshake
	}
	var nonce [cryptography.ChaChaNonceSize]byte
	stream, err := cryptography.NewChaCha20Stream(introKey, nonce[:])
	if err != nil {
		return err
	}
	stream.XORKeyStream(extension, extension)
	return nil
}
