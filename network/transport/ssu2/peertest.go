package ssu2

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrPeerTest = errors.New("ssu2: invalid peer test block")

// PeerTestBlock is the authenticated content of an SSU2 Peer Test block. The
// Signature field aliases the parsed packet; callers retaining it must copy.
type PeerTestBlock struct {
	Message   uint8
	Code      uint8
	Nonce     uint32
	Timestamp uint32
	Address   netip.AddrPort
	Hash      [32]byte
	HasHash   bool
	Signature []byte
}

// PeerTestConnectionIDs derives the mandatory out-of-session IDs for Peer
// Test messages 5-7 from the test nonce.
func PeerTestConnectionIDs(nonce uint32) (destinationID, sourceID uint64) {
	destinationID = uint64(nonce)<<32 | uint64(nonce)
	return destinationID, ^destinationID
}

var peerTestPrologue = "PeerTestValidate"

// PeerTestSignatureInput appends the exact byte sequence signed by Alice or
// Charlie for Peer Test messages 1-4. bobHash must be the 32-byte introducer
// hash; aliceHash is required for messages 3 and 4.
func PeerTestSignatureInput(dst, bobHash, aliceHash []byte, test PeerTestBlock) ([]byte, error) {
	if test.Message < 1 || test.Message > 4 || !validPeerTestCode(test.Message, test.Code) || len(bobHash) != 32 {
		return nil, ErrPeerTest
	}
	if (test.Message == 3 || test.Message == 4) && len(aliceHash) != 32 {
		return nil, ErrPeerTest
	}
	endpoint, err := appendRelayEndpoint(nil, test.Address)
	if err != nil {
		return nil, ErrPeerTest
	}
	dst = append(dst, peerTestPrologue...)
	dst = append(dst, bobHash...)
	if test.Message == 3 || test.Message == 4 {
		dst = append(dst, aliceHash...)
	}
	var fixed [10]byte
	fixed[0] = Version
	binary.BigEndian.PutUint32(fixed[1:5], test.Nonce)
	binary.BigEndian.PutUint32(fixed[5:9], test.Timestamp)
	fixed[9] = byte(len(endpoint))
	dst = append(dst, fixed[:]...)
	return append(dst, endpoint...), nil
}

// MarshalPeerTestBlock appends a strict SSU2 Peer Test block. Signatures for
// phases 1-4 are caller-supplied and must already cover the spec prologue and
// peer hashes; phases 5-7 may omit a signature.
func MarshalPeerTestBlock(dst []byte, test PeerTestBlock) ([]byte, error) {
	if test.Message < 1 || test.Message > 7 || !validPeerTestCode(test.Message, test.Code) || !validRelayEndpoint(test.Address) {
		return nil, ErrPeerTest
	}
	if test.Message <= 4 && len(test.Signature) == 0 {
		return nil, ErrPeerTest
	}
	ip := test.Address.Addr()
	var address []byte
	if ip.Is4() {
		v4 := ip.As4()
		address = v4[:]
	} else {
		v6 := ip.As16()
		address = v6[:]
	}
	dataLen := 3 + 1 + 4 + 4 + 1 + 2 + len(address) + len(test.Signature)
	if test.Message == 2 || test.Message == 4 {
		if !test.HasHash {
			return nil, ErrPeerTest
		}
		dataLen += len(test.Hash)
	} else if test.HasHash {
		return nil, ErrPeerTest
	}
	data := make([]byte, dataLen)
	data[0], data[1] = test.Message, test.Code
	offset := 3
	if test.HasHash {
		copy(data[offset:], test.Hash[:])
		offset += len(test.Hash)
	}
	data[offset] = Version
	binary.BigEndian.PutUint32(data[offset+1:offset+5], test.Nonce)
	binary.BigEndian.PutUint32(data[offset+5:offset+9], test.Timestamp)
	data[offset+9] = byte(2 + len(address))
	binary.BigEndian.PutUint16(data[offset+10:offset+12], test.Address.Port())
	copy(data[offset+12:], address)
	offset += 12 + len(address)
	copy(data[offset:], test.Signature)
	return MarshalBlock(dst, BlockPeerTest, data)
}

// ParsePeerTestBlock parses one SSU2 Peer Test block's data body.
func ParsePeerTestBlock(data []byte) (PeerTestBlock, error) {
	if len(data) < 15 || data[0] < 1 || data[0] > 7 || data[2] != 0 || !validPeerTestCode(data[0], data[1]) {
		return PeerTestBlock{}, ErrPeerTest
	}
	result := PeerTestBlock{Message: data[0], Code: data[1]}
	offset := 3
	if result.Message == 2 || result.Message == 4 {
		if len(data) < offset+32+12 {
			return PeerTestBlock{}, ErrPeerTest
		}
		copy(result.Hash[:], data[offset:offset+32])
		result.HasHash = true
		offset += 32
	}
	if len(data) < offset+12 || data[offset] != Version {
		return PeerTestBlock{}, ErrPeerTest
	}
	result.Nonce = binary.BigEndian.Uint32(data[offset+1 : offset+5])
	result.Timestamp = binary.BigEndian.Uint32(data[offset+5 : offset+9])
	addressSize := int(data[offset+9])
	if (addressSize != 6 && addressSize != 18) || len(data) < offset+10+addressSize {
		return PeerTestBlock{}, ErrPeerTest
	}
	port := binary.BigEndian.Uint16(data[offset+10 : offset+12])
	address, ok := netip.AddrFromSlice(data[offset+12 : offset+10+addressSize])
	if !ok || port == 0 || address.IsUnspecified() || address.Is4In6() {
		return PeerTestBlock{}, ErrPeerTest
	}
	result.Address = netip.AddrPortFrom(address, port)
	offset += 10 + addressSize
	result.Signature = data[offset:]
	if result.Message <= 4 && len(result.Signature) == 0 {
		return PeerTestBlock{}, ErrPeerTest
	}
	return result, nil
}

func validPeerTestCode(message, code uint8) bool {
	return code == 0 || message == 3 || message == 4
}
