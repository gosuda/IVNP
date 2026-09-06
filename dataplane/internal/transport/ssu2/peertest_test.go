package ssu2

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPeerTestBlockRoundTrip(t *testing.T) {
	var hash [32]byte
	for index := range hash {
		hash[index] = byte(index)
	}
	original := PeerTestBlock{
		Message:   4,
		Code:      0,
		Nonce:     0x01020304,
		Timestamp: 123,
		Address:   netip.MustParseAddrPort("192.0.2.1:4567"),
		Hash:      hash,
		HasHash:   true,
		Signature: []byte("signature"),
	}
	payload, err := MarshalPeerTestBlock(nil, original)
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != 10 {
		t.Fatalf("PeerTest block type = %d, want 10", payload[0])
	}
	iterator := NewBlockIterator(payload)
	block, ok, err := iterator.Next()
	if err != nil || !ok || block.Type != BlockPeerTest {
		t.Fatalf("PeerTest block = %#v, %t, %v", block, ok, err)
	}
	parsed, err := ParsePeerTestBlock(block.Data)
	peerTestBlockRoundTripRejected := err != nil || parsed.Message != original.Message || parsed.Code != original.Code || parsed.Nonce != original.Nonce || parsed.Timestamp != original.Timestamp || parsed.Address != original.Address || !parsed.HasHash || parsed.Hash != hash
	if !peerTestBlockRoundTripRejected {
		peerTestBlockRoundTripRejected = !bytes.Equal(parsed.Signature, original.Signature)
	}
	if peerTestBlockRoundTripRejected {
		t.Fatalf("ParsePeerTestBlock = %#v, %v", parsed, err)
	}
	destinationID, sourceID := PeerTestConnectionIDs(original.Nonce)
	if destinationID != 0x0102030401020304 || sourceID != ^destinationID {
		t.Fatalf("peer test IDs = %x, %x", destinationID, sourceID)
	}
}

func TestOutOfSessionPeerTestRoundTrip(t *testing.T) {
	block, err := MarshalPeerTestBlock(nil, PeerTestBlock{
		Message:   5,
		Nonce:     7,
		Timestamp: 123,
		Address:   netip.MustParseAddrPort("192.0.2.1:4567"),
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationID, sourceID := PeerTestConnectionIDs(7)
	if _, err = BuildPeerTest(make([]byte, MaxIPv4PacketLen), make([]byte, 32), destinationID, sourceID, 9, block); err == nil {
		t.Fatal("out-of-session PeerTest accepted a missing DateTime block")
	}
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], 123)
	payload, err := MarshalBlock(nil, BlockDateTime, timestamp[:])
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, block...)
	destinationID, sourceID = PeerTestConnectionIDs(7)
	packet, err := BuildPeerTest(make([]byte, MaxIPv4PacketLen), make([]byte, 32), destinationID, sourceID, 9, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, opened, err := ParsePeerTest(append([]byte(nil), packet...), make([]byte, 32))
	if err != nil || header.DestinationID != destinationID || header.SourceID != sourceID || !bytes.Equal(opened, payload) {
		t.Fatalf("out-of-session PeerTest = %#v, %x, %v", header, opened, err)
	}
}

func TestPeerTestBlockRejectsMissingSignedData(t *testing.T) {
	if _, err := MarshalPeerTestBlock(nil, PeerTestBlock{Message: 1, Address: netip.MustParseAddrPort("192.0.2.1:1")}); err == nil {
		t.Fatal("unsigned in-session peer test was accepted")
	}
	if _, err := ParsePeerTestBlock([]byte{5, 0, 1}); err == nil {
		t.Fatal("reserved peer test flag was accepted")
	}
}
