package ssu2

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRelayIntroductionBlocksRoundTrip(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.44:4100")
	request := RelayRequest{
		Nonce:     0x01020304,
		RelayTag:  0x05060708,
		Timestamp: 0x090a0b0c,
		Endpoint:  endpoint,
		Signature: []byte("alice-signature"),
	}
	var bob, charlie, alice [32]byte
	for index := range bob {
		bob[index] = byte(index)
		charlie[index] = byte(32 + index)
		alice[index] = byte(64 + index)
	}
	signed, err := RelayRequestSignatureInput(nil, bob[:], charlie[:], RelayRequest{
		Nonce:     request.Nonce,
		RelayTag:  request.RelayTag,
		Timestamp: request.Timestamp,
		Endpoint:  request.Endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed[:16], []byte("RelayRequestData")) || !bytes.Equal(signed[16:48], bob[:]) || !bytes.Equal(signed[48:80], charlie[:]) {
		t.Fatalf("Relay Request signature input prefix = %x", signed[:80])
	}
	if got := binary.BigEndian.Uint32(signed[80:84]); got != request.Nonce {
		t.Fatalf("Relay Request signature nonce = %x", got)
	}

	block, err := MarshalRelayRequestBlock(nil, request)
	if err != nil {
		t.Fatal(err)
	}
	iterator := NewBlockIterator(block)
	parsedBlock, ok, err := iterator.Next()
	if err != nil || !ok || parsedBlock.Type != BlockRelayRequest {
		t.Fatalf("Relay Request block = %#v, %t, %v", parsedBlock, ok, err)
	}
	parsedRequest, err := ParseRelayRequestBlock(parsedBlock.Data)
	if err != nil || parsedRequest.Nonce != request.Nonce || parsedRequest.RelayTag != request.RelayTag || parsedRequest.Timestamp != request.Timestamp || parsedRequest.Endpoint != endpoint || !bytes.Equal(parsedRequest.Signature, request.Signature) {
		t.Fatalf("parsed Relay Request = %#v, %v", parsedRequest, err)
	}

	introBlock, err := MarshalRelayIntroBlock(nil, RelayIntro{AliceHash: alice, Request: request})
	if err != nil {
		t.Fatal(err)
	}
	iterator = NewBlockIterator(introBlock)
	parsedBlock, ok, err = iterator.Next()
	if err != nil || !ok || parsedBlock.Type != BlockRelayIntro {
		t.Fatalf("Relay Intro block = %#v, %t, %v", parsedBlock, ok, err)
	}
	intro, err := ParseRelayIntroBlock(parsedBlock.Data)
	if err != nil || intro.AliceHash != alice || intro.Request.Nonce != request.Nonce || !bytes.Equal(intro.Request.Signature, request.Signature) {
		t.Fatalf("parsed Relay Intro = %#v, %v", intro, err)
	}

	response := RelayResponse{
		Nonce:     request.Nonce,
		Timestamp: request.Timestamp + 1,
		Endpoint:  netip.MustParseAddrPort("[2001:db8::1]:4200"),
		Signature: []byte("charlie-signature"),
		Token:     0x1122334455667788,
		HasToken:  true,
	}
	responseBlock, err := MarshalRelayResponseBlock(nil, response)
	if err != nil {
		t.Fatal(err)
	}
	iterator = NewBlockIterator(responseBlock)
	parsedBlock, ok, err = iterator.Next()
	if err != nil || !ok || parsedBlock.Type != BlockRelayResponse {
		t.Fatalf("Relay Response block = %#v, %t, %v", parsedBlock, ok, err)
	}
	parsedResponse, err := ParseRelayResponseBlock(parsedBlock.Data)
	if err != nil || parsedResponse.Nonce != response.Nonce || parsedResponse.Endpoint != response.Endpoint || parsedResponse.Token != response.Token || !parsedResponse.HasToken || !bytes.Equal(parsedResponse.Signature, response.Signature) {
		t.Fatalf("parsed Relay Response = %#v, %v", parsedResponse, err)
	}
	responseSigned, err := RelayResponseSignatureInput(nil, bob[:], RelayResponse{
		Nonce:     response.Nonce,
		Timestamp: response.Timestamp,
		Endpoint:  response.Endpoint,
		Token:     response.Token,
		HasToken:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseSigned[:16], []byte("RelayAgreementOK")) || !bytes.Equal(responseSigned[16:48], bob[:]) {
		t.Fatalf("Relay Response signature input prefix = %x", responseSigned[:48])
	}

	destinationID, sourceID := RelayConnectionIDs(request.Nonce)
	if destinationID != 0x0102030401020304 || sourceID != ^destinationID {
		t.Fatalf("Relay connection IDs = %x, %x", destinationID, sourceID)
	}
}

func TestRelayIntroductionBlocksRejectAmbiguousResponses(t *testing.T) {
	if _, err := MarshalRelayRequestBlock(nil, RelayRequest{Signature: []byte("signature")}); err == nil {
		t.Fatal("Relay Request accepted a missing endpoint")
	}
	response := RelayResponse{
		Nonce:     1,
		Timestamp: 2,
		Endpoint:  netip.MustParseAddrPort("192.0.2.1:3"),
		Signature: []byte("signature"),
		Token:     4,
		HasToken:  true,
	}
	block, err := MarshalRelayResponseBlock(nil, response)
	if err != nil {
		t.Fatal(err)
	}
	block[4] = 1 // non-accept responses must not carry an endpoint or token
	iterator := NewBlockIterator(block)
	if _, _, err = iterator.Next(); err == nil {
		t.Fatal("Relay Response accepted a non-accept endpoint")
	}
}

func TestHolePunchEnvelopeRequiresIntroductionPayload(t *testing.T) {
	dateTime := make([]byte, 4)
	binary.BigEndian.PutUint32(dateTime, 123)
	payload, err := MarshalBlock(nil, BlockDateTime, dateTime)
	if err != nil {
		t.Fatal(err)
	}
	address := []byte{0x10, 0x04, 192, 0, 2, 1}
	payload, err = MarshalBlock(payload, BlockAddress, address)
	if err != nil {
		t.Fatal(err)
	}
	response, err := MarshalRelayResponseBlock(nil, RelayResponse{
		Nonce:     7,
		Timestamp: 124,
		Endpoint:  netip.MustParseAddrPort("192.0.2.2:5000"),
		Signature: []byte("signature"),
		Token:     8,
		HasToken:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, response...)
	destinationID, sourceID := RelayConnectionIDs(7)
	packet, err := BuildHolePunch(make([]byte, MaxIPv4PacketLen), make([]byte, 32), destinationID, sourceID, 9, 10, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, opened, err := ParseHolePunch(append([]byte(nil), packet...), make([]byte, 32))
	if err != nil || header.DestinationID != destinationID || header.SourceID != sourceID || header.Token != 9 || !bytes.Equal(opened, payload) {
		t.Fatalf("Hole Punch = %#v, %x, %v", header, opened, err)
	}
	if _, err = BuildHolePunch(make([]byte, MaxIPv4PacketLen), make([]byte, 32), destinationID, sourceID, 0, 10, response); err == nil {
		t.Fatal("Hole Punch accepted a payload without DateTime and Address blocks")
	}
}
