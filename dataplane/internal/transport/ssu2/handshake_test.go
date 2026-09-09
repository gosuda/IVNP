package ssu2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestSSU2HandshakeSeparatesSelectedNetworks(t *testing.T) {
	for _, networkID := range []uint8{0, 3, 255} {
		t.Run(fmt.Sprint(networkID), func(t *testing.T) {
			static, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			intro := make([]byte, 32)
			initiator, err := NewInitiator(static.PublicKey().Bytes(), intro, 1, 2, networkID)
			if err != nil {
				t.Fatal(err)
			}
			defer initiator.ReleaseSensitive()
			payload := handshakeDateTimePayload(t, 1)
			request, err := initiator.BuildSessionRequest(make([]byte, MaxIPv4PacketLen), payload, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PeekSessionRequest(request, intro, 2); err == nil {
				t.Fatal("public network accepted private-network request")
			}
			if _, _, _, err := ParseSessionRequest(bytes.Clone(request), static.Bytes(), intro, 2); err == nil {
				t.Fatal("public network authenticated private-network request")
			}
			responder, header, _, err := ParseSessionRequest(bytes.Clone(request), static.Bytes(), intro, networkID)
			if err != nil || header.NetworkID != networkID {
				t.Fatalf("matching request network = %d, %v", header.NetworkID, err)
			}
			defer responder.ReleaseSensitive()
			created, err := responder.BuildSessionCreated(make([]byte, MaxIPv4PacketLen), payload, 2)
			if err != nil {
				t.Fatal(err)
			}
			header, _, err = initiator.ParseSessionCreated(created)
			if err != nil || header.NetworkID != networkID {
				t.Fatalf("matching response network = %d, %v", header.NetworkID, err)
			}
			token, err := BuildTokenRequest(make([]byte, MaxIPv4PacketLen), intro, 1, 2, 3, payload, networkID)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ParseTokenRequest(bytes.Clone(token), intro, 2); err == nil {
				t.Fatal("public network accepted private-network token request")
			}
			header, _, err = ParseTokenRequest(token, intro, networkID)
			if err != nil || header.NetworkID != networkID {
				t.Fatalf("matching token network = %d, %v", header.NetworkID, err)
			}
		})
	}
}

func TestSSU2HandshakeAndDataCiphers(t *testing.T) {
	curve := ecdh.X25519()
	bobStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobIntro := make([]byte, 32)
	aliceIntro := make([]byte, 32)
	if _, err = rand.Read(bobIntro); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(aliceIntro); err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(bobStatic.PublicKey().Bytes(), bobIntro, 1, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	requestPayload := handshakeDateTimePayload(t, 1)
	request, err := initiator.BuildSessionRequest(make([]byte, MaxIPv4PacketLen), requestPayload, 11, 0)
	if err != nil {
		t.Fatal(err)
	}
	peeked, err := PeekSessionRequest(request, bobIntro, 2)
	if err != nil || peeked.DestinationID != 1 || peeked.SourceID != 2 || peeked.Token != 0 {
		t.Fatalf("PeekSessionRequest = %#v, %v", peeked, err)
	}
	responder, requestHeader, openedRequest, err := ParseSessionRequest(append([]byte(nil), request...), bobStatic.Bytes(), bobIntro, 2)
	if err != nil || requestHeader.Type != SessionRequest || !bytes.Equal(openedRequest, requestPayload) {
		t.Fatalf("ParseSessionRequest = %#v, %x, %v", requestHeader, openedRequest, err)
	}
	createdPayload := handshakeDateTimePayload(t, 2)
	created, err := responder.BuildSessionCreated(make([]byte, MaxIPv4PacketLen), createdPayload, 12)
	if err != nil {
		t.Fatal(err)
	}
	createdHeader, openedCreated, err := initiator.ParseSessionCreated(append([]byte(nil), created...))
	if err != nil || createdHeader.Type != SessionCreated || !bytes.Equal(openedCreated, createdPayload) {
		t.Fatalf("ParseSessionCreated = %#v, %x, %v", createdHeader, openedCreated, err)
	}
	confirmedPayload := confirmedRouterInfoPayload(t)
	confirmed, err := initiator.BuildSessionConfirmed(make([]byte, MaxIPv4PacketLen), aliceStatic.Bytes(), confirmedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if destinationID, err := PeekDestinationID(confirmed, bobIntro); err != nil || destinationID != 1 {
		t.Fatalf("PeekDestinationID = %d, %v", destinationID, err)
	}
	static, openedConfirmed, err := responder.ParseSessionConfirmed(append([]byte(nil), confirmed...))
	if err != nil || !bytes.Equal(static, aliceStatic.PublicKey().Bytes()) || !bytes.Equal(openedConfirmed, confirmedPayload) {
		t.Fatalf("ParseSessionConfirmed = %x, %x, %v", static, openedConfirmed, err)
	}

	aliceSend, aliceReceive, err := initiator.DataCiphers(aliceIntro)
	if err != nil {
		t.Fatal(err)
	}
	bobSend, bobReceive, err := responder.DataCiphers(aliceIntro)
	if err != nil {
		t.Fatal(err)
	}
	dataPayload := handshakeDateTimePayload(t, 3)
	packet, err := aliceSend.SealDataTo(make([]byte, MaxIPv4PacketLen), ShortHeader{DestinationID: 1, PacketNumber: 1, Type: Data}, dataPayload)
	if err != nil {
		t.Fatal(err)
	}
	header, opened, err := bobReceive.OpenDataTo(make([]byte, len(dataPayload)), append([]byte(nil), packet...))
	if err != nil || header.PacketNumber != 1 || !bytes.Equal(opened, dataPayload) {
		t.Fatalf("Bob data packet = %#v, %x, %v", header, opened, err)
	}
	packet, err = bobSend.SealDataTo(make([]byte, MaxIPv4PacketLen), ShortHeader{DestinationID: 2, PacketNumber: 1, Type: Data}, dataPayload)
	if err != nil {
		t.Fatal(err)
	}
	_, opened, err = aliceReceive.OpenDataTo(make([]byte, len(dataPayload)), append([]byte(nil), packet...))
	if err != nil || !bytes.Equal(opened, dataPayload) {
		t.Fatalf("Alice data packet = %x, %v", opened, err)
	}
	confirmed[len(confirmed)-1] ^= 1
	if _, _, err := responder.ParseSessionConfirmed(confirmed); err == nil {
		t.Fatal("reused/tampered SessionConfirmed was accepted")
	}
}

func TestSSU2SessionConfirmedFragmentReassembly(t *testing.T) {
	curve := ecdh.X25519()
	bobStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobIntro := make([]byte, 32)
	if _, err = rand.Read(bobIntro); err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(bobStatic.PublicKey().Bytes(), bobIntro, 1, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := initiator.BuildSessionRequest(make([]byte, MaxIPv4PacketLen), handshakeDateTimePayload(t, 1), 11, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, _, _, err := ParseSessionRequest(append([]byte(nil), request...), bobStatic.Bytes(), bobIntro, 2)
	if err != nil {
		t.Fatal(err)
	}
	created, err := responder.BuildSessionCreated(make([]byte, MaxIPv4PacketLen), handshakeDateTimePayload(t, 2), 12)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = initiator.ParseSessionCreated(append([]byte(nil), created...)); err != nil {
		t.Fatal(err)
	}

	routerInfo := make([]byte, 1450)
	routerInfo[1] = 1
	if _, err = rand.Read(routerInfo[2:]); err != nil {
		t.Fatal(err)
	}
	confirmedPayload, err := MarshalBlock(nil, BlockRouterInfo, routerInfo)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := initiator.BuildSessionConfirmedFragments(aliceStatic.Bytes(), confirmedPayload, MaxIPv4PacketLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 {
		t.Fatalf("fragment count = %d, want 2", len(packets))
	}

	reassembler := NewConfirmedReassembler(responder)
	if _, _, complete, err := reassembler.Add(append([]byte(nil), packets[1]...)); err != nil || complete {
		t.Fatalf("second fragment = complete %t, error %v", complete, err)
	}
	static, opened, complete, err := reassembler.Add(append([]byte(nil), packets[0]...))
	if err != nil || !complete || !bytes.Equal(static, aliceStatic.PublicKey().Bytes()) || !bytes.Equal(opened, confirmedPayload) {
		t.Fatalf("reassembled confirmed = static %x, payload length %d, complete %t, error %v", static, len(opened), complete, err)
	}
}

func handshakeDateTimePayload(t *testing.T, timestamp uint32) []byte {
	t.Helper()
	var dateTime [4]byte
	binary.BigEndian.PutUint32(dateTime[:], timestamp)
	payload, err := MarshalBlock(nil, BlockDateTime, dateTime[:])
	if err != nil {
		t.Fatal(err)
	}
	payload, err = MarshalBlock(payload, BlockPadding, nil)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func confirmedRouterInfoPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := MarshalBlock(nil, BlockRouterInfo, []byte{0, 1, 0})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
