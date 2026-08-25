package ssu2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"slices"
	"testing"
)

func TestSSU2SessionConfirmedFragmentsReassembleOutOfOrder(t *testing.T) {
	curve := ecdh.X25519()
	bobStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intro := make([]byte, 32)
	if _, err = rand.Read(intro); err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(bobStatic.PublicKey().Bytes(), intro, 11, 12)
	if err != nil {
		t.Fatal(err)
	}
	request, err := initiator.BuildSessionRequest(make([]byte, MaxIPv4PacketLen), handshakeDateTimePayload(t, 1), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	responder, _, _, err := ParseSessionRequest(append([]byte(nil), request...), bobStatic.Bytes(), intro)
	if err != nil {
		t.Fatal(err)
	}
	created, err := responder.BuildSessionCreated(make([]byte, MaxIPv4PacketLen), handshakeDateTimePayload(t, 2), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = initiator.ParseSessionCreated(append([]byte(nil), created...)); err != nil {
		t.Fatal(err)
	}

	routerInfoData := make([]byte, 1400)
	routerInfoData[0], routerInfoData[1] = 0, 1
	if _, err = rand.Read(routerInfoData[2:]); err != nil {
		t.Fatal(err)
	}
	payload, err := MarshalBlock(nil, BlockRouterInfo, routerInfoData)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := initiator.BuildSessionConfirmedFragments(aliceStatic.Bytes(), payload, 900)
	if err != nil || len(packets) < 2 {
		t.Fatalf("BuildSessionConfirmedFragments = %d packets, %v", len(packets), err)
	}
	reassembly := NewConfirmedReassembler(responder)
	for index, packet := range slices.Backward(packets) {
		static, opened, complete, err := reassembly.Add(append([]byte(nil), packet...))
		if err != nil {
			t.Fatalf("fragment %d: %v", index, err)
		}
		if index != 0 && complete {
			t.Fatal("reassembly completed before fragment zero arrived")
		}
		if index == 0 {
			if !complete || !bytes.Equal(static, aliceStatic.PublicKey().Bytes()) || !bytes.Equal(opened, payload) {
				t.Fatalf("reassembly = complete %t static %x payload %d", complete, static, len(opened))
			}
		}
	}
}
