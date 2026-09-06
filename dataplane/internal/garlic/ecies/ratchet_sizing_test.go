package garlicecies

import (
	"bytes"
	"testing"
)

func TestRatchetBufferBoundsCoverHandshakeAndDHRotation(t *testing.T) {
	for _, cryptoType := range []uint16{4, 6, 7} {
		for _, bound := range []bool{false, true} {
			a, receiver, _, peer, now := ratchetPair(t)
			t.Cleanup(a.ReleaseSensitive)
			t.Cleanup(receiver.ReleaseSensitive)
			payload := clove("sized handshake")
			packetLen, plainLen, err := RatchetEncryptBufferSizes(len(payload), cryptoType)
			if err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, packetLen)
			if bound {
				packet, err = a.EncryptWithScratch(packet, make([]byte, plainLen), peer, ratchetPublic(t, receiver), cryptoType, payload, now)
			} else {
				packet, err = a.EncryptUnbound(packet, ratchetPublic(t, receiver), cryptoType, payload, now)
			}
			if err != nil {
				t.Fatalf("type %d bound %t: %v", cryptoType, bound, err)
			}
			result, err := receiver.Receive(make([]byte, plainLen), make([]byte, 4096), packet, now)
			if result.Candidate != nil {
				result.Candidate.Discard()
			}
			if err != nil || !bytes.Equal(result.Payload, payload) {
				t.Fatalf("type %d bound %t roundtrip: %v", cryptoType, bound, err)
			}
		}
	}
	a, receiver, aPeer, peer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer receiver.ReleaseSensitive()
	establishRatchet(t, a, receiver, aPeer, peer, now)
	payload := clove("DH rotation payload")
	packetLen, plainLen, err := RatchetEncryptBufferSizes(len(payload), 4)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := a.EncryptExistingWithScratch(make([]byte, packetLen), make([]byte, plainLen), peer, payload, RatchetOptions{RequestDH: true}, now+1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := receiver.Receive(make([]byte, plainLen), make([]byte, 2048), packet, now+1)
	if err != nil || !bytes.HasPrefix(result.Payload, payload) {
		t.Fatalf("sized DH rotation receive = %v, %v", result.Payload, err)
	}
}
