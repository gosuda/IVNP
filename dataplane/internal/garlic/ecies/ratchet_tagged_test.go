package garlicecies

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestRatchetTagOnlyReceiveDoesNotAcceptNewSession(t *testing.T) {
	sender, recipient, _, _, now := ratchetPair(t)
	defer sender.ReleaseSensitive()
	defer recipient.ReleaseSensitive()

	packet, err := sender.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, recipient), uint16(foundation.CryptoX25519), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipient.ReceiveTagged(make([]byte, 2048), nil, packet, now); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("unregistered tag result: %v", err)
	}
	result, err := recipient.Receive(make([]byte, 2048), nil, packet, now)
	if err != nil || !result.NewSession {
		t.Fatalf("ordinary New Session result: %#v, %v", result, err)
	}
}
