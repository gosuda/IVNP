package garlicecies

import (
	"errors"
	"testing"
)

func TestReceiveTaggedNeverDecryptsUnknownNewSession(t *testing.T) {
	a, b, _, _, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	packet, err := a.EncryptUnbound(make([]byte, 2048), ratchetPublic(t, b), 4, clove("test"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReceiveTagged(make([]byte, 2048), make([]byte, 2048), packet, now); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("unknown tag entered New Session decryption: %v", err)
	}
	result, err := b.Receive(make([]byte, 2048), make([]byte, 2048), packet, now)
	if err != nil || !result.NewSession || string(result.Payload) != string(clove("test")) {
		t.Fatalf("New Session lost after tagged rejection: %#v, %v", result, err)
	}
}

func TestReceiveTaggedConsumesKnownTagWithoutCryptoFallback(t *testing.T) {
	a, b, aPeer, bPeer, now := ratchetPair(t)
	defer a.ReleaseSensitive()
	defer b.ReleaseSensitive()
	establishRatchet(t, a, b, aPeer, bPeer, now)
	packet, err := a.EncryptExisting(make([]byte, 512), bPeer, clove("test"), RatchetOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.ReceiveTagged(make([]byte, 512), nil, packet, now)
	if err != nil || result.NewSession {
		t.Fatalf("known tag rejected: %#v, %v", result, err)
	}
	if _, err := b.ReceiveTagged(make([]byte, 512), nil, packet, now); !errors.Is(err, ErrRatchetNoSession) {
		t.Fatalf("consumed tag reached unauthenticated decrypt path: %v", err)
	}
}
