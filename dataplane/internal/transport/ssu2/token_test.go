package ssu2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSSU2TokenRequestAndRetry(t *testing.T) {
	intro := make([]byte, 32)
	if _, err := rand.Read(intro); err != nil {
		t.Fatal(err)
	}
	payload := handshakeDateTimePayload(t, 123)

	request, err := BuildTokenRequest(make([]byte, MaxIPv4PacketLen), intro, 11, 22, 33, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, opened, err := ParseTokenRequest(append([]byte(nil), request...), intro)
	sSU2TokenRequestAndRetryRejected := err != nil || header.DestinationID != 11 || header.SourceID != 22 || header.PacketNumber != 33 || header.Token != 0
	if !sSU2TokenRequestAndRetryRejected {
		sSU2TokenRequestAndRetryRejected = !bytes.Equal(opened, payload)
	}
	if sSU2TokenRequestAndRetryRejected {
		t.Fatalf("TokenRequest = %#v, %x, %v", header, opened, err)
	}

	retry, err := BuildRetry(make([]byte, MaxIPv4PacketLen), intro, 22, 11, 44, 55, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, opened, err = ParseRetry(append([]byte(nil), retry...), intro)
	sSU2TokenRequestAndRetryRejected = err != nil || header.DestinationID != 22 || header.SourceID != 11 || header.PacketNumber != 55 || header.Token != 44
	if !sSU2TokenRequestAndRetryRejected {
		sSU2TokenRequestAndRetryRejected = !bytes.Equal(opened, payload)
	}
	if sSU2TokenRequestAndRetryRejected {
		t.Fatalf("Retry = %#v, %x, %v", header, opened, err)
	}

	tampered := append([]byte(nil), retry...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := ParseRetry(tampered, intro); err == nil {
		t.Fatal("tampered Retry was accepted")
	}
}

// Java I2P ChaCha20 and i2pd Crypto.cpp both start raw SSU2 header
// protection at block counter 1. An internal build/parse round trip cannot
// detect using counter 0 on both sides, so retain the complete wire vector.
func TestTokenRequestMatchesJavaI2PDHeaderCounter(t *testing.T) {
	intro := make([]byte, 32)
	for index := range intro {
		intro[index] = byte(index)
	}
	payload := []byte{BlockDateTime, 0, 4, 0x1f, 0x20, 0x21, 0x22, BlockPadding, 0, 1, 0x42}
	packet, err := BuildTokenRequest(make([]byte, MaxIPv4PacketLen), intro, 0x0102030405060708, 0x1112131415161718, 0x21222324, payload)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("d6516c12ef393bb82cc63ce16b4c178109aa5125b8f0b1c913615c61af434e2752213165ef3cf263d323f829de8c7f136a0bbccc54fb51994aab5e")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, expected) {
		t.Fatalf("TokenRequest wire = %x, want %x", packet, expected)
	}
}

func TestSSUOutOfSessionRejectsShortPackets(t *testing.T) {
	intro := make([]byte, 32)
	payload := handshakeDateTimePayload(t, 1)
	request, err := BuildTokenRequest(make([]byte, MaxIPv4PacketLen), intro, 11, 22, 33, payload)
	if err != nil {
		t.Fatal(err)
	}
	for size := MinPacketLen; size < LongHeaderLen+PacketTagLen+8; size++ {
		for _, parse := range []func([]byte, []byte) (LongHeader, []byte, error){ParseTokenRequest, ParseRetry} {
			if _, _, err := parse(append([]byte(nil), request[:size]...), intro); !errors.Is(err, ErrHandshake) {
				t.Errorf("length %d error = %v, want %v", size, err, ErrHandshake)
			}
		}
	}
}
