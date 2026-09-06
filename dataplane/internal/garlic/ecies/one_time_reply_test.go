package garlicecies

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/foundation"
)

func TestOneTimeReplyExistingSessionRoundTripAndPadding(t *testing.T) {
	key, tag := testShortBuildReplyKey(), testShortBuildReplyTag()
	reply := testShortBuildReply()
	padding := []byte{1, 2, 3, 4}
	sealed := make([]byte, 8+13+len(reply.Payload)+len(padding)+3+cryptography.ChaChaTagSize)
	sealed, err := SealOneTimeReplyExistingSession(sealed, key, tag, reply, padding)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed[:8]) != string(tag[:]) {
		t.Fatal("clear existing-session tag was not preserved")
	}
	plaintext := make([]byte, len(sealed)-8-cryptography.ChaChaTagSize)
	opened, err := OpenOneTimeReplyExistingSession(plaintext, key, tag, sealed)
	if err != nil {
		t.Fatal(err)
	}
	expiration, ok := foundation.I2NPEncodeTransportExpiration(reply.Header.Expiration)
	if !ok {
		t.Fatal("test expiration is not encodable")
	}
	wantHeader := reply.Header
	wantHeader.Expiration = foundation.I2NPDecodeTransportExpiration(expiration)
	if opened.Header != wantHeader || string(opened.Payload) != string(reply.Payload) {
		t.Fatalf("opened reply = %#v, want header %#v payload %x", opened, wantHeader, reply.Payload)
	}
	if len(opened.Payload) != 0 && &opened.Payload[0] != &plaintext[13] {
		t.Fatal("opened payload does not alias caller storage")
	}
}

func TestOneTimeReplyExistingSessionRejectsTamperingAndOversizedPadding(t *testing.T) {
	key, tag := testShortBuildReplyKey(), testShortBuildReplyTag()
	reply := testShortBuildReply()
	sealed := make([]byte, 8+13+len(reply.Payload)+cryptography.ChaChaTagSize)
	sealed, err := SealOneTimeReplyExistingSession(sealed, key, tag, reply, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err = OpenOneTimeReplyExistingSession(make([]byte, len(sealed)-8-cryptography.ChaChaTagSize), key, tag, sealed); !errors.Is(err, ErrOneTimeReplyExistingSession) {
		t.Fatalf("tampered reply error = %v", err)
	}
	tooLargePadding := make([]byte, uint16Max+1)
	if _, err = SealOneTimeReplyExistingSession(make([]byte, maxOneTimeReplyPlaintext+8+cryptography.ChaChaTagSize), key, tag, reply, tooLargePadding); !errors.Is(err, ErrOneTimeReplyExistingSession) {
		t.Fatalf("oversized padding error = %v", err)
	}
}

func testShortBuildReply() foundation.I2NPMessage {
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 9, Expiration: 10_000},
		Payload: append([]byte{1}, make([]byte, foundation.I2NPShortBuildRecordLen)...),
	}
}

func testShortBuildReplyKey() (key [cryptography.ChaChaKeySize]byte) {
	for index := range key {
		key[index] = byte(index + 1)
	}
	return key
}

func testShortBuildReplyTag() (tag [oneTimeReplyTagLen]byte) {
	for index := range tag {
		tag[index] = byte(index + 10)
	}
	return tag
}
