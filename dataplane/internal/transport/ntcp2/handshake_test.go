package ntcp2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"testing"
)

func TestSessionRequestRoundTrip(t *testing.T) {
	curve := ecdh.X25519()
	staticPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remoteHash := bytes.Repeat([]byte{1}, 32)
	remoteIV := bytes.Repeat([]byte{2}, 16)
	initiator, err := NewInitiator(staticPrivate.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	padding := bytes.Repeat([]byte{3}, 32)
	options := SessionRequestOptions{NetworkID: 2, Version: 2, PaddingLength: uint16(len(padding)), Message3Part2Length: 32, Timestamp: 123}
	packet, err := initiator.BuildSessionRequest(make([]byte, SessionRequestCiphertextLen+len(padding)), remoteHash, remoteIV, padding, options, false)
	if err != nil {
		t.Fatal(err)
	}
	responder, got, err := ParseSessionRequest(packet, staticPrivate.Bytes(), remoteHash, remoteIV, 2, false)
	if err != nil || got != options {
		t.Fatalf("ParseSessionRequest() = %#v, %v", got, err)
	}
	if initiator.state.Hash() != responder.state.Hash() || initiator.state.ChainingKey() != responder.state.ChainingKey() {
		t.Fatal("initiator and responder state diverged")
	}
	createdPadding := bytes.Repeat([]byte{4}, 16)
	createdOptions := SessionCreatedOptions{PaddingLength: uint16(len(createdPadding)), Timestamp: 456}
	created, err := responder.BuildSessionCreated(make([]byte, SessionRequestCiphertextLen+len(createdPadding)), remoteHash, createdPadding, createdOptions)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := initiator.ParseSessionCreated(created, remoteHash); err != nil || got != createdOptions {
		t.Fatalf("ParseSessionCreated() = %#v, %v", got, err)
	}
	if initiator.state.Hash() != responder.state.Hash() || initiator.state.ChainingKey() != responder.state.ChainingKey() {
		t.Fatal("initiator and responder state diverged after SessionCreated")
	}
	aliceStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	confirmedPayload := bytes.Repeat([]byte{5}, 16)
	confirmed, err := initiator.BuildSessionConfirmed(make([]byte, 64+len(confirmedPayload)), aliceStatic.Bytes(), confirmedPayload)
	if err != nil {
		t.Fatal(err)
	}
	staticKey, receivedPayload, err := responder.ParseSessionConfirmed(confirmed)
	if err != nil || !bytes.Equal(staticKey, aliceStatic.PublicKey().Bytes()) || !bytes.Equal(receivedPayload, confirmedPayload) {
		t.Fatalf("ParseSessionConfirmed() = %x / %x / %v", staticKey, receivedPayload, err)
	}
	if initiator.state.Hash() != responder.state.Hash() || initiator.state.ChainingKey() != responder.state.ChainingKey() {
		t.Fatal("initiator and responder state diverged after SessionConfirmed")
	}
	packet[40] ^= 1
	if _, _, err := ParseSessionRequest(packet, staticPrivate.Bytes(), remoteHash, remoteIV, 2, false); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestDataSessionsDeriveOppositeDirections(t *testing.T) {
	curve := ecdh.X25519()
	bobStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewInitiator(bobStatic.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	options := SessionRequestOptions{NetworkID: 2, Version: 2, Message3Part2Length: 16}
	request, err := alice.BuildSessionRequest(make([]byte, SessionRequestCiphertextLen), make([]byte, 32), make([]byte, 16), nil, options, false)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := ParseSessionRequest(request, bobStatic.Bytes(), make([]byte, 32), make([]byte, 16), 2, false)
	if err != nil {
		t.Fatal(err)
	}
	created, err := bob.BuildSessionCreated(make([]byte, SessionRequestCiphertextLen), make([]byte, 32), nil, SessionCreatedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.ParseSessionCreated(created, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	confirmed, err := alice.BuildSessionConfirmed(make([]byte, 64), aliceStatic.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = bob.ParseSessionConfirmed(confirmed); err != nil {
		t.Fatal(err)
	}

	left, right := net.Pipe()
	aliceSession, err := alice.NewDataSession(left)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := bob.NewDataSession(right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = aliceSession.Close()
		_ = bobSession.Close()
	})

	received := make(chan []byte, 1)
	errs := make(chan error, 2)
	go func() {
		plain, err := bobSession.Read(make([]byte, 32))
		if err != nil {
			errs <- err
			return
		}
		received <- append([]byte(nil), plain...)
	}()
	if err := aliceSession.Write([]byte("alice-to-bob")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, []byte("alice-to-bob")) {
			t.Fatalf("Bob frame = %q", got)
		}
	case err := <-errs:
		t.Fatal(err)
	}

	go func() {
		plain, err := aliceSession.Read(make([]byte, 32))
		if err != nil {
			errs <- err
			return
		}
		received <- append([]byte(nil), plain...)
	}()
	if err := bobSession.Write([]byte("bob-to-alice")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, []byte("bob-to-alice")) {
			t.Fatalf("Alice frame = %q", got)
		}
	case err := <-errs:
		t.Fatal(err)
	}
	if _, err := alice.NewDataSession(left); !errors.Is(err, ErrHandshake) {
		t.Fatalf("second data session = %v, want ErrHandshake", err)
	}
}

func TestSessionRequestLengthAndOptionsValidation(t *testing.T) {
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(private.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	options := SessionRequestOptions{NetworkID: 2, Version: 2, PaddingLength: 224}
	if _, err := initiator.BuildSessionRequest(make([]byte, LegacyNTCPMaxSessionRequestLen+1), make([]byte, 32), make([]byte, 16), make([]byte, 224), options, true); !errors.Is(err, ErrHandshake) {
		t.Fatalf("legacy packet limit = %v", err)
	}
	var encoded [16]byte
	options.PaddingLength = 0
	options.marshalTo(encoded[:])
	encoded[6] = 1
	if _, err := parseSessionRequestOptions(encoded[:], 2); !errors.Is(err, ErrNetwork) {
		t.Fatalf("reserved option = %v", err)
	}
}

func TestAESCBCRoundTrip(t *testing.T) {
	key, iv := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 16)
	plaintext := bytes.Repeat([]byte{6}, 32)
	ciphertext := make([]byte, len(plaintext))
	if err := aesCBCEncrypt(ciphertext, plaintext, key, iv); err != nil {
		t.Fatal(err)
	}
	opened := make([]byte, len(plaintext))
	if err := aesCBCDecrypt(opened, ciphertext, key, iv); err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("aes CBC = %x, %v", opened, err)
	}
}

// Vector copied from libi2pd tests/test-aes.cpp.
func TestI2PDAESCBCVector(t *testing.T) {
	key, iv := decodeHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"), decodeHex(t, "f58c4c04d6e5f1ba779eabfb5f7bfbd6")
	plaintext := decodeHex(t, "ae2d8a571e03ac9c9eb76fac45af8e51")
	expected := decodeHex(t, "9cfc4e967edb808d679f777bc6702c7d")
	ciphertext := make([]byte, len(plaintext))
	if err := aesCBCEncrypt(ciphertext, plaintext, key, iv); err != nil || !bytes.Equal(ciphertext, expected) {
		t.Fatalf("AES-CBC encrypt = %x, %v", ciphertext, err)
	}
	opened := make([]byte, len(plaintext))
	if err := aesCBCDecrypt(opened, ciphertext, key, iv); err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("AES-CBC decrypt = %x, %v", opened, err)
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestHandshakeReleaseSensitiveIsIdempotentAndTerminal(t *testing.T) {
	curve := ecdh.X25519()
	bobStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewInitiator(bobStatic.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	alice.ReleaseSensitive()
	alice.ReleaseSensitive()
	if alice.state != nil || alice.ephemeral != nil || alice.peerEphemeral != nil || alice.aesState != ([16]byte{}) {
		t.Fatal("initiator retained handshake state after release")
	}
	if _, err = alice.BuildSessionRequest(make([]byte, SessionRequestCiphertextLen), make([]byte, 32), make([]byte, 16), nil, SessionRequestOptions{}, false); !errors.Is(err, ErrHandshake) {
		t.Fatalf("BuildSessionRequest after release = %v", err)
	}

	fresh, err := NewInitiator(bobStatic.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	request, err := fresh.BuildSessionRequest(make([]byte, SessionRequestCiphertextLen), make([]byte, 32), make([]byte, 16), nil, SessionRequestOptions{NetworkID: 2, Version: 2}, false)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := ParseSessionRequest(request, bobStatic.Bytes(), make([]byte, 32), make([]byte, 16), 2, false)
	if err != nil {
		t.Fatal(err)
	}
	bob.ReleaseSensitive()
	bob.ReleaseSensitive()
	if bob.state != nil || bob.ephemeral != nil || bob.peerEphemeral != nil || bob.aesState != ([16]byte{}) {
		t.Fatal("responder retained handshake state after release")
	}
	if _, err = bob.BuildSessionCreated(make([]byte, SessionRequestCiphertextLen), make([]byte, 32), nil, SessionCreatedOptions{}); !errors.Is(err, ErrHandshake) {
		t.Fatalf("BuildSessionCreated after release = %v", err)
	}
}
