package ecies

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"gosuda.org/ivnp/crypto/cryptx"
)

func TestAttachPayloadKDFMatchesJavaVector(t *testing.T) {
	split := make([]byte, 32)
	for i := range split {
		split[i] = byte(i)
	}
	cipher, err := cryptx.NewChaCha20Poly1305(split)
	if err != nil {
		t.Fatal(err)
	}
	defer cipher.ReleaseSensitive()
	got, err := deriveAttachPayloadKey(cipher)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0333819bc5348a00a62852e4c3bfe7f773364cfe3952e439c4cb4644bb0ca0f1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("AttachPayloadKDF = %x, want Java HKDF %x", got, want)
	}
}

func TestHandshakeUsesJavaRawStaticPremessage(t *testing.T) {
	curve := ecdh.X25519()
	alice, err := curve.NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := curve.NewPrivateKey(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(alice.Bytes(), bob.PublicKey().Bytes(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.ReleaseSensitive()

	protocolHash := sha256.Sum256([]byte("Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"))
	prologueHash := sha256.Sum256(protocolHash[:])
	transcript := append(prologueHash[:], bob.PublicKey().Bytes()...)
	want := sha256.Sum256(transcript)
	if got := initiator.state.Hash(); !bytes.Equal(got[:], want[:]) {
		t.Fatalf("hs2 pre-message hash = %x, want Java raw-static transcript %x", got, want)
	}
}

func TestBoundECIESHandshakeAndHybridReplies(t *testing.T) {
	for _, cryptoType := range []uint16{4, cryptx.MLKEM768X25519, cryptx.MLKEM1024X25519} {
		t.Run(handshakeName(cryptoType), func(t *testing.T) {
			curve := ecdh.X25519()
			aliceStatic, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bobStatic, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			initiator, err := NewInitiator(aliceStatic.Bytes(), bobStatic.PublicKey().Bytes(), cryptoType, true)
			if err != nil {
				t.Fatal(err)
			}
			request := []byte{1, 2, 3, 4, 5, 6, 7, 'r', 'e', 'q'}
			newSession := make([]byte, 4096)
			n, err := initiator.CreateNewSession(newSession, request)
			if err != nil {
				t.Fatal(err)
			}
			responder, err := NewResponder(bobStatic.Bytes(), cryptoType)
			if err != nil {
				t.Fatal(err)
			}
			requestOut, err := responder.ParseNewSession(newSession[:n], make([]byte, len(request)))
			if err != nil || !bytes.Equal(requestOut, request) {
				t.Fatalf("ParseNewSession = %x, %v", requestOut, err)
			}
			var tag [replyTagLen]byte
			copy(tag[:], []byte("replytag"))
			reply := []byte("response")
			newReply := make([]byte, 4096)
			n, err = responder.CreateReply(newReply, tag, reply)
			if err != nil {
				t.Fatal(err)
			}
			replyOut, err := initiator.ParseReply(newReply[:n], make([]byte, len(reply)))
			if err != nil || !bytes.Equal(replyOut, reply) {
				t.Fatalf("ParseReply = %x, %v", replyOut, err)
			}
		})
	}
}

func TestECIESHandshakeRejectsTamperedCiphertext(t *testing.T) {
	curve := ecdh.X25519()
	alice, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := NewInitiator(alice.Bytes(), bob.PublicKey().Bytes(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 128)
	n, err := initiator.CreateNewSession(wire, []byte{1, 2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	wire[n-1] ^= 1
	responder, err := NewResponder(bob.Bytes(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.ParseNewSession(wire[:n], make([]byte, 7)); err == nil {
		t.Fatal("tampered New Session accepted")
	}
}

func TestECIESHandshakeRejectsRemovedType5AndReleases(t *testing.T) {
	curve := ecdh.X25519()
	alice, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if initiator, err := NewInitiator(alice.Bytes(), bob.PublicKey().Bytes(), 5, true); err == nil || initiator != nil {
		t.Fatalf("NewInitiator(type 5) = %#v, %v", initiator, err)
	}
	if responder, err := NewResponder(bob.Bytes(), 5); err == nil || responder != nil {
		t.Fatalf("NewResponder(type 5) = %#v, %v", responder, err)
	}
	for _, cryptoType := range []uint16{4, cryptx.MLKEM768X25519, cryptx.MLKEM1024X25519} {
		if initiator, err := newInitiator(alice.Bytes(), bob.PublicKey().Bytes(), cryptoType, true, bytes.NewReader(nil)); !errors.Is(err, io.EOF) || initiator != nil {
			t.Fatalf("newInitiator(type %d) injected randomness failure = %#v, %v", cryptoType, initiator, err)
		}
	}

	initiator, err := NewInitiator(alice.Bytes(), bob.PublicKey().Bytes(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	initiator.ReleaseSensitive()
	initiator.ReleaseSensitive()
	if !initiator.closed || initiator.state != nil || initiator.static != nil || initiator.remoteStatic != nil || initiator.ephemeral != nil || initiator.ephemeralEnc != ([32]byte{}) {
		t.Fatal("initiator retained handshake state after release")
	}
	responder, err := NewResponder(bob.Bytes(), 4)
	if err != nil {
		t.Fatal(err)
	}
	responder.ReleaseSensitive()
	responder.ReleaseSensitive()
	if !responder.closed || responder.state != nil || responder.static != nil || responder.aliceEphemeral != nil || responder.aliceStatic != nil {
		t.Fatal("responder retained handshake state after release")
	}
}

func handshakeName(cryptoType uint16) string {
	if cryptoType == 4 {
		return "x25519"
	}
	params, _ := cryptx.Parameters(cryptoType)
	return params.NoiseIdentifier
}
