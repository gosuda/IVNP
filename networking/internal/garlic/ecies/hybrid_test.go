package ecies

import (
	"bytes"
	cryptx "gosuda.org/ivnp/cryptography"
	"gosuda.org/ivnp/networking/internal/transport/noise"
	"testing"
)

func TestHybridE1EKEMTranscriptAndMixKey(t *testing.T) {
	for _, cryptoType := range []uint16{cryptx.MLKEM768X25519, cryptx.MLKEM1024X25519} {
		t.Run(string(rune(cryptoType)), func(t *testing.T) {
			params, _ := cryptx.Parameters(cryptoType)
			initiator, err := NewHybridInitiator(cryptoType)
			if err != nil {
				t.Fatal(err)
			}
			responder, err := NewHybridResponder(cryptoType)
			if err != nil {
				t.Fatal(err)
			}
			alice := noise.Initialize(params.NoiseIdentifier)
			bob := noise.Initialize(params.NoiseIdentifier)
			priorDH := bytes.Repeat([]byte{1}, 32)
			if err := alice.MixKey(priorDH); err != nil {
				t.Fatal(err)
			}
			if err := bob.MixKey(priorDH); err != nil {
				t.Fatal(err)
			}

			e1Wire := make([]byte, params.PublicKeySize+16)
			if _, err := initiator.EncryptE1(alice, e1Wire); err != nil {
				t.Fatal(err)
			}
			if err := responder.ConsumeE1(bob, make([]byte, params.PublicKeySize), e1Wire); err != nil {
				t.Fatal(err)
			}
			eKemWire := make([]byte, params.CiphertextSize+16)
			if _, err := responder.EncryptEKEM(bob, eKemWire); err != nil {
				t.Fatal(err)
			}
			if err := initiator.ConsumeEKEM(alice, make([]byte, params.CiphertextSize), eKemWire); err != nil {
				t.Fatal(err)
			}
			if alice.ChainingKey() != bob.ChainingKey() || alice.Hash() != bob.Hash() {
				t.Fatal("hybrid participants diverged after e1/ekem1")
			}
		})
	}
}

func TestHybridRejectsMalformedSections(t *testing.T) {
	initiator, err := NewHybridInitiator(cryptx.MLKEM768X25519)
	if err != nil {
		t.Fatal(err)
	}
	state := noise.Initialize("Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256")
	if err := state.MixKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := initiator.ConsumeEKEM(state, nil, nil); err != ErrHybrid {
		t.Fatalf("malformed ekem error = %v, want ErrHybrid", err)
	}
	if _, err := NewHybridInitiator(999); err != ErrHybrid {
		t.Fatalf("unknown hybrid initiator error = %v, want ErrHybrid", err)
	}
}
