package cryptography

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	mathrand "math/rand/v2"
	"testing"
)

func TestX25519PrivateKeyReleaseSensitive(t *testing.T) {
	encoded := bytes.Repeat([]byte{0x42}, 32)
	key, err := NewX25519PrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	key.ReleaseSensitive()
	key.ReleaseSensitive()
	if key.scalar != ([32]byte{}) || !key.released {
		t.Fatal("X25519 private scalar remained after release")
	}
	var output [32]byte
	output[0] = 1
	if err = key.PublicKey(&output); !errors.Is(err, ErrSensitiveReleased) || output != ([32]byte{}) {
		t.Fatalf("PublicKey after release = %x, %v", output, err)
	}
	output[0] = 1
	if err = key.ECDH(&output, make([]byte, 32)); !errors.Is(err, ErrSensitiveReleased) || output != ([32]byte{}) {
		t.Fatalf("ECDH after release = %x, %v", output, err)
	}
}

func TestX25519PrivateKeyZeroAllocAndLowOrderRejection(t *testing.T) {
	alice, err := NewX25519PrivateKey(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.ReleaseSensitive()
	bob, err := NewX25519PrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.ReleaseSensitive()

	var alicePublic, bobPublic, aliceShared, bobShared [32]byte
	if err = alice.PublicKey(&alicePublic); err != nil {
		t.Fatal(err)
	}
	if err = bob.PublicKey(&bobPublic); err != nil {
		t.Fatal(err)
	}
	if err = alice.ECDH(&aliceShared, bobPublic[:]); err != nil {
		t.Fatal(err)
	}
	if err = bob.ECDH(&bobShared, alicePublic[:]); err != nil {
		t.Fatal(err)
	}
	if aliceShared != bobShared || aliceShared == ([32]byte{}) {
		t.Fatalf("ECDH mismatch: %x != %x", aliceShared, bobShared)
	}

	if allocs := testing.AllocsPerRun(100, func() {
		_ = alice.PublicKey(&alicePublic)
		_ = alice.ECDH(&aliceShared, bobPublic[:])
	}); allocs != 0 {
		t.Fatalf("X25519 PublicKey+ECDH allocs = %v, want 0", allocs)
	}

	var zeroPeer [32]byte
	aliceShared[0] = 1
	if err = alice.ECDH(&aliceShared, zeroPeer[:]); err == nil || aliceShared != ([32]byte{}) {
		t.Fatalf("low-order peer ECDH = %x, %v; want error and cleared dst", aliceShared, err)
	}
}

func mustHex32(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("invalid 32-byte hex %q: %v", s, err)
	}
	return decoded
}

func TestX25519RFC7748Vectors(t *testing.T) {
	scalarMult := []struct{ scalar, u, want string }{
		{ // RFC 7748 section 5.2, first vector.
			"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
	}
	for _, vector := range scalarMult {
		key, err := NewX25519PrivateKey(mustHex32(t, vector.scalar))
		if err != nil {
			t.Fatal(err)
		}
		var got [32]byte
		if err := key.ECDH(&got, mustHex32(t, vector.u)); err != nil {
			t.Fatal(err)
		}
		key.ReleaseSensitive()
		if want := mustHex32(t, vector.want); !bytes.Equal(got[:], want) {
			t.Fatalf("X25519(%s, %s) = %x, want %x", vector.scalar, vector.u, got, want)
		}
	}

	// RFC 7748 section 6.1 Diffie-Hellman exchange.
	alice, err := NewX25519PrivateKey(mustHex32(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.ReleaseSensitive()
	var alicePublic, shared [32]byte
	if err := alice.PublicKey(&alicePublic); err != nil {
		t.Fatal(err)
	}
	if want := mustHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"); !bytes.Equal(alicePublic[:], want) {
		t.Fatalf("Alice public = %x, want %x", alicePublic, want)
	}
	bobPublic := mustHex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	if err := alice.ECDH(&shared, bobPublic); err != nil {
		t.Fatal(err)
	}
	if want := mustHex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"); !bytes.Equal(shared[:], want) {
		t.Fatalf("shared secret = %x, want %x", shared, want)
	}
}

// TestX25519MatchesStandardLibrary cross-checks the custom ladder against
// crypto/ecdh. Every in-repo handshake uses this implementation on both ends,
// so a symmetric arithmetic error would otherwise only surface against other
// I2P routers. Peers include non-canonical u-coordinates and a set bit 255.
func TestX25519MatchesStandardLibrary(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(7748, 25519))
	curve := ecdh.X25519()
	var scalar, peer [32]byte
	for iteration := range 2000 {
		for index := range scalar {
			scalar[index] = byte(random.Uint32())
			peer[index] = byte(random.Uint32())
		}
		switch iteration % 4 {
		case 1:
			peer[31] |= 0x80 // RFC 7748 requires ignoring bit 255.
		case 2:
			// Non-canonical encoding in [p, 2^255): p + small offset.
			peer = [32]byte{0xed + byte(random.IntN(18)), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
		}

		stdPrivate, err := curve.NewPrivateKey(scalar[:])
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewX25519PrivateKey(scalar[:])
		if err != nil {
			t.Fatal(err)
		}
		var public, shared [32]byte
		if err := key.PublicKey(&public); err != nil {
			t.Fatal(err)
		}
		if want := stdPrivate.PublicKey().Bytes(); !bytes.Equal(public[:], want) {
			t.Fatalf("iteration %d: public = %x, crypto/ecdh = %x", iteration, public, want)
		}

		stdPeer, err := curve.NewPublicKey(peer[:])
		if err != nil {
			t.Fatal(err)
		}
		want, stdErr := stdPrivate.ECDH(stdPeer)
		err = key.ECDH(&shared, peer[:])
		key.ReleaseSensitive()
		if (stdErr == nil) != (err == nil) {
			t.Fatalf("iteration %d: peer %x error = %v, crypto/ecdh error = %v", iteration, peer, err, stdErr)
		}
		if stdErr == nil && !bytes.Equal(shared[:], want) {
			t.Fatalf("iteration %d: peer %x shared = %x, crypto/ecdh = %x", iteration, peer, shared, want)
		}
	}
}

func BenchmarkX25519PublicKey(b *testing.B) {
	key, err := NewX25519PrivateKey(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		b.Fatal(err)
	}
	defer key.ReleaseSensitive()
	var public [32]byte
	b.ReportAllocs()
	for b.Loop() {
		if err := key.PublicKey(&public); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkX25519ECDH(b *testing.B) {
	alice, err := NewX25519PrivateKey(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		b.Fatal(err)
	}
	defer alice.ReleaseSensitive()
	bob, err := NewX25519PrivateKey(bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		b.Fatal(err)
	}
	defer bob.ReleaseSensitive()
	var peer, shared [32]byte
	if err = bob.PublicKey(&peer); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := alice.ECDH(&shared, peer[:]); err != nil {
			b.Fatal(err)
		}
	}
}
