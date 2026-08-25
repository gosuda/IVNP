package cryptx

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

// These direct-map fixtures are from elligator.org/vectors/curve25519_direct.vec
// (Elligator reference implementation, retrieved 2026-08-22). The published
// values are little-endian and have the I2P wire-format padding bits clear.
func TestElligator2AuthoritativeDirectVectors(t *testing.T) {
	fixtures := []struct {
		representative string
		public         string
	}{
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12",
			"04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e",
		},
		{
			"673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f",
			"242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e",
		},
	}
	for _, fixture := range fixtures {
		representative := mustElligatorHex(t, fixture.representative)
		want := mustElligatorHex(t, fixture.public)
		for _, entropy := range []byte{0x00, 0x40, 0x80, 0xc0} {
			encoded := append([]byte(nil), representative...)
			encoded[31] |= entropy
			var got [32]byte
			if err := DecodeElligator2(got[:], encoded); err != nil {
				t.Fatalf("DecodeElligator2(%x): %v", encoded, err)
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("DecodeElligator2(%x) = %x, want %x", encoded, got, want)
			}
		}
	}
}

func TestElligator2GeneratedKeyRoundTrip(t *testing.T) {
	for range 32 {
		private, encoded, err := GenerateElligator2X25519(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var decoded [32]byte
		if err := DecodeElligator2(decoded[:], encoded[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded[:], private.PublicKey().Bytes()) {
			t.Fatalf("decoded public key differs\n got %x\nwant %x", decoded, private.PublicKey().Bytes())
		}
		if _, err := ecdh.X25519().NewPublicKey(decoded[:]); err != nil {
			t.Fatalf("decoded invalid X25519 public key: %v", err)
		}
	}
}

func TestElligator2ExactEncodeVectors(t *testing.T) {
	public := mustElligatorHex(t, "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e")
	fixtures := []struct {
		entropy byte
		want    string
	}{
		{0x00, "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12"},
		{0x01, "d296c6e91f864a429198d2723689e3c2deb7b165323fdf1ef1e56d3e89d7772b"},
		{0x40, "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a52"},
		{0x41, "d296c6e91f864a429198d2723689e3c2deb7b165323fdf1ef1e56d3e89d7776b"},
		{0x80, "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a92"},
		{0x81, "d296c6e91f864a429198d2723689e3c2deb7b165323fdf1ef1e56d3e89d777ab"},
		{0xc0, "66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38ad2"},
		{0xc1, "d296c6e91f864a429198d2723689e3c2deb7b165323fdf1ef1e56d3e89d777eb"},
	}
	for _, fixture := range fixtures {
		var encoded [32]byte
		ok, err := EncodeElligator2(encoded[:], public, bytes.NewReader([]byte{fixture.entropy}))
		if err != nil || !ok {
			t.Fatalf("EncodeElligator2(entropy=%#x) = (%v, %v)", fixture.entropy, ok, err)
		}
		if want := mustElligatorHex(t, fixture.want); !bytes.Equal(encoded[:], want) {
			t.Fatalf("EncodeElligator2(entropy=%#x) = %x, want %x", fixture.entropy, encoded, want)
		}
		var decoded [32]byte
		if err := DecodeElligator2(decoded[:], encoded[:]); err != nil || !bytes.Equal(decoded[:], public) {
			t.Fatalf("encoded vector did not decode to source public key: %x, %v", decoded, err)
		}
	}
}

func TestElligator2RejectsBadLengthsAndBoundaries(t *testing.T) {
	if _, err := EncodeElligator2(nil, make([]byte, 32), rand.Reader); err != ErrElligator {
		t.Fatalf("short encode error = %v", err)
	}
	if err := DecodeElligator2(nil, make([]byte, 32)); err != ErrElligator {
		t.Fatalf("short decode error = %v", err)
	}

	// Failed operations must not publish partially computed values.
	unchanged := bytes.Repeat([]byte{0xa5}, 32)
	for _, public := range [][]byte{
		make([]byte, 32),
		fieldBytes(fieldP),
		fieldBytes(fieldNegA),
	} {
		dst := append([]byte(nil), unchanged...)
		if _, err := EncodeElligator2(dst, public, bytes.NewReader([]byte{0})); err != ErrElligator {
			t.Fatalf("invalid public %x error = %v", public, err)
		}
		if !bytes.Equal(dst, unchanged) {
			t.Fatalf("invalid public %x altered destination", public)
		}
	}

	for _, representative := range [][]byte{
		fieldBytes(fieldHalf.add(fieldOne)),
		bytes.Repeat([]byte{0xff}, 32),
	} {
		dst := append([]byte(nil), unchanged...)
		if err := DecodeElligator2(dst, representative); err != ErrElligator {
			t.Fatalf("invalid representative %x error = %v", representative, err)
		}
		if !bytes.Equal(dst, unchanged) {
			t.Fatalf("invalid representative %x altered destination", representative)
		}
	}
}

func TestElligator2IneligibleDoesNotConsumeRandomness(t *testing.T) {
	for candidate := byte(1); candidate != 0; candidate++ {
		public := make([]byte, 32)
		public[0] = candidate
		reader := &countingReader{data: []byte{0x7f}}
		ok, err := EncodeElligator2(make([]byte, 32), public, reader)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			if reader.read != 0 {
				t.Fatalf("ineligible public key consumed %d random bytes", reader.read)
			}
			return
		}
	}
	t.Fatal("no ineligible public key in test corpus")
}
func TestElligator2Allocations(t *testing.T) {
	public := mustElligatorHex(t, "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e")
	var encoded, decoded [32]byte
	entropy := oneByteReader{value: 1, remaining: 1}
	if ok, err := EncodeElligator2(encoded[:], public, &entropy); err != nil || !ok {
		t.Fatalf("setup EncodeElligator2 = (%v, %v)", ok, err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		entropy.remaining = 1
		if ok, err := EncodeElligator2(encoded[:], public, &entropy); err != nil || !ok {
			panic("encode failed")
		}
	}); allocations != 0 {
		t.Fatalf("EncodeElligator2 allocations/call = %v, want 0", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		if err := DecodeElligator2(decoded[:], encoded[:]); err != nil {
			panic("decode failed")
		}
	}); allocations != 0 {
		t.Fatalf("DecodeElligator2 allocations/call = %v, want 0", allocations)
	}
}

func mustElligatorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func fieldBytes(value field25519) []byte {
	var encoded [32]byte
	value.store(encoded[:])
	return encoded[:]
}

type countingReader struct {
	data []byte
	read int
}

func (r *countingReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(dst, r.data)
	r.data = r.data[n:]
	r.read += n
	return n, nil
}

type oneByteReader struct {
	value     byte
	remaining int
}

func (r *oneByteReader) Read(dst []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	dst[0] = r.value
	r.remaining--
	return 1, nil
}
func (r *oneByteReader) ReadByte() (byte, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	r.remaining--
	return r.value, nil
}
