package cryptx

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
)

var ErrElligator = errors.New("cryptx: invalid Elligator2 point")

// EncodeElligator2 maps an eligible 32-byte little-endian X25519 public key to
// a uniform-looking 32-byte I2P Elligator2 representative. About half X25519
// public keys are ineligible; callers should generate another ephemeral key.
func EncodeElligator2(dst, public []byte, random io.Reader) (bool, error) {
	if len(dst) < 32 || len(public) != 32 {
		return false, ErrElligator
	}
	if random ==
		nil {
		random = rand.Reader
	}

	x := fieldLoad(public)
	canonical := x.lessMask(fieldP)
	valid := canonical &^ x.zeroMask() &^ x.equalMask(fieldNegA)
	if valid != ^uint64(0) {
		return false, ErrElligator
	}

	// r0² = x/(2*(-x-A)). Check eligibility before consuming randomness: callers
	// retry an ineligible key without advancing their RNG stream.
	xA := x.add(fieldA).neg()
	r0, square := fieldSqrtRatio(x, fieldTwo.mul(xA))
	if square != ^uint64(0) {
		return false, nil
	}
	var entropy byte
	if reader, ok := random.(interface{ ReadByte() (byte, error) }); ok {
		var err error
		entropy, err = reader.ReadByte()
		if err != nil {
			return false, err
		}
	} else {
		var buffer [1]byte
		if _, err := io.ReadFull(random, buffer[:]); err != nil {
			return false, err
		}
		entropy = buffer[0]
	}
	r1 := fieldTwo.mul(r0).invert()
	r := fieldSelect(r1, r0, 0-uint64(entropy&1))
	r = fieldSelect(r.neg(), r, r.lessOrEqualMask(fieldHalf)^uint64(0xffffffffffffffff))

	var encoded [32]byte
	r.store(encoded[:])
	// The two unused top bits add entropy without changing the decoded field
	// element, exactly as i2pd's Elligator2 encoder does.
	encoded[31] |= entropy & 0xc0
	copy(dst[:32], encoded[:])
	return true, nil
}

// DecodeElligator2 maps an I2P Elligator2 representative back to the
// little-endian X25519 public key used by Noise DH.
func DecodeElligator2(dst, encoded []byte) error {
	if len(dst) < 32 || len(encoded) != 32 {
		return ErrElligator
	}

	var representative [32]byte
	copy(representative[:], encoded)
	representative[31] &= 0x3f
	r := fieldLoad(representative[:])
	valid := r.lessOrEqualMask(fieldHalf)

	d := fieldOne.add(fieldTwo.mul(r.square()))
	v := fieldNegA.mul(d.invert())
	vSquared := v.square()
	t := vSquared.mul(v)
	t = t.add(fieldA.mul(vSquared))
	t = t.add(v)
	other := v.neg().sub(fieldA)
	x := fieldSelect(v, other, fieldIsSquareNonzero(t))

	// There is only one public validity decision; failed decoding does not alter
	// the caller's destination.
	if valid != ^uint64(0) {
		return ErrElligator
	}
	var canonical [32]byte
	x.store(canonical[:])
	copy(dst[:32], canonical[:])
	return nil
}

// GenerateElligator2X25519 creates an eligible ephemeral X25519 private key
// and its encoded public representative. The retry bound makes RNG or mapping
// failures explicit rather than creating an unbounded handshake allocation.
func GenerateElligator2X25519(random io.Reader) (*ecdh.PrivateKey, [32]byte, error) {
	if random ==
		nil {
		random = rand.Reader
	}

	curve := ecdh.X25519()
	for range 128 {
		private, err := curve.GenerateKey(random)
		if err != nil {
			return nil, [32]byte{}, err
		}
		var encoded [32]byte
		ok, err := EncodeElligator2(encoded[:], private.PublicKey().Bytes(), random)
		if err != nil {
			return nil, [32]byte{}, err
		}
		if ok {
			return private, encoded, nil
		}
	}
	return nil, [32]byte{}, ErrElligator
}
