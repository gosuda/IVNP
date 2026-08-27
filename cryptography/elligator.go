package cryptography

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
)

var ErrElligator = errors.New("cryptx: invalid Elligator2 point")

// EncodeElligator2 maps an eligible 32-byte X25519 public key to a uniform 32-byte
// I2P Elligator2 representative. Roughly 50% of X25519 keys are ineligible; callers
// must generate a new ephemeral key if encoding fails (ok=false).
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

	// r0² = x / (2 * (-x - A)). Check eligibility first to avoid consuming random bytes when ineligible.
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
	// The two unused high bits add entropy without altering the decoded curve point.
	encoded[31] |= entropy & 0xc0
	copy(dst[:32], encoded[:])
	return true, nil
}

// DecodeElligator2 decodes an Elligator2 representative back to an X25519 public key.
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

	if valid != ^uint64(0) {
		return ErrElligator
	}
	var canonical [32]byte
	x.store(canonical[:])
	copy(dst[:32], canonical[:])
	return nil
}

// GenerateElligator2X25519 generates an ephemeral X25519 key whose public key can be
// encoded with Elligator2, retrying until an eligible key is found (up to 128 attempts).
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
