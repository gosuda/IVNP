package cryptx

import (
	"encoding/binary"
	"math/big"
	"testing"
)

func TestField25519ArithmeticAgainstOracle(t *testing.T) {
	modulus := new(big.Int).Lsh(big.NewInt(1), 255)
	modulus.Sub(modulus, big.NewInt(19))
	values := []field25519{
		{}, fieldOne, fieldTwo, fieldA, fieldHalf, fieldHalf.add(fieldOne),
		fieldP.sub(fieldOne), fieldP.sub(fieldTwo),
		fieldP.sub(fieldOne),
	}
	state := uint64(0x6a09e667f3bcc909)
	for range 64 {
		var value field25519
		for limb := range value {
			state ^= state << 7
			state ^= state >> 9
			state ^= state << 8
			value[limb] = state
		}
		value[3] &= fieldTopMask
		values = append(values, value.canonical())
	}

	for _, x := range values {
		for _, y := range values {
			assertFieldOracle(t, x.add(y), new(big.Int).Add(fieldBig(x), fieldBig(y)), modulus)
			gotSub, wantSub := x.sub(y), new(big.Int).Sub(fieldBig(x), fieldBig(y))
			if gotBig := fieldBig(gotSub); gotBig.Cmp(new(big.Int).Mod(wantSub, modulus)) != 0 {
				t.Fatalf("sub(%x, %x) = %x, want %064x", fieldBytes(x), fieldBytes(y), fieldBytes(gotSub), new(big.Int).Mod(wantSub, modulus))
			}
			assertFieldOracle(t, x.mul(y), new(big.Int).Mul(fieldBig(x), fieldBig(y)), modulus)
		}
		assertFieldOracle(t, x.square(), new(big.Int).Mul(fieldBig(x), fieldBig(x)), modulus)
		if x.zeroMask() == 0 {
			inverse := new(big.Int).ModInverse(fieldBig(x), modulus)
			assertFieldOracle(t, x.invert(), inverse, modulus)
			if x.mul(x.invert()).equalMask(fieldOne) != ^uint64(0) {
				t.Fatalf("inverse product for %x is not one", fieldBytes(x))
			}
		}
	}
}

func TestField25519SerializationAndMasks(t *testing.T) {
	for _, value := range []field25519{fieldOne, fieldHalf, fieldP.sub(fieldOne)} {
		encoded := fieldBytes(value)
		if got := fieldLoad(encoded); got != value {
			t.Fatalf("fieldLoad(fieldStore(%x)) = %#v, want %#v", encoded, got, value)
		}
		if value.lessMask(fieldP) != ^uint64(0) || value.equalMask(value) != ^uint64(0) {
			t.Fatalf("canonical masks failed for %#v", value)
		}
	}
	if fieldP.lessMask(fieldP) != 0 || fieldP.sub(fieldOne).lessMask(fieldP.sub(fieldOne)) != 0 {
		t.Fatal("comparison equality mask is not zero")
	}
}

func assertFieldOracle(t *testing.T, got field25519, want, modulus *big.Int) {
	t.Helper()
	want = new(big.Int).Mod(want, modulus)
	if want.Sign() < 0 {
		want.Add(want, modulus)
	}
	if gotBig := fieldBig(got); gotBig.Cmp(want) != 0 {
		t.Fatalf("field result = %x, want %064x", fieldBytes(got), want)
	}
	if got.lessMask(fieldP) != ^uint64(0) {
		t.Fatalf("field result is not canonical: %x", fieldBytes(got))
	}
}

func fieldBig(value field25519) *big.Int {
	var encoded [32]byte
	for i, word := range value {
		binary.LittleEndian.PutUint64(encoded[8*i:], word)
	}
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return new(big.Int).SetBytes(encoded[:])
}
