package cryptography

import (
	"math/bits"
)

// field25519 represents an element in GF(2^255-19) in 4x64-bit little-endian limbs.
type field25519 [4]uint64

const fieldTopMask uint64 = 0x7fffffffffffffff

var (
	fieldP        = field25519{0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff, fieldTopMask}
	fieldA        = field25519{486662}
	fieldNegA     = field25519{0xfffffffffff892e7, 0xffffffffffffffff, 0xffffffffffffffff, fieldTopMask}
	fieldHalf     = field25519{0xfffffffffffffff6, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff}
	fieldOne      = field25519{1}
	fieldTwo      = field25519{2}
	fieldSqrtM1   = field25519{0xc4ee1b274a0ea0b0, 0x2f431806ad2fe478, 0x2b4d00993dfbd7a7, 0x2b8324804fc1df0b}
	fieldPMinus2  = field25519{0xffffffffffffffeb, 0xffffffffffffffff, 0xffffffffffffffff, fieldTopMask}
	fieldPow22523 = field25519{0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0x0fffffffffffffff}
)

func fieldLoad(in []byte) field25519 {
	_ = in[31] // One length check eliminates bounds checks for every byte load below.
	return field25519{
		uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 | uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56,
		uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 | uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56,
		uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 | uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56,
		uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 | uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56,
	}
}

func (z field25519) store(out []byte) {
	_ = out[31] // One length check eliminates bounds checks for every byte store below.
	for i, word := range z {
		off := 8 * i
		out[off] = byte(word)
		out[off+1] = byte(word >> 8)
		out[off+2] = byte(word >> 16)
		out[off+3] = byte(word >> 24)
		out[off+4] = byte(word >> 32)
		out[off+5] = byte(word >> 40)
		out[off+6] = byte(word >> 48)
		out[off+7] = byte(word >> 56)
	}
}

func fieldNonzeroMask(x uint64) uint64 { return 0 - ((x | (0 - x)) >> 63) }
func fieldZeroMask(x uint64) uint64    { return ^fieldNonzeroMask(x) }

func (z field25519) equalMask(x field25519) uint64 {
	return fieldZeroMask((z[0] ^ x[0]) | (z[1] ^ x[1]) | (z[2] ^ x[2]) | (z[3] ^ x[3]))
}

func (z field25519) zeroMask() uint64 { return fieldZeroMask(z[0] | z[1] | z[2] | z[3]) }

func (z field25519) lessMask(x field25519) uint64 {
	_, borrow := bits.Sub64(z[0], x[0], 0)
	_, borrow = bits.Sub64(z[1], x[1], borrow)
	_, borrow = bits.Sub64(z[2], x[2], borrow)
	_, borrow = bits.Sub64(z[3], x[3], borrow)
	return 0 - borrow
}

func (z field25519) lessOrEqualMask(x field25519) uint64 {
	return z.lessMask(x) | z.equalMask(x)
}

func fieldSelect(a, b field25519, mask uint64) field25519 {
	return field25519{
		(a[0] & mask) | (b[0] &^ mask),
		(a[1] & mask) | (b[1] &^ mask),
		(a[2] & mask) | (b[2] &^ mask),
		(a[3] & mask) | (b[3] &^ mask),
	}
}

func (z field25519) canonical() field25519 {
	d0, borrow := bits.Sub64(z[0], fieldP[0], 0)
	d1, borrow := bits.Sub64(z[1], fieldP[1], borrow)
	d2, borrow := bits.Sub64(z[2], fieldP[2], borrow)
	d3, borrow := bits.Sub64(z[3], fieldP[3], borrow)
	return fieldSelect(field25519{d0, d1, d2, d3}, z, ^(0 - borrow))
}

// fieldFold reduces a value with carry into the canonical field range.
func fieldFold(z field25519, carry uint64) field25519 {
	z[0], carry = bits.Add64(z[0], 38*carry, 0)
	z[1], carry = bits.Add64(z[1], 0, carry)
	z[2], carry = bits.Add64(z[2], 0, carry)
	z[3], carry = bits.Add64(z[3], 0, carry)
	// Handle additional 2^256 carry
	z[0], carry = bits.Add64(z[0], 38*carry, 0)
	z[1], carry = bits.Add64(z[1], 0, carry)
	z[2], carry = bits.Add64(z[2], 0, carry)
	z[3], _ = bits.Add64(z[3], 0, carry)
	for range 2 { // 2^255 = 19 mod p
		high := z[3] >> 63
		z[3] &= fieldTopMask
		z[0], carry = bits.Add64(z[0], 19*high, 0)
		z[1], carry = bits.Add64(z[1], 0, carry)
		z[2], carry = bits.Add64(z[2], 0, carry)
		z[3], _ = bits.Add64(z[3], 0, carry)
	}
	return z.canonical()
}

func (z field25519) add(x field25519) field25519 {
	z0, carry := bits.Add64(z[0], x[0], 0)
	z1, carry := bits.Add64(z[1], x[1], carry)
	z2, carry := bits.Add64(z[2], x[2], carry)
	z3, carry := bits.Add64(z[3], x[3], carry)
	return fieldFold(field25519{z0, z1, z2, z3}, carry)
}

func (z field25519) sub(x field25519) field25519 {
	z0, borrow := bits.Sub64(z[0], x[0], 0)
	z1, borrow := bits.Sub64(z[1], x[1], borrow)
	z2, borrow := bits.Sub64(z[2], x[2], borrow)
	z3, borrow := bits.Sub64(z[3], x[3], borrow)
	mask := 0 - borrow
	z0, carry := bits.Add64(z0, fieldP[0]&mask, 0)
	z1, carry = bits.Add64(z1, fieldP[1]&mask, carry)
	z2, carry = bits.Add64(z2, fieldP[2]&mask, carry)
	z3, _ = bits.Add64(z3, fieldP[3]&mask, carry)
	return field25519{z0, z1, z2, z3}
}

func (z field25519) neg() field25519 {
	minus := fieldP.sub(z)
	return fieldSelect(field25519{}, minus, z.zeroMask())
}

func (z field25519) mul(x field25519) field25519 {
	var t [9]uint64
	for i := range 4 {
		for j := range 4 {
			hi, lo := bits.Mul64(z[i], x[j])
			k := i + j
			var carry uint64
			t[k], carry = bits.Add64(t[k], lo, 0)
			t[k+1], carry = bits.Add64(t[k+1], hi, carry)
			for k += 2; k < len(t); k++ {
				t[k], carry = bits.Add64(t[k], 0, carry)
			}
		}
	}

	// 2^255 = 19 (mod p)
	h := [5]uint64{t[3]>>63 | t[4]<<1, t[4]>>63 | t[5]<<1, t[5]>>63 | t[6]<<1, t[6]>>63 | t[7]<<1, t[7]>>63 | t[8]<<1}
	r := [6]uint64{t[0], t[1], t[2], t[3] & fieldTopMask}
	var carry uint64
	for i := range 5 {
		hi, lo := bits.Mul64(h[i], 19)
		lo, c := bits.Add64(lo, carry, 0)
		hi += c
		r[i], carry = bits.Add64(r[i], lo, 0)
		carry += hi
	}
	r[5] = carry

	high := r[3]>>63 | r[4]<<1
	q := field25519{r[0], r[1], r[2], r[3] & fieldTopMask}
	hi, lo := bits.Mul64(high, 19)
	q[0], carry = bits.Add64(q[0], lo, 0)
	q[1], carry = bits.Add64(q[1], hi, carry)
	q[2], carry = bits.Add64(q[2], 0, carry)
	q[3], _ = bits.Add64(q[3], 0, carry)
	return fieldFold(q, 0)
}

func (z field25519) square() field25519 { return z.mul(z) }

func (z field25519) squareN(n int) field25519 {
	for range n {
		z = z.square()
	}
	return z
}

func (z field25519) pow(exponent field25519) field25519 {
	result := fieldOne
	for limb := 3; limb >= 0; limb-- {
		for bit := 63; bit >= 0; bit-- {
			result = result.square()
			product := result.mul(z)
			result = fieldSelect(product, result, 0-((exponent[limb]>>uint(bit))&1))
		}
	}
	return result
}

func (z field25519) invert() field25519   { return z.pow(fieldPMinus2) }
func (z field25519) pow22523() field25519 { return z.pow(fieldPow22523) }

// fieldSqrtRatio computes sqrt(u/v) and returns an all-ones mask if u/v is a quadratic residue.
// The candidate root is normalized into the Elligator2 half-range.
func fieldSqrtRatio(u, v field25519) (field25519, uint64) {
	v2 := v.square()
	uv3 := u.mul(v2).mul(v)
	uv7 := uv3.mul(v2).mul(v2)
	r := uv3.mul(uv7.pow22523())
	check := v.mul(r.square())
	isU := check.equalMask(u)
	isNegU := check.equalMask(u.neg())
	r = fieldSelect(r.mul(fieldSqrtM1), r, isNegU)
	r = fieldSelect(r.neg(), r, r.lessOrEqualMask(fieldHalf)^0xffffffffffffffff)
	return r, isU | isNegU
}

func fieldIsSquareNonzero(z field25519) uint64 {
	_, square := fieldSqrtRatio(z, fieldOne)
	return square &^ z.zeroMask()
}
