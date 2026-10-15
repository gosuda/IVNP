package cryptography

import (
	"math/bits"
)

// field25519 represents an element in GF(2^255-19) in 4x64-bit little-endian limbs.
type field25519 [4]uint64

const fieldTopMask uint64 = 0x7fffffffffffffff

var (
	fieldP      = field25519{0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff, fieldTopMask}
	fieldA      = field25519{486662}
	fieldNegA   = field25519{0xfffffffffff892e7, 0xffffffffffffffff, 0xffffffffffffffff, fieldTopMask}
	fieldHalf   = field25519{0xfffffffffffffff6, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff}
	fieldOne    = field25519{1}
	fieldTwo    = field25519{2}
	fieldSqrtM1 = field25519{0xc4ee1b274a0ea0b0, 0x2f431806ad2fe478, 0x2b4d00993dfbd7a7, 0x2b8324804fc1df0b}
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
	high := (z[3] >> 63) + (carry << 1)
	z[3] &= fieldTopMask
	var c uint64
	z[0], c = bits.Add64(z[0], 19*high, 0)
	z[1], c = bits.Add64(z[1], 0, c)
	z[2], c = bits.Add64(z[2], 0, c)
	z[3], _ = bits.Add64(z[3], 0, c)
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

func fieldReduce512(t0, t1, t2, t3, t4, t5, t6, t7 uint64) field25519 {
	hi0, lo0 := bits.Mul64(t4, 38)
	r0, c := bits.Add64(t0, lo0, 0)
	hi1, lo1 := bits.Mul64(t5, 38)
	lo1, c1 := bits.Add64(lo1, hi0, 0)
	r1, c := bits.Add64(t1, lo1, c)
	c += c1
	hi2, lo2 := bits.Mul64(t6, 38)
	lo2, c2 := bits.Add64(lo2, hi1, 0)
	r2, c := bits.Add64(t2, lo2, c)
	c += c2
	hi3, lo3 := bits.Mul64(t7, 38)
	lo3, c3 := bits.Add64(lo3, hi2, 0)
	r3, c := bits.Add64(t3, lo3, c)
	carry := hi3 + c3 + c
	return fieldFold(field25519{r0, r1, r2, r3}, carry)
}

func (z field25519) mul(x field25519) field25519 {
	z0, z1, z2, z3 := z[0], z[1], z[2], z[3]
	x0, x1, x2, x3 := x[0], x[1], x[2], x[3]

	hi0, t0 := bits.Mul64(z0, x0)
	hi1, lo1 := bits.Mul64(z0, x1)
	t1, c := bits.Add64(lo1, hi0, 0)
	hi2, lo2 := bits.Mul64(z0, x2)
	t2, c := bits.Add64(lo2, hi1, c)
	hi3, lo3 := bits.Mul64(z0, x3)
	t3, c := bits.Add64(lo3, hi2, c)
	t4 := hi3 + c

	hi0, lo0 := bits.Mul64(z1, x0)
	hi1, lo1 = bits.Mul64(z1, x1)
	p2, c := bits.Add64(lo1, hi0, 0)
	hi2, lo2 = bits.Mul64(z1, x2)
	p3, c := bits.Add64(lo2, hi1, c)
	hi3, lo3 = bits.Mul64(z1, x3)
	p4, c := bits.Add64(lo3, hi2, c)
	p5 := hi3 + c
	t1, c = bits.Add64(t1, lo0, 0)
	t2, c = bits.Add64(t2, p2, c)
	t3, c = bits.Add64(t3, p3, c)
	t4, c = bits.Add64(t4, p4, c)
	t5 := p5 + c

	hi0, lo0 = bits.Mul64(z2, x0)
	hi1, lo1 = bits.Mul64(z2, x1)
	p3, c = bits.Add64(lo1, hi0, 0)
	hi2, lo2 = bits.Mul64(z2, x2)
	p4, c = bits.Add64(lo2, hi1, c)
	hi3, lo3 = bits.Mul64(z2, x3)
	p5, c = bits.Add64(lo3, hi2, c)
	p6 := hi3 + c
	t2, c = bits.Add64(t2, lo0, 0)
	t3, c = bits.Add64(t3, p3, c)
	t4, c = bits.Add64(t4, p4, c)
	t5, c = bits.Add64(t5, p5, c)
	t6 := p6 + c

	hi0, lo0 = bits.Mul64(z3, x0)
	hi1, lo1 = bits.Mul64(z3, x1)
	p4, c = bits.Add64(lo1, hi0, 0)
	hi2, lo2 = bits.Mul64(z3, x2)
	p5, c = bits.Add64(lo2, hi1, c)
	hi3, lo3 = bits.Mul64(z3, x3)
	p6, c = bits.Add64(lo3, hi2, c)
	p7 := hi3 + c
	t3, c = bits.Add64(t3, lo0, 0)
	t4, c = bits.Add64(t4, p4, c)
	t5, c = bits.Add64(t5, p5, c)
	t6, c = bits.Add64(t6, p6, c)
	t7 := p7 + c

	return fieldReduce512(t0, t1, t2, t3, t4, t5, t6, t7)
}

func (z field25519) square() field25519 {
	z0, z1, z2, z3 := z[0], z[1], z[2], z[3]

	// Cross terms (i < j):
	hi1, t1 := bits.Mul64(z0, z1)
	hi2, lo2 := bits.Mul64(z0, z2)
	t2, c := bits.Add64(lo2, hi1, 0)
	hi3, lo3 := bits.Mul64(z0, z3)
	t3, c := bits.Add64(lo3, hi2, c)
	t4 := hi3 + c

	hi3, lo3 = bits.Mul64(z1, z2)
	hi4, lo4 := bits.Mul64(z1, z3)
	p4, c := bits.Add64(lo4, hi3, 0)
	p5 := hi4 + c
	t3, c = bits.Add64(t3, lo3, 0)
	t4, c = bits.Add64(t4, p4, c)
	t5 := p5 + c

	hi5, lo5 := bits.Mul64(z2, z3)
	t5, c = bits.Add64(t5, lo5, 0)
	t6 := hi5 + c

	// Double cross terms:
	t7 := t6 >> 63
	t6 = (t6 << 1) | (t5 >> 63)
	t5 = (t5 << 1) | (t4 >> 63)
	t4 = (t4 << 1) | (t3 >> 63)
	t3 = (t3 << 1) | (t2 >> 63)
	t2 = (t2 << 1) | (t1 >> 63)
	t1 <<= 1

	// Add diagonal terms z[i]^2:
	d1, t0 := bits.Mul64(z0, z0)
	d3, d2 := bits.Mul64(z1, z1)
	d5, d4 := bits.Mul64(z2, z2)
	d7, d6 := bits.Mul64(z3, z3)

	t1, c = bits.Add64(t1, d1, 0)
	t2, c = bits.Add64(t2, d2, c)
	t3, c = bits.Add64(t3, d3, c)
	t4, c = bits.Add64(t4, d4, c)
	t5, c = bits.Add64(t5, d5, c)
	t6, c = bits.Add64(t6, d6, c)
	t7, _ = bits.Add64(t7, d7, c)

	return fieldReduce512(t0, t1, t2, t3, t4, t5, t6, t7)
}

func (z field25519) mulA24() field25519 {
	const a24 = 121665
	hi0, r0 := bits.Mul64(z[0], a24)
	hi1, lo1 := bits.Mul64(z[1], a24)
	r1, c := bits.Add64(lo1, hi0, 0)
	hi2, lo2 := bits.Mul64(z[2], a24)
	r2, c := bits.Add64(lo2, hi1, c)
	hi3, lo3 := bits.Mul64(z[3], a24)
	r3, c := bits.Add64(lo3, hi2, c)
	return fieldFold(field25519{r0, r1, r2, r3}, hi3+c)
}

func (z field25519) squareN(n int) field25519 {
	for range n {
		z = z.square()
	}
	return z
}

var fieldBasepoint = [32]byte{9}

func (z field25519) pow250(z11 *field25519) field25519 {
	z2 := z.square()
	z9 := z2.squareN(2).mul(z)
	*z11 = z9.mul(z2)
	z2_5_0 := z11.square().mul(z9)
	z2_10_0 := z2_5_0.squareN(5).mul(z2_5_0)
	z2_20_0 := z2_10_0.squareN(10).mul(z2_10_0)
	z2_40_0 := z2_20_0.squareN(20).mul(z2_20_0)
	z2_50_0 := z2_40_0.squareN(10).mul(z2_10_0)
	z2_100_0 := z2_50_0.squareN(50).mul(z2_50_0)
	z2_200_0 := z2_100_0.squareN(100).mul(z2_100_0)
	return z2_200_0.squareN(50).mul(z2_50_0)
}

func (z field25519) invert() field25519 {
	var z11 field25519
	return z.pow250(&z11).squareN(5).mul(z11)
}

func (z field25519) pow22523() field25519 {
	var z11 field25519
	return z.pow250(&z11).squareN(2).mul(z)
}

func x25519ScalarMult(dst, scalar, point *[32]byte) {
	var e, uBytes [32]byte
	copy(e[:], scalar[:])
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64
	copy(uBytes[:], point[:])
	uBytes[31] &= 0x7f

	x1 := fieldLoad(uBytes[:])
	x2 := fieldOne
	var z2 field25519
	x3 := x1
	z3 := fieldOne
	var swap uint64

	for t := 254; t >= 0; t-- {
		kt := uint64((e[t>>3] >> uint(t&7)) & 1)
		swap ^= kt
		mask := 0 - swap
		x2, x3 = fieldSelect(x3, x2, mask), fieldSelect(x2, x3, mask)
		z2, z3 = fieldSelect(z3, z2, mask), fieldSelect(z2, z3, mask)
		swap = kt

		a := x2.add(z2)
		aa := a.square()
		b := x2.sub(z2)
		bb := b.square()
		eField := aa.sub(bb)
		c := x3.add(z3)
		d := x3.sub(z3)
		da := d.mul(a)
		cb := c.mul(b)
		x3 = da.add(cb).square()
		z3 = x1.mul(da.sub(cb).square())
		x2 = aa.mul(bb)
		z2 = eField.mul(aa.add(eField.mulA24()))
	}
	mask := 0 - swap
	x2 = fieldSelect(x3, x2, mask)
	z2 = fieldSelect(z3, z2, mask)
	x2.mul(z2.invert()).store(dst[:])
	clear(e[:])
}

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
