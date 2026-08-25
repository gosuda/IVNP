// Package gost implements the GOST R 34.11-2012 (Streebog) hash used by
// i2pd GOST signatures. It is a direct Go port of libi2pd's reference core.
package gost

type block [64]byte

func (b block) xor(other block) (out block) {
	for i := range b {
		out[i] = b[i] ^ other[i]
	}
	return
}
func (b block) add(other block) (out block) {
	carry := uint16(0)
	for i := 63; i >= 0; i-- {
		v := uint16(b[i]) + uint16(other[i]) + carry
		out[i] = byte(v)
		carry = v >> 8
	}
	return
}
func (b *block) addBits(bits uint32) {
	for i := 63; i >= 0 && bits != 0; i-- {
		bits += uint32(b[i])
		b[i] = byte(bits)
		bits >>= 8
	}
}
func (b *block) f() {
	var out [8]uint64
	for i := range 8 {
		out[i] = t0[b[i+56]] ^ t1[b[i+48]] ^ t2[b[i+40]] ^ t3[b[i+32]] ^ t4[b[i+24]] ^ t5[b[i+16]] ^ t6[b[i+8]] ^ t7[b[i]]
	}
	for i := range 8 {
		v := out[i]
		for j := range 8 {
			b[i*8+j] = byte(v >> (8 * j))
		}
	}
}
func (b block) encrypt(message block) (out block) {
	k := b
	out = k.xor(message)
	for i := range 12 {
		out.f()
		k = k.xor(words(roundConstants[i]))
		k.f()
		out = k.xor(out)
	}
	return
}
func words(values [8]uint64) (out block) {
	for i, v := range values {
		for j := range 8 {
			out[i*8+j] = byte(v >> (8 * j))
		}
	}
	return
}
func g(n, h, m block) block {
	key := n.xor(h)
	key.f()
	out := key.encrypt(m)
	out = out.xor(h)
	return out.xor(m)
}

// Sum512 returns the Streebog-512 digest.
func Sum512(data []byte) (digest [64]byte) { return sum(data, 0) }

// Sum256 returns the first half of the Streebog-256 state, as libi2pd does.
func Sum256(data []byte) (digest [32]byte) { full := sum(data, 1); copy(digest[:], full[:32]); return }
func sum(data []byte, iv byte) (digest [64]byte) {
	var h, n, s block
	for i := range h {
		h[i] = iv
	}
	left := len(data)
	for left >= 64 {
		var m block
		copy(m[:], data[left-64:left])
		h = g(n, h, m)
		n.addBits(512)
		s = s.add(m)
		left -= 64
	}
	var m block
	padding := 64 - left
	if padding > 0 {
		m[padding-1] = 1
	}
	copy(m[padding:], data[:left])
	h = g(n, h, m)
	n.addBits(uint32(left * 8))
	s = s.add(m)
	var zero block
	h = g(zero, h, n)
	h = g(zero, h, s)
	return h
}
