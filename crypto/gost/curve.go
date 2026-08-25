package gost

import "math/big"

type curve struct{ a, b, p, q, gx, gy *big.Int }
type point struct {
	x, y *big.Int
	inf  bool
}

func newCurve(values [6]string) curve {
	parse := func(s string) *big.Int { n, _ := new(big.Int).SetString(s, 16); return n }
	return curve{parse(values[0]), parse(values[1]), parse(values[2]), parse(values[3]), parse(values[4]), parse(values[5])}
}

var curve256 = newCurve([6]string{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", "A6", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", "1", "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"})
var curve512 = newCurve([6]string{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4", "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", "3", "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"})

func (c curve) add(p, q point) point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(p.y, q.y), c.p).Sign() == 0 {
			return point{inf: true}
		}
		return c.double(p)
	}
	num := new(big.Int).Sub(q.y, p.y)
	den := new(big.Int).ModInverse(new(big.Int).Sub(q.x, p.x), c.p)
	l := new(big.Int).Mod(new(big.Int).Mul(num, den), c.p)
	x := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(l, l), p.x), q.x), c.p)
	y := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(l, new(big.Int).Sub(p.x, x)), p.y), c.p)
	return point{x, y, false}
}
func (c curve) double(p point) point {
	if p.inf || p.y.Sign() == 0 {
		return point{inf: true}
	}
	num := new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.x, p.x)), c.a)
	den := new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), p.y), c.p)
	l := new(big.Int).Mod(new(big.Int).Mul(num, den), c.p)
	x := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(l, l), new(big.Int).Mul(big.NewInt(2), p.x)), c.p)
	y := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(l, new(big.Int).Sub(p.x, x)), p.y), c.p)
	return point{x, y, false}
}
func (c curve) mul(p point, k *big.Int) point {
	out := point{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		out = c.double(out)
		if k.Bit(i) != 0 {
			out = c.add(out, p)
		}
	}
	return out
}
func (c curve) verify(public, digest, r, s []byte) bool {
	if len(public) != (c.p.BitLen()+7)/8*2 || len(r) != (c.p.BitLen()+7)/8 || len(s) != len(r) {
		return false
	}
	rr := new(big.Int).SetBytes(r)
	ss := new(big.Int).SetBytes(s)
	if rr.Sign() <= 0 || rr.Cmp(c.q) >= 0 || ss.Sign() <= 0 || ss.Cmp(c.q) >= 0 {
		return false
	}
	h := new(big.Int).Mod(new(big.Int).SetBytes(digest), c.q)
	inv := new(big.Int).ModInverse(h, c.q)
	if inv == nil {
		return false
	}
	z1 := new(big.Int).Mod(new(big.Int).Mul(ss, inv), c.q)
	z2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(c.q, rr), inv), c.q)
	pub := point{new(big.Int).SetBytes(public[:len(public)/2]), new(big.Int).SetBytes(public[len(public)/2:]), false}
	base := point{new(big.Int).Set(c.gx), new(big.Int).Set(c.gy), false}
	out := c.add(c.mul(base, z1), c.mul(pub, z2))
	if out.inf {
		return false
	}
	return new(big.Int).Mod(out.x, c.q).Cmp(rr) == 0
}
func Verify256(public, message, r, s []byte) bool {
	h := Sum256(message)
	return curve256.verify(public, h[:], r, s)
}
func Verify512(public, message, r, s []byte) bool {
	h := Sum512(message)
	return curve512.verify(public, h[:], r, s)
}
