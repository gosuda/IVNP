package gost

import (
	"math/big"
	"testing"
)

func TestGOST256SignatureEquation(t *testing.T) {
	private := big.NewInt(1)
	base := point{new(big.Int).Set(curve256.gx), new(big.Int).Set(curve256.gy), false}
	publicPoint := curve256.mul(base, private)
	public := make([]byte, 64)
	publicPoint.x.FillBytes(public[:32])
	publicPoint.y.FillBytes(public[32:])
	message := []byte("i2pd gost signature vector")
	digest := Sum256(message)
	k := big.NewInt(2)
	c := curve256.mul(base, k)
	r := new(big.Int).Mod(c.x, curve256.q)
	s := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(r, private), new(big.Int).Mul(k, new(big.Int).SetBytes(digest[:]))), curve256.q)
	rawR, rawS := make([]byte, 32), make([]byte, 32)
	r.FillBytes(rawR)
	s.FillBytes(rawS)
	if !Verify256(public, message, rawR, rawS) {
		t.Fatal("GOST R 34.10-2012 256 verification failed")
	}
}
