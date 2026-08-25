package gost

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Vectors from libi2pd tests/test-gost.cpp.
func TestStreebogI2PDVector(t *testing.T) {
	message := mustDecode(t, "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
	want512 := mustDecode(t, "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")
	want256 := mustDecode(t, "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")
	got512 := Sum512(message)
	got256 := Sum256(message)
	if !bytes.Equal(got512[:], want512) {
		t.Fatalf("512 = %x", got512)
	}
	if !bytes.Equal(got256[:], want256) {
		t.Fatalf("256 = %x", got256)
	}
}
func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
