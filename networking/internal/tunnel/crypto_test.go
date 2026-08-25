package tunnel

import (
	"bytes"
	"testing"
)

func TestLayerCipherRoundTrip(t *testing.T) {
	layer, iv := make([]byte, 32), make([]byte, 32)
	for i := range layer {
		layer[i] = byte(i)
		iv[i] = byte(i + 32)
	}
	enc, err := NewLayerEncryptor(layer, iv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewLayerDecryptor(layer, iv)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, LayerPayloadSize)
	for i := range plain {
		plain[i] = byte(i)
	}
	cipher := make([]byte, LayerPayloadSize)
	if err := enc.Transform(cipher, plain); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cipher, plain) {
		t.Fatal("ciphertext unchanged")
	}
	out := make([]byte, LayerPayloadSize)
	if err := dec.Transform(out, cipher); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("round trip mismatch")
	}
}
