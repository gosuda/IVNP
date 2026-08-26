package tunnel

import (
	"bytes"
	"sync"
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

func TestLayerCipherConcurrentRoundTrips(t *testing.T) {
	layer, iv := make([]byte, 32), make([]byte, 32)
	for index := range layer {
		layer[index] = byte(index)
		iv[index] = byte(index + 32)
	}
	encryptor, err := NewLayerEncryptor(layer, iv)
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := NewLayerDecryptor(layer, iv)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var group sync.WaitGroup
	failures := make(chan int, workers)
	group.Add(workers)
	for worker := range workers {
		go func() {
			defer group.Done()
			plain := make([]byte, LayerPayloadSize)
			for index := range plain {
				plain[index] = byte(index + worker)
			}
			encrypted := make([]byte, LayerPayloadSize)
			decrypted := make([]byte, LayerPayloadSize)
			if encryptor.Transform(encrypted, plain) != nil || decryptor.Transform(decrypted, encrypted) != nil || !bytes.Equal(decrypted, plain) {
				failures <- worker
			}
		}()
	}
	group.Wait()
	close(failures)
	for worker := range failures {
		t.Errorf("worker %d CBC round trip failed", worker)
	}
}

func BenchmarkLayerCipherTransform(b *testing.B) {
	layer, iv := make([]byte, 32), make([]byte, 32)
	encryptor, err := NewLayerEncryptor(layer, iv)
	if err != nil {
		b.Fatal(err)
	}
	src := make([]byte, LayerPayloadSize)
	dst := make([]byte, LayerPayloadSize)
	b.ReportAllocs()
	for b.Loop() {
		if err = encryptor.Transform(dst, src); err != nil {
			b.Fatal(err)
		}
	}
}
