package netdb

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestCompressRouterInfoPreservesWireBytesAcrossReuse(t *testing.T) {
	raw := bytes.Repeat([]byte("signed RouterInfo encoding"), 80)
	var reference bytes.Buffer
	writer, err := gzip.NewWriterLevel(&reference, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err = writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := CompressRouterInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reference.Bytes()) {
		t.Fatal("compression changed the deterministic wire encoding")
	}
	if _, err = CompressRouterInfo(bytes.Repeat([]byte{0xff}, MaxRouterInfoBytes)); err != nil {
		t.Fatal(err)
	}
	second, err := CompressRouterInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reference.Bytes()) || !bytes.Equal(second, reference.Bytes()) {
		t.Fatal("compressor reuse overwrote an owned result or retained previous input")
	}
	first[0] ^= 0xff
	if !bytes.Equal(second, reference.Bytes()) {
		t.Fatal("compression results alias one another")
	}
	reader, err := gzip.NewReader(bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err = errors.Join(err, reader.Close()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("decompressed bytes differ from the original RouterInfo")
	}
}

func TestCompressRouterInfoConcurrentOwnership(t *testing.T) {
	var workers sync.WaitGroup
	for id := range 16 {
		workers.Go(func() {
			raw := bytes.Repeat([]byte{byte(id)}, 512+id)
			for range 8 {
				compressed, err := CompressRouterInfo(raw)
				if err != nil {
					t.Error(err)
					return
				}
				reader, err := gzip.NewReader(bytes.NewReader(compressed))
				if err != nil {
					t.Error(err)
					return
				}
				decoded, err := io.ReadAll(reader)
				if err = errors.Join(err, reader.Close()); err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(decoded, raw) {
					t.Errorf("worker %d received another compression's bytes", id)
					return
				}
			}
		})
	}
	workers.Wait()
}

func TestCompressRouterInfoRejectsInvalidSize(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, MaxRouterInfoBytes+1)} {
		if _, err := CompressRouterInfo(raw); !errors.Is(err, ErrInvalidDatabaseStore) {
			t.Fatalf("compression of %d bytes returned %v", len(raw), err)
		}
	}
}

func BenchmarkCompressRouterInfoReuse(b *testing.B) {
	raw := bytes.Repeat([]byte("signed RouterInfo encoding"), 80)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := CompressRouterInfo(raw); err != nil {
			b.Fatal(err)
		}
	}
}
