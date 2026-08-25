package netdb

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	ivnp "gosuda.org/ivnp/i2p"
	"gosuda.org/ivnp/internal/pool"
	"testing"
)

func gzipBytes(t *testing.T, input []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestRoutingKeyMatchesI2PDUTCDateTransform(t *testing.T) {
	want, err := hex.DecodeString("8d5e0050a16b50f39a72cd045710ad628d343d596dd1068945d237d6413a987e")
	if err != nil {
		t.Fatal(err)
	}
	got := RoutingKey(ivnp.Hash{}, 1_787_529_600_000)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("routing key = %x, want %x", got, want)
	}
}

func TestInflateRouterInfoExactBoundary(t *testing.T) {
	database := NewDatabase(ivnp.Hash{}, DefaultBucketCapacity)
	exact := make([]byte, MaxRouterInfoBytes)
	inflated, err := database.inflateRouterInfo(gzipBytes(t, exact))
	if err != nil || len(inflated) != MaxRouterInfoBytes {
		t.Fatalf("exact boundary = %d bytes, %v", len(inflated), err)
	}
	defer pool.Release(inflated)
	if _, err := database.inflateRouterInfo(gzipBytes(t, make([]byte, MaxRouterInfoBytes+1))); !errors.Is(err, ErrRouterInfoTooLarge) {
		t.Fatalf("oversize gzip error = %v, want ErrRouterInfoTooLarge", err)
	}
}

func TestRouterInfoFreshUsesSharedTransportBounds(t *testing.T) {
	now := uint64(1_000_000_000)
	for _, test := range []struct {
		name      string
		published uint64
		want      error
	}{
		{"fresh", now - RouterInfoMaxAgeMillis, nil},
		{"stale", now - RouterInfoMaxAgeMillis - 1, ErrRouterInfoStale},
		{"near future", now + RouterInfoMaxFutureMillis, nil},
		{"future", now + RouterInfoMaxFutureMillis + 1, ErrRouterInfoFuture},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := RouterInfoFresh(RouterInfo{Published: test.published}, now)
			if !errors.Is(err, test.want) {
				t.Fatalf("RouterInfoFresh() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReseedRouterInfoFreshUsesBoundedStandardWindow(t *testing.T) {
	now := uint64(100_000_000)
	if err := ReseedRouterInfoFresh(RouterInfo{Published: now - ReseedRouterInfoMaxAgeMillis}, now); err != nil {
		t.Fatalf("fresh reseed RouterInfo error = %v", err)
	}
	if err := ReseedRouterInfoFresh(RouterInfo{Published: now - ReseedRouterInfoMaxAgeMillis - 1}, now); !errors.Is(err, ErrRouterInfoStale) {
		t.Fatalf("stale reseed RouterInfo error = %v, want ErrRouterInfoStale", err)
	}
	if err := RouterInfoFresh(RouterInfo{Published: now - RouterInfoMaxAgeMillis - 1}, now); !errors.Is(err, ErrRouterInfoStale) {
		t.Fatalf("transport freshness was weakened: %v", err)
	}
}
