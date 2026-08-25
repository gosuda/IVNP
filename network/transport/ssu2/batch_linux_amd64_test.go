//go:build linux && amd64

package ssu2

import (
	"errors"
	"math/bits"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"
)

func TestLinuxUsesKernelVectorBatching(t *testing.T) {
	if !usesKernelVector() {
		t.Fatal("Linux amd64 backend did not select recvmmsg/sendmmsg")
	}
}

func TestNormalizeReadBatchUpdatesTrailingPacketsAfterTruncation(t *testing.T) {
	batch, err := NewBatch(2, 64)
	if err != nil {
		t.Fatal(err)
	}
	state := newBatchState(2).(*linuxBatchState)
	state.msgs[0].len = 64
	state.msgs[0].hdr.Flags = syscall.MSG_TRUNC
	state.msgs[1].len = 2
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&state.names[0])) = syscall.RawSockaddrInet4{
		Family: syscall.AF_INET, Port: bits.ReverseBytes16(1234), Addr: [4]byte{127, 0, 0, 1},
	}
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&state.names[1])) = syscall.RawSockaddrInet4{
		Family: syscall.AF_INET, Port: bits.ReverseBytes16(5678), Addr: [4]byte{127, 0, 0, 2},
	}

	count, err := normalizeReadBatch(batch, state, 2)
	if count != 2 || !errors.Is(err, ErrDatagramTruncated) {
		t.Fatalf("normalizeReadBatch = (%d, %v), want (2, ErrDatagramTruncated)", count, err)
	}
	packets := batch.Packets()
	if packets[0].Len != 64 || packets[0].Addr != netip.MustParseAddrPort("127.0.0.1:1234") {
		t.Fatalf("first packet = %#v", packets[0])
	}
	if packets[1].Len != 2 || packets[1].Addr != netip.MustParseAddrPort("127.0.0.2:5678") {
		t.Fatalf("trailing packet was stale: %#v", packets[1])
	}
}
