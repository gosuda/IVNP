//go:build !linux || !amd64

package ssu2

import (
	"syscall"
)

// Portable builds have no kernel vector path: every socket — native or
// simulated — uses the shared per-datagram implementation.

func newBatchState(count int) any { return newBatchStatePortable(count) }

func enableKernelDropAccounting(syscall.RawConn) bool { return false }

func readBatch(c *UDPBatchConn, b *Batch) (int, error) {
	return readBatchPortable(c, b)
}

func writeBatchPrefix(c *UDPBatchConn, b *Batch, count int) (int, error) {
	return writeBatchPrefixPortable(c, b, count)
}

func usesKernelVector() bool { return false }
