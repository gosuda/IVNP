//go:build !linux || !amd64

package ssu2

import "testing"

func TestPortableDoesNotRequireKernelVectorBatching(t *testing.T) {
	if usesKernelVector() {
		t.Fatal("portable backend unexpectedly selected Linux vector I/O")
	}
}
