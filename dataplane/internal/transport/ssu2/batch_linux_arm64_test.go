//go:build linux && arm64

package ssu2

import (
	"testing"
)

func TestLinuxARM64UsesKernelVectorBatching(t *testing.T) {
	if !usesKernelVector() || sysSendmmsg != 269 {
		t.Fatalf("Linux arm64 backend usesKernelVector=%t sysSendmmsg=%d", usesKernelVector(), sysSendmmsg)
	}
}
