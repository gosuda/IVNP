//go:build dst || synctest

package router

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gosuda.org/ivnp/internal/simnet"
)

// Dst tests require the durable-semaphore overlay (tools/dstoverlay): stock
// sync lock waits are not idle in a synctest bubble, so without -overlay the
// virtual clock freezes. This reference fails compilation without the overlay.
var _ = sync.DurableMutexOverlay

// TestMain serializes goroutine scheduling for deterministic simulation: one
// P runs runnable goroutines in runqueue order rather than racing them across
// threads. Async preemption can only be disabled via the GODEBUG environment
// variable at process start — run dst tests as:
//
//	GODEBUG=asyncpreemptoff=1 go test -tags dst ...
func TestMain(m *testing.M) {
	if !strings.Contains(os.Getenv("GODEBUG"), "asyncpreemptoff=1") {
		fmt.Fprintln(os.Stderr, "dst tests require GODEBUG=asyncpreemptoff=1")
		os.Exit(1)
	}
	seed, err := simnet.SessionEntropySeed(42)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Handshake key generation draws crypto/rand: an entropy syscall inside
	// the bubble whose completion timing perturbs same-instant wakeup order.
	simnet.PinSessionEntropy(seed)
	runtime.GOMAXPROCS(1)
	os.Exit(m.Run())
}
