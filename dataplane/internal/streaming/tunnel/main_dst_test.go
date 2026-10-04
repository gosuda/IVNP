//go:build dst || synctest

package streamingtunnel

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
// threads, and crypto packages honor a pinned crypto/rand.Reader. Both
// GODEBUG settings can only be applied at process start — run dst tests as:
//
//	GODEBUG=asyncpreemptoff=1,cryptocustomrand=1 GOGC=off go test -tags dst -overlay=...
func TestMain(m *testing.M) {
	godebug := os.Getenv("GODEBUG")
	for _, setting := range []string{"asyncpreemptoff=1", "cryptocustomrand=1"} {
		if !strings.Contains(godebug, setting) {
			fmt.Fprintf(os.Stderr, "dst tests require GODEBUG=asyncpreemptoff=1,cryptocustomrand=1 (missing %s)\n", setting)
			os.Exit(1)
		}
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
