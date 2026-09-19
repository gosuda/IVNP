//go:build dst || synctest

package ivnp

import (
	"os"
	"runtime"
	"testing"
)

// TestMain serializes goroutine scheduling for deterministic simulation: one
// P runs runnable goroutines in runqueue order rather than racing them across
// threads. Async preemption can only be disabled via the GODEBUG environment
// variable at process start — run dst tests as:
//
//	GODEBUG=asyncpreemptoff=1 go test -tags dst ...
func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(1)
	os.Exit(m.Run())
}
