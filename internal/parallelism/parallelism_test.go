package parallelism

import (
	"runtime"
	"testing"
)

func TestWorkersBoundedByCPUAndWork(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })

	if got := Workers(0); got != 0 {
		t.Fatalf("Workers(0) = %d, want 0", got)
	}
	if got := Workers(1); got != 1 {
		t.Fatalf("Workers(1) = %d, want 1", got)
	}
	if got := Workers(8); got != 2 {
		t.Fatalf("Workers(8) = %d, want effective CPU count 2", got)
	}
}
