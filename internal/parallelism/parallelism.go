package parallelism

import (
	"runtime"
)

// Workers returns a CPU-scaled worker count bounded by the currently available
func Workers(work int) int {
	if work <= 0 {
		return 0
	}
	workers := min(CPUs(), work)
	return workers
}

// CPUs returns the scheduler's current effective CPU parallelism.
func CPUs() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	return workers
}
