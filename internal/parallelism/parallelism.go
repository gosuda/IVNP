package parallelism

import (
	"runtime"
)

// Workers returns a worker count based on the available CPUs and the amount of work to perform.
func Workers(work int) int {
	if work <= 0 {
		return 0
	}
	workers := min(CPUs(), work)
	return workers
}

// CPUs returns GOMAXPROCS, ensuring at least 1.
func CPUs() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	return workers
}
