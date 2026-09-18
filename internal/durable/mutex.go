//go:build !dst && !synctest

package durable

import (
	"sync"
)

// Mutex in production is a zero-overhead alias to sync.Mutex.
type Mutex = sync.Mutex
