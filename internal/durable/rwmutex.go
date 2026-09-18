//go:build !dst && !synctest

package durable

import (
	"sync"
)

// RWMutex in production is a zero-overhead alias to sync.RWMutex.
type RWMutex = sync.RWMutex
