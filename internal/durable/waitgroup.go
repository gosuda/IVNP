//go:build !dst && !synctest

package durable

import (
	"sync"
)

// WaitGroup in production is a zero-overhead alias to sync.WaitGroup.
type WaitGroup = sync.WaitGroup
