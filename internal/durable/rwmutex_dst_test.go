//go:build dst || synctest

package durable_test

import (
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/internal/durable"
)

func TestRWMutexWriterExcludesReaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu durable.RWMutex
		mu.RLock()
		mu.RLock()
		writer := make(chan struct{})
		release := make(chan struct{})
		go func() {
			mu.Lock()
			close(writer)
			<-release
			mu.Unlock()
		}()
		synctest.Wait()
		if mu.TryRLock() {
			t.Fatal("reader bypassed waiting writer")
		}
		reader := make(chan struct{})
		go func() {
			mu.RLock()
			close(reader)
			mu.RUnlock()
		}()
		mu.RUnlock()
		synctest.Wait()
		select {
		case <-writer:
			t.Fatal("writer entered with one reader remaining")
		default:
		}
		mu.RUnlock()
		<-writer
		synctest.Wait()
		select {
		case <-reader:
			t.Fatal("reader entered before writer released")
		default:
		}
		if mu.TryLock() || mu.TryRLock() {
			t.Fatal("try-lock acquired a write-locked mutex")
		}
		close(release)
		<-reader
		synctest.Wait()
		if !mu.TryLock() {
			t.Fatal("mutex remained locked after all holders released")
		}
		mu.Unlock()
	})
}

func TestRWMutexContentionAdvancesVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu durable.RWMutex
		mu.Lock()
		start := time.Now()
		go func() {
			time.Sleep(time.Second)
			mu.Unlock()
		}()
		mu.RLocker().Lock()
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Fatalf("reader waited %v, want one virtual second", elapsed)
		}
		if mu.TryLock() {
			t.Fatal("writer acquired a read-locked mutex")
		}
		if !mu.TryRLock() {
			t.Fatal("concurrent reader could not acquire mutex")
		}
		mu.RUnlock()
		go func() {
			time.Sleep(time.Second)
			mu.RLocker().Unlock()
		}()
		mu.Lock()
		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Fatalf("writer acquired after %v, want two virtual seconds", elapsed)
		}
		mu.Unlock()
	})
}
