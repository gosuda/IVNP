package securestore

import (
	"errors"
	"testing"
)

func TestStateLockExcludesAnotherStoreUntilClosed(t *testing.T) {
	first := testStore(t)
	second, err := NewStore(first.StatePath, first.MasterKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := first.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	other, err := second.AcquireLock()
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, ErrStateLocked) {
		t.Fatalf("second store lock = %v, want locked", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	other, err = second.AcquireLock()
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
}
