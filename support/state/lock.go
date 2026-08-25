package state

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"gosuda.org/ivnp/support/fsstore"
)

const lockFileName = ".ivnp.lock"

// Lock is an exclusive advisory ownership claim for a state directory.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// AcquireLock obtains exclusive, nonblocking ownership of the state directory.
// The lock remains held until Close.
func (s *Store) AcquireLock() (*Lock, error) {
	if s == nil {
		return nil, ErrStoreConfig
	}
	if err := s.validConfig(); err != nil {
		return nil, err
	}
	dir, err := ensureParent(s.StatePath)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, lockFileName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	if created {
		err = file.Chmod(0o600)
	}
	info, statErr := file.Stat()
	if statErr ==

		nil {
		statErr = err
	}
	if statErr ==
		nil {
		statErr = validatePrivateFile(info)
	}

	if statErr != nil {
		file.Close()
		return nil, statErr
	}
	if created {
		if err := fsstore.SyncDir(dir); err != nil {
			file.Close()
			return nil, err
		}
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrStateLocked
		}
		return nil, err
	}
	return &Lock{file: file}, nil
}

// Close releases the advisory lock and its file descriptor.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file == nil {
			return
		}
		unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		closeErr := l.file.Close()
		l.err = errors.Join(unlockErr, closeErr)
	})
	return l.err
}
