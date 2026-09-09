package securestore

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	filesystemstore "gosuda.org/ivnp/state/internal/filesystem_store"
)

const lockFileName = ".ivnp.lock"

// Lock represents an advisory file lock on a state directory.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// AcquireLock acquires an exclusive non-blocking file lock on the state directory.
func (s *Store) AcquireLock() (*Lock, error) {
	if s == nil {
		return nil, ErrStoreConfig
	}
	if err := s.validConfig(); err != nil {
		return nil, err
	}
	if s.memory {
		return &Lock{}, nil
	}
	dir, err := ensureParent(s.StatePath)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, lockFileName)
	file, err := filesystemstore.CreatePrivate(path)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, _, err = filesystemstore.OpenRegularFile(path, os.O_RDWR)
	}
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFile(file); err != nil {
		file.Close()
		return nil, err
	}
	if created {
		if err := filesystemstore.SyncCreated(file); err != nil {
			file.Close()
			return nil, err
		}
	}
	if err := filesystemstore.LockExclusive(file); err != nil {
		file.Close()
		if errors.Is(err, filesystemstore.ErrLocked) {
			return nil, ErrStateLocked
		}
		return nil, err
	}
	return &Lock{file: file}, nil
}

// Close releases the file lock and closes the lock file.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file == nil {
			return
		}
		unlockErr := filesystemstore.Unlock(l.file)
		closeErr := l.file.Close()
		l.err = errors.Join(unlockErr, closeErr)
	})
	return l.err
}
