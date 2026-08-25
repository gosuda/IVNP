// Package filesystemstore provides crash-safe bounded state-file updates.
package filesystemstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrTooLarge    = errors.New("fsstore: content exceeds configured maximum")
	ErrInvalidFile = errors.New("fsstore: not a regular file")
)

// WriteAtomic persists data through a same-directory temporary file and rename.
func WriteAtomic(path string, data []byte, mode os.FileMode, max int) error {
	if max >= 0 && len(data) > max {
		return ErrTooLarge
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".ivnp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err ==
		nil {
		err = file.Sync()
	}

	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// OpenRegular opens path without following a final symlink and verifies that
// the opened descriptor is a regular file.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, ErrInvalidFile
	}
	return file, info, nil
}

// SyncDir makes previously completed directory entry updates durable.
func SyncDir(dir string) error {
	file, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func ReadBounded(path string, max int64) ([]byte, error) {
	file, _, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ReadBoundedFile(file, max)
}

// ReadBoundedFile reads from an already-open regular-file descriptor.
func ReadBoundedFile(file *os.File, max int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrInvalidFile
	}
	if max >= 0 && info.Size() > max {
		return nil, ErrTooLarge
	}
	if max < 0 || max == int64(^uint64(0)>>1) {
		return io.ReadAll(file)
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, ErrTooLarge
	}
	return data, nil
}
