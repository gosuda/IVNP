// Package filesystemstore provides atomic file writes and bounded file reads.
package filesystemstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrTooLarge          = errors.New("fsstore: content exceeds configured maximum")
	ErrInvalidFile       = errors.New("fsstore: not a regular file")
	ErrUnsafePermissions = errors.New("fsstore: unsafe ownership or permissions")
	ErrLocked            = errors.New("fsstore: file is locked")
)

// WriteAtomic writes data to a temporary file and atomically renames it to path.
func WriteAtomic(path string, data []byte, mode os.FileMode, max int) error {
	if max >= 0 && len(data) > max {
		return ErrTooLarge
	}
	dir := filepath.Dir(path)
	file, err := createTemporary(dir)
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
	return replaceAtomic(temporary, path)
}

// OpenRegular opens a file without following symlinks and checks that it is a regular file.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	return OpenRegularFile(path, os.O_RDONLY)
}

// OpenRegularFile opens an existing regular file without following symlinks.
// flag must be os.O_RDONLY or os.O_RDWR.
func OpenRegularFile(path string, flag int) (*os.File, os.FileInfo, error) {
	if flag != os.O_RDONLY && flag != os.O_RDWR {
		return nil, nil, os.ErrInvalid
	}
	file, err := openRegular(path, flag)
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

func ReadBounded(path string, max int64) ([]byte, error) {
	file, _, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ReadBoundedFile(file, max)
}

// ReadBoundedFile reads file contents up to max bytes.
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

func createTemporary(dir string) (*os.File, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		file, err := CreatePrivate(filepath.Join(dir, ".ivnp-"+hex.EncodeToString(random[:])))
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, err
	}
	return nil, os.ErrExist
}
