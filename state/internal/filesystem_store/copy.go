package filesystemstore

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
)

// CopyPrivateBoundedIfExists atomically copies an owner-only regular file into
// a private destination, rejecting symlinks, hard links and unsafe directories.
// Missing sources are skipped; maxBytes must be in [0, math.MaxInt64).
func CopyPrivateBoundedIfExists(srcPath, dstPath string, maxBytes int64) error {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return os.ErrInvalid
	}
	source, info, err := OpenRegular(srcPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer source.Close()
	if err := EnsurePrivateDir(filepath.Dir(srcPath)); err != nil {
		return err
	}

	if err := ValidatePrivateFile(source); err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return ErrTooLarge
	}

	destination, err := createTemporary(filepath.Dir(dstPath))
	if err != nil {
		return err
	}
	temporary := destination.Name()
	defer func() {
		_ = destination.Close()
		_ = os.Remove(temporary)
	}()

	copied, err := io.Copy(destination, io.LimitReader(source, maxBytes))
	if err != nil {
		return err
	}
	if copied == maxBytes {
		var extra [1]byte
		read, readErr := source.Read(extra[:])
		if read != 0 {
			return ErrTooLarge
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if readErr == nil {
			return io.ErrNoProgress
		}
	}

	if err := destination.Sync(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	return replaceAtomic(temporary, dstPath)
}
