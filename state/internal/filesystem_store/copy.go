package filesystemstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// CopyOwnedFileIfExists atomically copies an owned regular file to an owner-only
// destination. Private sources must have the permissions required by state storage.
// Missing sources are skipped; maxBytes must be nonnegative.
func CopyOwnedFileIfExists(srcPath, dstPath string, maxBytes int64, private bool) error {
	if maxBytes < 0 {
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

	if private {
		err = ValidatePrivateFile(source)
	} else {
		err = ValidateOwnedFile(source)
	}
	if err != nil {
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
