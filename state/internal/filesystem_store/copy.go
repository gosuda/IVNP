package filesystemstore

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
)

// CopyPrivateBoundedIfExists copies an owner-only regular file atomically and
// leaves an absent source absent. No source symlink or hard link is followed.
func CopyPrivateBoundedIfExists(srcPath, dstPath string, maxBytes int64) (err error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return os.ErrInvalid
	}
	src, info, err := OpenRegular(srcPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, src.Close()) }()
	if err := ValidatePrivateFile(src); err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return ErrTooLarge
	}

	dst, err := createTemporary(filepath.Dir(dstPath))
	if err != nil {
		return err
	}
	temporary := dst.Name()
	defer os.Remove(temporary)
	copied, copyErr := io.CopyN(dst, src, maxBytes+1)
	if copyErr == nil || errors.Is(copyErr, io.EOF) {
		if copied > maxBytes {
			copyErr = ErrTooLarge
		} else {
			copyErr = dst.Sync()
		}
	}
	if err := errors.Join(copyErr, dst.Close()); err != nil {
		return err
	}
	return replaceAtomic(temporary, dstPath)
}
