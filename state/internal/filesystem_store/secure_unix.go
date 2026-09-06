//go:build !windows

package filesystemstore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func openRegular(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// CreatePrivate exclusively creates an owner-only regular file, open for reading and writing.
func CreatePrivate(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// ValidateOwnedFile rejects foreign ownership, hard links and non-regular files.
func ValidateOwnedFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return ErrUnsafePermissions
	}
	return nil
}

// ValidatePrivateAccess requires an owned regular file without group or other access.
func ValidatePrivateAccess(file *os.File) error {
	if err := ValidateOwnedFile(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafePermissions
	}
	return nil
}

// ValidatePrivateFile additionally requires owner-only permissions.
func ValidatePrivateFile(file *os.File) error {
	if err := ValidateOwnedFile(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return ErrUnsafePermissions
	}
	return nil
}

// EnsurePrivateDir creates a private directory or validates its owner and write permissions.
func EnsurePrivateDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	file, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o022 != 0 {
		return ErrUnsafePermissions
	}
	return nil
}

// SyncDir flushes directory changes to disk.
func SyncDir(dir string) error {
	file, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func replaceAtomic(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(to))
}

// SyncCreated persists both the contents and directory entry of a newly created file.
func SyncCreated(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(file.Name()))
}

// LockExclusive acquires a non-blocking exclusive file lock.
func LockExclusive(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrLocked
	}
	return err
}

// Unlock releases a file lock.
func Unlock(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
