package filesystemstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func diskPath(path string) (*uint16, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(absolute)
	// Device namespaces and alternate data streams are not state files.
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(absolute[len(volume):], ":") {
		return nil, ErrInvalidFile
	}
	relative := strings.TrimLeft(absolute[len(volume):], `\`)
	if relative != "" && !filepath.IsLocal(relative) {
		return nil, ErrInvalidFile
	}
	return windows.UTF16PtrFromString(absolute)
}

func privateSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
}

func openDisk(path string, access, disposition uint32, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	name, err := diskPath(path)
	if err != nil {
		return nil, err
	}
	var attributes *windows.SecurityAttributes
	if sd != nil {
		attributes = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
	if access&windows.GENERIC_WRITE != 0 {
		flags |= windows.FILE_FLAG_WRITE_THROUGH
	}
	handle, err := windows.CreateFile(name, access|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attributes, disposition, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if _, err := diskInfo(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func diskInfo(file *os.File) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return info, err
	}
	if kind != windows.FILE_TYPE_DISK {
		return info, ErrInvalidFile
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, ErrInvalidFile
	}
	return info, nil
}

func openRegular(path string, flag int) (*os.File, error) {
	access := uint32(windows.GENERIC_READ)
	if flag == os.O_RDWR {
		access |= windows.GENERIC_WRITE
	}
	return openDisk(path, access, windows.OPEN_EXISTING, nil)
}

// CreatePrivate installs the owner-only DACL at exclusive creation, before any data is written.
func CreatePrivate(path string) (*os.File, error) {
	sd, err := privateSecurity()
	if err != nil {
		return nil, err
	}
	file, err := openDisk(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.CREATE_NEW, sd)
	if err != nil {
		return nil, err
	}
	if err := ValidatePrivateFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func ownedSecurity(file *os.File) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return nil, ErrUnsafePermissions
	}
	return sd, nil
}

func validatePrivateSecurity(file *os.File) error {
	sd, err := ownedSecurity(file)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ErrUnsafePermissions
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		// Unknown/object/callback ACEs are rejected rather than incorrectly interpreted.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnsafePermissions
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windows.EqualSid(sid, owner) && !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return ErrUnsafePermissions
		}
	}
	return nil
}

// ValidateOwnedFile rejects foreign ownership, hard links and non-regular files.
func ValidateOwnedFile(file *os.File) error {
	info, err := diskInfo(file)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
		return ErrUnsafePermissions
	}
	_, err = ownedSecurity(file)
	return err
}

// ValidatePrivateFile requires a DACL granting access only to the owner, SYSTEM or administrators.
func ValidatePrivateFile(file *os.File) error {
	if err := ValidateOwnedFile(file); err != nil {
		return err
	}
	return validatePrivateSecurity(file)
}

// ValidatePrivateAccess requires an owned regular file with a private DACL.
func ValidatePrivateAccess(file *os.File) error {
	return ValidatePrivateFile(file)
}

// EnsurePrivateDir creates directories with an owner-only DACL and rejects unsafe existing directories.
func EnsurePrivateDir(dir string) error {
	file, err := openDisk(dir, windows.GENERIC_READ, windows.OPEN_EXISTING, nil)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(dir)
		if parent == dir {
			return err
		}
		if _, parentErr := os.Lstat(parent); errors.Is(parentErr, os.ErrNotExist) {
			if err := EnsurePrivateDir(parent); err != nil {
				return err
			}
		} else if parentErr != nil {
			return parentErr
		}
		sd, err := privateSecurity()
		if err != nil {
			return err
		}
		name, err := diskPath(dir)
		if err != nil {
			return err
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		if err := windows.CreateDirectory(name, &attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return err
		}
		file, err = openDisk(dir, windows.GENERIC_READ, windows.OPEN_EXISTING, nil)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer file.Close()
	info, err := diskInfo(file)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrInvalidFile
	}
	return validatePrivateSecurity(file)
}

// SyncCreated persists a file created by CreatePrivate. Its WRITE_THROUGH handle
// flushes NTFS metadata as well as data; Windows has no directory-fsync contract.
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
func SyncCreated(file *os.File) error {
	return file.Sync()
}

func replaceAtomic(from, to string) error {
	source, err := diskPath(from)
	if err != nil {
		return err
	}
	target, err := diskPath(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// LockExclusive acquires a non-blocking exclusive lock on the first byte.
func LockExclusive(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

// Unlock releases the byte-range lock.
func Unlock(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
