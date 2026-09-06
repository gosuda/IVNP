package filesystemstore

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateFileRejectsPublicACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	file, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(file); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("public ACL accepted: %v", err)
	}
}

func TestWindowsPrivateFileRejectsHardLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	file, err := CreatePrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(file); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("hard-linked secret accepted: %v", err)
	}
}

func TestWindowsPrivateDirectoryRejectsJunction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := EnsurePrivateDir(target); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	if err := EnsurePrivateDir(junction); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("directory junction accepted: %v", err)
	}
}

func TestWindowsReadRejectsAlternateDataStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+":secret", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(path+":secret", 8); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("alternate stream accepted: %v", err)
	}
}

func TestWindowsAtomicReplacementRetainsPrivateACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	for _, value := range []string{"first", "second"} {
		if err := WriteAtomic(path, []byte(value), 0o600, 32); err != nil {
			t.Fatal(err)
		}
		file, _, err := OpenRegular(path)
		if err != nil {
			t.Fatal(err)
		}
		permissionErr := ValidatePrivateFile(file)
		data, readErr := ReadBoundedFile(file, 32)
		file.Close()
		if permissionErr != nil || readErr != nil || string(data) != value {
			t.Fatalf("replacement: data=%q read=%v permissions=%v", data, readErr, permissionErr)
		}
	}
}
