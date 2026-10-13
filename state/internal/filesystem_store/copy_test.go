package filesystemstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateCopyTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCopyPrivateBoundedIfExistsBoundsAndMissing(t *testing.T) {
	dir := privateCopyTestDir(t)
	src := filepath.Join(dir, "source")
	dst := filepath.Join(dir, "target")
	if err := WriteAtomic(dst, []byte("old"), 0o600, 64); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, 4); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(dst); err != nil || string(content) != "old" {
		t.Fatalf("missing source changed destination: %q, %v", content, err)
	}
	if err := WriteAtomic(src, []byte("12345"), 0o600, 64); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize source = %v, want ErrTooLarge", err)
	}
	if content, err := os.ReadFile(dst); err != nil || string(content) != "old" {
		t.Fatalf("oversize source changed destination: %q, %v", content, err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, 5); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(dst)
	if err != nil || string(content) != "12345" {
		t.Fatalf("copy at size bound = %q, %v", content, err)
	}
	destination, _, err := OpenRegular(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(destination); err != nil {
		t.Fatalf("destination privacy: %v", err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(src, filepath.Join(dir, "absent", "target"), 5); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing destination directory = %v", err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("negative bound = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= 6 && entry.Name()[:6] == ".ivnp-" {
			t.Fatalf("temporary copy left behind: %s", entry.Name())
		}
	}
}

func TestCopyPrivateBoundedIfExistsRejectsSymlinkAndDirectory(t *testing.T) {
	dir := privateCopyTestDir(t)
	src := filepath.Join(dir, "source")
	link := filepath.Join(dir, "link")
	dst := filepath.Join(dir, "destination")
	if err := WriteAtomic(src, []byte("safe"), 0o600, 64); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(src, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := CopyPrivateBoundedIfExists(link, dst, 10); err == nil {
		t.Fatal("symlink source was accepted")
	}
	directory := filepath.Join(dir, "directory")
	if err := EnsurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	if err := CopyPrivateBoundedIfExists(directory, dst, 10); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("directory source = %v, want ErrInvalidFile", err)
	}
	if content, err := os.ReadFile(dst); err != nil || string(content) != "old" {
		t.Fatalf("rejected source changed destination: %q, %v", content, err)
	}
}

func TestCopyPrivateBoundedIfExistsDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := privateCopyTestDir(t)
	src := filepath.Join(dir, "source")
	victim := filepath.Join(dir, "victim")
	dst := filepath.Join(dir, "destination")
	if err := WriteAtomic(src, []byte("copy"), 0o600, 64); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(victim, []byte("untouched"), 0o600, 64); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, dst); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := CopyPrivateBoundedIfExists(src, dst, 4); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "untouched" {
		t.Fatalf("symlink victim overwritten: %q, %v", content, err)
	}
	if info, err := os.Lstat(dst); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("destination remains a symlink: %v, %v", info, err)
	}
}
