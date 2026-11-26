package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicDoesNotFollowPlantedTempSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "i2pseeds.su3")
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := writeFileAtomic(path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	if got, err := os.ReadFile(victim); err != nil || string(got) != "victim" {
		t.Fatalf("symlink target = %q, %v; want it untouched", got, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "payload" {
		t.Fatalf("written file = %q, %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("written path mode = %v, %v; want a regular file", info, err)
	}
}

func TestWriteFileAtomicReplacesSymlinkAtDestination(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "reseed-rsa.crt")
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := writeFileAtomic(path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	if got, err := os.ReadFile(victim); err != nil || string(got) != "victim" {
		t.Fatalf("symlink target = %q, %v; want it untouched", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("written path mode = %v, %v; want a regular file", info, err)
	}
}
