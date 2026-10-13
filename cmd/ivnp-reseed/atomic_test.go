package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicDoesNotFollowPredictableSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	victim := filepath.Join(dir, "victim")
	const protected = "do not overwrite"
	if err := os.WriteFile(victim, []byte(protected), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	const replacement = "new state"
	if err := writeFileAtomic(path, []byte(replacement), 0600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != protected {
		t.Fatalf("symlink target changed: data=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != replacement {
		t.Fatalf("new state: data=%q err=%v", got, err)
	}
	if info, err := os.Lstat(path+".tmp"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("predictable symlink changed: info=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("temporary file leaked: entries=%v err=%v", entries, err)
	}
}

func TestWriteFileAtomicReplacesExistingFileAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("replacement"), 0644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement: data=%q err=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("mode: info=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file leaked: entries=%v err=%v", entries, err)
	}
}

func TestWriteFileAtomicCleansUpAfterRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(path, "keep")
	if err := os.WriteFile(sentinel, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new state"), 0600); err == nil {
		t.Fatal("expected rename over nonempty directory to fail")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "original" {
		t.Fatalf("original state changed: data=%q err=%v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("temporary file leaked: entries=%v err=%v", entries, err)
	}
}
