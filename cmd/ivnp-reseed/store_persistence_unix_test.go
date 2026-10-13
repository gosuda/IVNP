//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerCacheLoadRejectsSymlinkAndPublicFile(t *testing.T) {
	_, raw := testCacheRouterInfo(t, uint64(time.Now().UnixMilli()))
	path := writeTestPeerCache(t, []PeerRecord{{Raw: raw}})
	link := filepath.Join(t.TempDir(), "cache-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	store := NewPeerStore()
	if err := store.LoadFromFile(link, 2); err == nil || store.Len() != 0 {
		t.Fatalf("symlink load: error = %v, peers = %d", err, store.Len())
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadFromFile(path, 2); err == nil || store.Len() != 0 {
		t.Fatalf("public file load: error = %v, peers = %d", err, store.Len())
	}
}
