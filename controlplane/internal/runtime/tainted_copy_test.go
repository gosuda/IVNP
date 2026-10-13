package noderuntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gosuda.org/ivnp/controlplane/internal/netdb"
)

func TestNewTaintedRejectsUnsafeNetDBSnapshot(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	original, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	tainted, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets), TaintedCopy: true})
	if err != nil {
		t.Fatalf("valid tainted copy: %v", err)
	}
	if err := tainted.Close(); err != nil {
		t.Fatal(err)
	}

	snapshot := filepath.Join(cfg.StateDir, "netdb.routers")
	if err := os.Remove(snapshot); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(cfg.StatePath, snapshot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets), TaintedCopy: true}); err == nil {
		t.Fatal("tainted mode accepted a symlinked optional NetDB snapshot")
	}

	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(snapshot, netdb.RouterSnapshotMaxBytes(cfg.NetDB.BucketCapacity)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets), TaintedCopy: true}); err == nil {
		t.Fatal("tainted mode accepted an oversized optional NetDB snapshot")
	}
}
