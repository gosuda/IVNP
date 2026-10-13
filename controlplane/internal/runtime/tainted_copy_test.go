package noderuntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gosuda.org/ivnp/state"
)

func TestTaintedCopyRejectsSymlinkedStateKeyAndParent(t *testing.T) {
	for _, name := range []string{"state", "key", "parent"} {
		t.Run(name, func(t *testing.T) {
			cfg := daemonTestConfig(t)
			store, err := state.SecureStateNewStore(cfg.StatePath, cfg.KeyPath)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			bundle.ReleaseSensitive()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if name == "parent" {
				parent := filepath.Dir(cfg.StatePath)
				alias := filepath.Join(parent, "linked")
				if err := os.Symlink(parent, alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				cfg.StatePath = filepath.Join(alias, filepath.Base(cfg.StatePath))
				cfg.KeyPath = filepath.Join(alias, filepath.Base(cfg.KeyPath))
			} else {
				path := cfg.StatePath
				if name == "key" {
					path = cfg.KeyPath
				}
				original := path + ".original"
				if err := os.Rename(path, original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			controller, err := NewController(cfg, ControllerOptions{TaintedCopy: true, SocketRuntime: new(recordingSockets)})
			if controller != nil {
				_ = controller.Close()
			}
			if err == nil {
				t.Fatal("tainted mode followed a symlinked source")
			}
		})
	}
}

func TestTaintedCopyRejectsOversizedStateBeforeInitialization(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.State.MaxBytes = 4096
	if err := os.WriteFile(cfg.StatePath, make([]byte, cfg.State.MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(cfg, ControllerOptions{TaintedCopy: true, SocketRuntime: new(recordingSockets)})
	if controller != nil {
		_ = controller.Close()
	}
	if !errors.Is(err, state.FilesystemStoreErrTooLarge) {
		t.Fatalf("oversized source = %v, want fsstore.ErrTooLarge", err)
	}
}

func TestTaintedCopyRejectsSymlinkedNetDBSnapshot(t *testing.T) {
	cfg := daemonTestConfig(t)
	dir := filepath.Dir(cfg.StatePath)
	snapshot := filepath.Join(dir, "netdb.routers")
	original := filepath.Join(dir, "original-routers")
	if err := os.WriteFile(original, []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(original, snapshot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	controller, err := NewController(cfg, ControllerOptions{TaintedCopy: true, SocketRuntime: new(recordingSockets)})
	if controller != nil {
		_ = controller.Close()
	}
	if err == nil {
		t.Fatal("tainted mode silently skipped an unsafe NetDB source")
	}
}
