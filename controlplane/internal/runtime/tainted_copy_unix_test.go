//go:build !windows

package noderuntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaintedCopyRejectsWritableAuxiliarySources(t *testing.T) {
	for _, name := range []string{"netdb.routers", "netdb.responders", "addressbook.json"} {
		t.Run(name, func(t *testing.T) {
			cfg := daemonTestConfig(t)
			path := filepath.Join(filepath.Dir(cfg.StatePath), name)
			if name == "addressbook.json" {
				cfg.AddressBook.StatePath = path
				cfg.AddressBook.MaxFileBytes = 1 << 20
			}
			if err := os.WriteFile(path, []byte("untrusted"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
			controller, err := NewController(cfg, ControllerOptions{TaintedCopy: true, SocketRuntime: new(recordingSockets)})
			if controller != nil {
				_ = controller.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "failed to copy") {
				t.Fatalf("tainted mode accepted writable source %q: %v", name, err)
			}
		})
	}
}
