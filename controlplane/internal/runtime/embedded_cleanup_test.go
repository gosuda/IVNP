package noderuntime

import (
	"bytes"
	"testing"
)

func TestEmbeddedCloseWipesFactoryRouterKey(t *testing.T) {
	cfg := daemonTestConfig(t)
	cfg.Tunnel.Enabled = true
	controller, err := NewController(cfg, ControllerOptions{Embedded: true, SocketRuntime: new(recordingSockets)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Error(err)
		}
	})
	retained := controller.destinationFactory.staticPrivate
	var zero [32]byte
	if len(retained) != len(zero) || bytes.Equal(retained, zero[:]) {
		t.Fatal("factory did not retain the initialized router key")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, zero[:]) {
		t.Fatal("closed router retains a nonzero factory key copy")
	}
}
