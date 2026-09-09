package node

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"gosuda.org/ivnp/controlplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

func embeddedTestConfiguration() state.ConfigurationOperating {
	cfg := state.ConfigurationDefaultOperating()
	cfg.DataDir, cfg.StateDir, cfg.StatePath, cfg.KeyPath = "", "", "", ""
	cfg.NTCP2.Enabled, cfg.SSU2.Enabled, cfg.Reseed.Enabled = true, false, false
	cfg.NTCP2.Bind = state.ConfigurationEndpoint{Host: "127.0.0.1"}
	cfg.SAM.Enabled, cfg.AddressBook.Enabled = false, false
	return cfg
}

func TestEmbeddedRouterConstructionContextDoesNotOwnLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	router, err := NewEmbeddedRouter(ctx, embeddedTestConfiguration(), controlplane.ControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	cancel()
	if status := router.controller.Status(); !status.Running {
		t.Fatalf("constructor cancellation stopped router: %+v", status)
	}
	if destinations, err := router.controller.ListDestinations(t.Context()); err != nil || len(destinations) != 0 {
		t.Fatalf("implicit destinations = %v, %v", destinations, err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := router.WaitReady(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("readiness after Close = %v", err)
	}
}

func TestEmbeddedRouterPersistentIdentityAndExclusiveOwnership(t *testing.T) {
	cfg := embeddedTestConfiguration()
	cfg.StateDir = t.TempDir()
	cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
	cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
	first, err := NewEmbeddedRouter(t.Context(), cfg, controlplane.ControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	hash := first.Hash()
	if _, err := NewEmbeddedRouter(t.Context(), cfg, controlplane.ControllerOptions{}); !errors.Is(err, controlplane.ErrStateConflict) {
		t.Fatalf("concurrent persistent owner = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewEmbeddedRouter(t.Context(), cfg, controlplane.ControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Hash() != hash {
		t.Fatal("persistent restart changed router identity")
	}
}

func TestEmbeddedRouterRejectsNamedStateWithoutChangingIdentity(t *testing.T) {
	cfg := embeddedTestConfiguration()
	cfg.StateDir = t.TempDir()
	cfg.StatePath = filepath.Join(cfg.StateDir, "router.state")
	cfg.KeyPath = filepath.Join(cfg.StateDir, "router.keys")
	store, err := state.SecureStateNewStore(cfg.StatePath, cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bundle, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.ReleaseSensitive()
	local, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	private := make([]byte, local.PrivateEncodedLen())
	n, err := local.MarshalPrivateTo(private)
	if err != nil {
		t.Fatal(err)
	}
	bundle.DestinationPrivate["service"] = private[:n]
	if err := store.Save(bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEmbeddedRouter(t.Context(), cfg, controlplane.ControllerOptions{}); !errors.Is(err, controlplane.ErrStateConflict) {
		t.Fatalf("named state admission = %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.ReleaseSensitive()
	if loaded.Router.Hash != bundle.Router.Hash || len(loaded.DestinationPrivate) != 1 {
		t.Fatal("rejected open changed named state")
	}
}
