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
	if status := router.Default().Status(); !status.Running {
		t.Fatalf("constructor cancellation stopped router: %+v", status)
	}
	if destinations, err := router.Default().ListDestinations(t.Context()); err != nil || len(destinations) != 0 {
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

func TestEmbeddedRouterExportAndImportRouterInfo(t *testing.T) {
	ctx := t.Context()
	cfgA := embeddedTestConfiguration()
	cfgA.NTCP2.Bind = state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 20001}
	cfgA.NTCP2.Advertised = state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 20001}
	routerA, err := NewEmbeddedRouter(ctx, cfgA, controlplane.ControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer routerA.Close()

	cfgB := embeddedTestConfiguration()
	cfgB.NTCP2.Bind = state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 20002}
	cfgB.NTCP2.Advertised = state.ConfigurationEndpoint{Host: "127.0.0.1", Port: 20002}
	routerB, err := NewEmbeddedRouter(ctx, cfgB, controlplane.ControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer routerB.Close()

	rawA, err := routerA.ExportLocalRouterInfo("")
	if err != nil || len(rawA) == 0 {
		t.Fatalf("ExportLocalRouterInfo failed: %v", err)
	}

	hashA, err := routerB.ImportRouterInfo(ctx, "", rawA)
	if err != nil {
		t.Fatalf("ImportRouterInfo failed: %v", err)
	}
	if hashA != routerA.Hash() {
		t.Fatalf("imported hash = %v, want %v", hashA, routerA.Hash())
	}

	peerWire, ok := routerB.ExportPeerRouterInfo("", hashA)
	if !ok || len(peerWire) == 0 {
		t.Fatal("ExportPeerRouterInfo could not find newly imported peer")
	}
}

// TestExampleExportAndImportRouterInfoPeering demonstrates how two nodes in a private
// network exchange signed RouterInfo wire bytes without public reseed servers.
func TestExampleExportAndImportRouterInfoPeering(t *testing.T) {
	t.Skip("Demonstrative example showing manual peer exchange across private networks without reseed")

	ctx := context.Background()

	// 1. Node A boots on a dedicated private network (e.g. netId 77) without reseed endpoints.
	var routerA *EmbeddedRouter
	// routerA, _ = NewEmbeddedRouter(ctx, privateNetConfig, options)
	// defer routerA.Close()

	// 2. Node A exports its self-signed RouterInfo wire bytes.
	exportedRouterInfo, err := routerA.ExportLocalRouterInfo("corp-mesh")
	if err != nil {
		t.Fatalf("failed to export local router info: %v", err)
	}

	// 3. Node A publishes exportedRouterInfo to an out-of-band discovery service
	// (such as etcd, Consul, Kubernetes ConfigMap, or a management RPC).
	// outOfBandStore.Put("peers/node-a", exportedRouterInfo)

	// 4. Node B boots on the same private network (netId 77).
	var routerB *EmbeddedRouter
	// routerB, _ = NewEmbeddedRouter(ctx, privateNetConfig, options)
	// defer routerB.Close()

	// 5. Node B fetches Node A's wire bytes from the discovery service and imports it.
	// nodeABytes := outOfBandStore.Get("peers/node-a")
	peerHash, err := routerB.ImportRouterInfo(ctx, "corp-mesh", exportedRouterInfo)
	if err != nil {
		t.Fatalf("failed to import peer router info: %v", err)
	}

	// 6. Node B now has Node A in its NetDB, allowing outbound dials to Node A's destinations.
	t.Logf("Successfully imported peer into corp-mesh NetDB with router hash: %s", peerHash)
}
