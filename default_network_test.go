package ivnp

import (
	"context"
	"testing"

	"gosuda.org/ivnp/node"
)

// TestEmbeddedRouterDefaultNetworkPropagates verifies the resolved default
// network reaches the embedded core: when the configured default is not the
// first spec, Default() must still serve that network, and an unknown default
// must be rejected.
func TestEmbeddedRouterDefaultNetworkPropagates(t *testing.T) {
	cfg := multiNetTestConfig(t)
	// Two networks; make the second entry the configured default.
	cfg.DefaultNetwork = "corp"
	specs, def, err := networkSpecs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if def != "corp" {
		t.Fatalf("resolved default = %q, want corp", def)
	}
	router, err := node.NewEmbeddedRouterNetworks(context.Background(), specs, def)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	if got := router.Default(); got == nil || got != router.Context("corp") {
		t.Fatalf("Default() did not serve the configured default network: %v", got)
	}

	// An unknown default name must fail construction.
	if _, err = node.NewEmbeddedRouterNetworks(context.Background(), specs, "missing"); err == nil {
		t.Fatal("unknown default network name was accepted")
	}
}
