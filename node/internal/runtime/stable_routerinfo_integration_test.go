//go:build integration

package noderuntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

const (
	stableRouterInfoHash      = "mIyKvlqkIKXM9Gts7hp1PGI62kA01S-h8wWwxdOq47Q="
	stormyCloudReseedEndpoint = "https://reseed.stormycloud.org/i2pseeds.su3?netid=2"
)

// TestAcquireStableRouterInfo bootstraps IVNP through the configured HTTPS
// reseed, removes any reseed copy of the pinned identity, and performs an exact
// NetDB RouterInfo lookup. The output is consumed by the separate SSU2 actual
// test so discovery and transport interoperability retain distinct failures.
func TestAcquireStableRouterInfo(t *testing.T) {
	if os.Getenv("IVNP_STABLE_ROUTERINFO_ACQUIRE") != "1" {
		t.Skip("set IVNP_STABLE_ROUTERINFO_ACQUIRE=1 to run the live NetDB lookup")
	}
	output := os.Getenv("IVNP_STABLE_ROUTER_INFO_OUTPUT")
	if output == "" {
		t.Fatal("IVNP_STABLE_ROUTER_INFO_OUTPUT must name the acquired RouterInfo path")
	}

	base := t.TempDir()
	configuration := fmt.Sprintf(`[paths]
data_dir = %s

[router]
version = 0.9.70

[reseed]
enabled = true
required = true
endpoints = %s
timeout = 45s

[tunnel]
enabled = true
hops = 1
exploratory_inbound_target = 1
exploratory_outbound_target = 1
exploratory_pool_capacity = 2
client_inbound_target = 1
client_outbound_target = 1
client_pool_capacity = 2
build_pending_capacity = 8
lifetime = 10m
renew_before = 30s
maintenance_interval = 1s

[ntcp2]
enabled = false

[sam]
enabled = false

[addressbook]
enabled = false
subscriptions =

[metrics]
enabled = false

[log]
level = info
format = text
`, base, stormyCloudReseedEndpoint)
	config, err := state.ConfigurationParseOperating(configuration, filepath.Join(base, "ivnp.conf"))
	if err != nil {
		t.Fatalf("parse RouterInfo acquisition configuration: %v", err)
	}
	daemon, err := New(config, Options{})
	if err != nil {
		t.Fatalf("create RouterInfo acquisition daemon: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	if err = daemon.Start(ctx); err != nil {
		cancel()
		_ = daemon.Close()
		t.Fatalf("bootstrap IVNP NetDB: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = daemon.Close()
		if waitErr := daemon.Wait(); waitErr != nil {
			t.Errorf("wait for RouterInfo acquisition daemon: %v", waitErr)
		}
	})

	target := decodeStableRouterInfoHash(t)
	// A reseed archive is only a bootstrap sample. Force the proof to use the
	// iterative NetDB request path even when that sample happens to contain the
	// target identity.
	daemon.database.Routers().Remove(target)
	result, err := daemon.requests.LookupRouterInfo(ctx, target)
	if err != nil {
		t.Fatalf("start exact RouterInfo lookup: %v", err)
	}
	select {
	case lookup := <-result:
		if lookup.Err != nil {
			t.Fatalf("exact RouterInfo lookup: %v", lookup.Err)
		}
	case <-ctx.Done():
		t.Fatalf("exact RouterInfo lookup: %v", ctx.Err())
	}
	ref, found := daemon.database.Routers().Get(target)
	if !found {
		t.Fatal("exact RouterInfo lookup completed without the pinned identity")
	}
	wire := ref.Info.Bytes()
	if len(wire) == 0 {
		t.Fatal("exact RouterInfo lookup returned an empty RouterInfo")
	}
	if err = os.WriteFile(output, wire, 0o600); err != nil {
		t.Fatalf("write acquired RouterInfo: %v", err)
	}
}

func decodeStableRouterInfoHash(t *testing.T) foundation.Hash {
	t.Helper()
	raw, err := foundation.DecodeI2PBase64([]byte(stableRouterInfoHash))
	if err != nil || len(raw) != foundation.HashLength {
		t.Fatalf("decode pinned stable router hash: length=%d err=%v", len(raw), err)
	}
	var hash foundation.Hash
	copy(hash[:], raw)
	return hash
}
