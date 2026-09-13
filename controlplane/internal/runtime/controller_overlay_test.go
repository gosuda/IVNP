package noderuntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/foundation"
)

// PublishOwnedDestinationOptions must carry verified extension entries into
// the signed record itself: the stored LS2 — the same bytes the bridge's
// publication driver reports and ReadBack observes — exposes them through
// its canonical options mapping.
func TestPublishOwnedDestinationOptionsCarriesExtensionEntries(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	cfg := daemonTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	cfg.Tunnel.Enabled = true
	cfg.NTCP2.Enabled = false
	cfg.Tunnel.MaintenanceInterval = time.Hour
	d, err := NewController(cfg, ControllerOptions{Transport: network.transport()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.Close()
		_ = d.Wait()
	})
	if err := d.DestroyDestination(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateDestination(context.Background(), "public", DestinationPolicy{Kind: DestinationPublicLS2}); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime := d.clientRuntimeSnapshot()[0]
	hash := runtime.local.IdentityHash()
	now = uint64(d.clock.Now().UnixMilli())
	if err := runtime.pool.Add(tunnel.Entry{
		ID: 1, Direction: tunnel.Inbound, Gateway: foundation.Hash{9},
		GatewayTunnelID: 77, Expires: now + 60_000, Owner: hash,
	}, now); err != nil {
		t.Fatal(err)
	}
	options := []foundation.MappingEntry{
		{Key: []byte("x-ivnp.v"), Value: []byte("1")},
		{Key: []byte("x-ov.t"), Value: []byte("ivnp-tls")},
	}
	raw, _, err := d.PublishOwnedDestinationOptions(context.Background(), hash, options)
	if err != nil {
		t.Fatal(err)
	}
	assertLS2Options(t, raw, options)

	// ReadBack resolves the same stored record through the verified lookup
	// path.
	readBack, encrypted, err := d.LookupDestinationRecord(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		t.Fatal("public destination reported as encrypted")
	}
	assertLS2Options(t, readBack, options)

	// A cleared option set restores the canonical empty mapping.
	cleared, _, err := d.PublishOwnedDestinationOptions(context.Background(), hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertLS2Options(t, cleared, nil)

	// Unowned hashes are rejected; nothing may publish under a foreign key.
	if _, _, err := d.PublishOwnedDestinationOptions(context.Background(), foundation.Hash{255}, options); !errors.Is(err, errOverlayNoOwnedDestination) {
		t.Fatalf("unowned publish error = %v", err)
	}
}

func assertLS2Options(t *testing.T, raw []byte, want []foundation.MappingEntry) {
	t.Helper()
	set, err := foundation.NetworkDatabaseParseLeaseSet2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := set.Verify(); err != nil || !ok {
		t.Fatalf("stored LS2 verification = %t, %v", ok, err)
	}
	got := make(map[string]string)
	it := set.Options.Iterator()
	for {
		key, value, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got[string(key)] = string(value)
	}
	if len(got) != len(want) {
		t.Fatalf("stored options = %v, want %v", got, want)
	}
	for _, entry := range want {
		if got[string(entry.Key)] != string(entry.Value) {
			t.Fatalf("stored options = %v, want key %q", got, entry.Key)
		}
	}
}
