package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/networking/internal/netdb"
	"gosuda.org/ivnp/observability"
)

func TestLocalRouterInfoPublishesRouterLifecycleState(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	database := netdb.NewDatabase(foundation.Hash{}, 4)
	clock := fixedClock{now: time.UnixMilli(123456789)}
	metrics := observability.NewRegistry()
	database.SetMetrics(metrics)
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{
		Local:         local,
		Database:      database,
		Clock:         clock,
		RouterVersion: "0.1.0",
		Metrics:       metrics,
		Options: []MappingOption{
			{Key: "z", Value: "last"},
			{Key: "a", Value: "first"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if owner.Hash() != local.Hash || owner.Snapshot().Bytes() != nil {
		t.Fatal("new local RouterInfo has incorrect initial state")
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{
		Transport: "NTCP2",
		Cost:      3,
		Options: []MappingOption{
			{Key: "s", Value: "static"},
			{Key: "host", Value: "127.0.0.1"},
			{Key: "port", Value: "12345"},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	owner.SetReachability(ReachabilityReachable)
	if metrics.Snapshot().Bootstrap.RouterReachable != 1 {
		t.Fatal("reachable transition was not published")
	}
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	info := owner.Snapshot()
	if info.Hash() != local.Hash || info.Published != uint64(clock.now.UnixMilli()) {
		t.Fatalf("snapshot identity/timestamp = %x / %d", info.Hash(), info.Published)
	}
	if valid, err := info.Verify(); err != nil || !valid {
		t.Fatalf("snapshot signature = %t, %v", valid, err)
	}
	if got := mappingValue(t, info.Options, "caps"); got != "KR" {
		t.Fatalf("reachable caps = %q, want KR", got)
	}
	if got := mappingValue(t, info.Options, "netId"); got != "2" {
		t.Fatalf("netId = %q, want 2", got)
	}
	if got := mappingValue(t, info.Options, "router.version"); got != "0.1.0" {
		t.Fatalf("router.version = %q", got)
	}
	if database.Routers().Len() != 1 {
		t.Fatalf("published RouterInfo was not admitted to netdb: len = %d", database.Routers().Len())
	}
	if metrics.Snapshot().NetDB.Routers != 1 {
		t.Fatalf("verified remote router gauge = %d", metrics.Snapshot().NetDB.Routers)
	}

	owner.SetReachability(ReachabilityFirewalled)
	if metrics.Snapshot().Bootstrap.RouterReachable != 0 {
		t.Fatal("firewalled transition was not published")
	}
	if owner.Snapshot().Bytes() != nil {
		t.Fatal("reachability change retained stale advertisement")
	}
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := mappingValue(t, owner.Snapshot().Options, "caps"); got != "KU" {
		t.Fatalf("firewalled caps = %q, want KU", got)
	}
}

func TestLocalRouterInfoAdvertisesConfiguredFloodfillWithReachabilityState(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local, Floodfill: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if netdb.IsFloodfill(owner.Snapshot()) {
		t.Fatal("unknown-reachability router advertised floodfill capability")
	}
	owner.SetReachability(ReachabilityFirewalled)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info := owner.Snapshot(); !netdb.IsFloodfill(info) || mappingValue(t, info.Options, "caps") != "KfU" {
		t.Fatalf("firewalled floodfill caps = %q, want KfU", mappingValue(t, info.Options, "caps"))
	}
	owner.SetReachability(ReachabilityReachable)
	if err = owner.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	info := owner.Snapshot()
	if !netdb.IsFloodfill(info) {
		t.Fatal("reachable configured router omitted floodfill capability")
	}
	if got := mappingValue(t, info.Options, "caps"); got != "KfR" {
		t.Fatalf("floodfill caps = %q, want KfR", got)
	}
}

func TestLocalRouterBandwidthCapabilityMatchesJavaThresholds(t *testing.T) {
	for _, test := range []struct {
		bytesPerSecond int
		want           byte
	}{
		{0, 'K'},
		{12 * 1024, 'L'},
		{48 * 1024, 'L'},
		{49 * 1024, 'M'},
		{65 * 1024, 'N'},
		{129 * 1024, 'O'},
		{257 * 1024, 'P'},
		{2001 * 1024, 'X'},
	} {
		if got := localRouterBandwidthCapability(test.bytesPerSecond); got != test.want {
			t.Fatalf("localRouterBandwidthCapability(%d) = %q, want %q", test.bytesPerSecond, got, test.want)
		}
	}
}

func TestLocalRouterInfoRejectsMalformedOptionsAndCanceledPublication(t *testing.T) {
	local, err := foundation.GenerateLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewLocalRouterInfo(LocalRouterInfoConfig{
		Local:   local,
		Options: []MappingOption{{Key: "caps", Value: "R"}},
	}); !errors.Is(err, ErrLocalRouterInfoOptions) {
		t.Fatalf("caller caps option error = %v, want ErrLocalRouterInfoOptions", err)
	}
	owner, err := NewLocalRouterInfo(LocalRouterInfoConfig{Local: local})
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ReplaceAddresses([]PublishedAddress{{Transport: ""}}); !errors.Is(err, ErrLocalRouterInfoOptions) {
		t.Fatalf("empty transport error = %v, want ErrLocalRouterInfoOptions", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = owner.Publish(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled publication error = %v, want context.Canceled", err)
	}
	if owner.Snapshot().Bytes() != nil {
		t.Fatal("canceled publication created a snapshot")
	}
}

func mappingValue(t *testing.T, mapping foundation.Mapping, key string) string {
	t.Helper()
	iterator := mapping.Iterator()
	for {
		currentKey, value, ok, err := iterator.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("mapping does not contain %q", key)
		}
		if string(currentKey) == key {
			return string(value)
		}
	}
}
