package tunnel

import (
	"errors"
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestOwnedPoolsRejectCrossDestinationCircuits(t *testing.T) {
	var alice, bob foundation.Hash
	alice[0], bob[0] = 1, 2
	alicePool := NewOwnedPool(alice, 2)
	bobPool := NewOwnedPool(bob, 2)
	entry := Entry{ID: 1, Owner: alice, Direction: Outbound, Expires: 100}
	if err := alicePool.Add(entry, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := bobPool.Select(Outbound, 1); ok {
		t.Fatal("empty destination pool selected another destination circuit")
	}
	if err := bobPool.Add(entry, 1); !errors.Is(err, ErrPoolOwner) {
		t.Fatalf("cross-owner Add() = %v", err)
	}
	if got, ok := alicePool.Select(Outbound, 1); !ok || got.Owner != alice {
		t.Fatalf("owner selection = %#v, %t", got, ok)
	}
}

func TestRuntimeRetainsCreatorOwnerOnInstalledCircuit(t *testing.T) {
	var owner foundation.Hash
	owner[0] = 9
	runtime := NewRuntime(RuntimeConfig{Now: func() uint64 { return 1 }})
	if err := runtime.RegisterOutbound(OutboundCircuit{ID: 7, Owner: owner, NextTunnelID: 8, ExpiresAt: 100}); err != nil {
		t.Fatal(err)
	}
	got, ok := runtime.CircuitOwner(7)
	if !ok || got != owner {
		t.Fatalf("CircuitOwner() = %x, %t", got, ok)
	}
	runtime.RemoveCircuit(7)
	if _, ok := runtime.CircuitOwner(7); ok {
		t.Fatal("removed owner circuit remains registered")
	}
}
