package tunnel

import (
	"testing"

	"gosuda.org/ivnp/foundation"
)

func TestBuildReservationsExcludePendingPeersUntilTerminalRelease(t *testing.T) {
	reservations := NewBuildReservations()
	hops := []ShortBuildHop{{Router: foundation.Hash{1}}, {Router: foundation.Hash{2}}}
	first := reservations.Reserve(hops)
	if first == nil {
		t.Fatal("initial path reservation failed")
	}
	if reservations.Available(hops[0].Router) || reservations.Reserve(hops) != nil {
		t.Fatal("pending path peers remained available to a sibling pool")
	}
	first.Release()
	first.Release()
	if !reservations.Available(hops[0].Router) {
		t.Fatal("terminal release did not return peer to selection")
	}
	second := reservations.Reserve(hops)
	if second == nil {
		t.Fatal("released path could not be reserved again")
	}
	second.Release()
}
