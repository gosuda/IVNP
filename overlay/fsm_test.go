package overlay

import (
	"errors"
	"testing"
	"time"
)

func TestFSMHappyPath(t *testing.T) {
	f := newConnFSM()
	if err := f.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := f.ContactFound(); err != nil {
		t.Fatal(err)
	}
	state, err := f.Commit(RouteDirect)
	if err != nil || state != ConnActiveIVNP {
		t.Fatalf("commit: %v %v", state, err)
	}
	if err := f.PathLost(false); err != nil {
		t.Fatal(err)
	}
	// No delivery was possible, so resume begins a fresh bounded setup and
	// frees the winner slot.
	if err := f.BeginResume(false); err != nil {
		t.Fatal(err)
	}
	state, err = f.Commit(RouteNativeI2P)
	if err != nil || state != ConnActiveI2P {
		t.Fatalf("recommit: %v %v", state, err)
	}
	if err := f.Revoke(); err != nil {
		t.Fatal(err)
	}
	if err := f.Drained(); err != nil {
		t.Fatal(err)
	}
	if f.State() != ConnClosed || !f.State().Terminal() {
		t.Fatalf("state %v", f.State())
	}
}

func TestFSMWinnerCAS(t *testing.T) {
	f := newConnFSM()
	f.Begin()
	f.ContactFound()
	state, err := f.Commit(RouteDirect)
	if err != nil || state != ConnActiveIVNP {
		t.Fatalf("first commit: %v %v", state, err)
	}
	// A late success must not transition again — and must not report an
	// active state the caller would bind a session onto.
	f.state = ConnConnecting
	state, err = f.Commit(RouteNativeI2P)
	if err == nil || state == ConnActiveI2P {
		t.Fatalf("late commit won: %v %v", state, err)
	}
}

func TestFSMDeliveryUncertainty(t *testing.T) {
	f := newConnFSM()
	f.Begin()
	f.ContactFound()
	f.Commit(RouteDirect)
	if err := f.PathLost(true); err != nil {
		t.Fatal(err)
	}
	// Delivery was possible and no contract exists: a fresh retry is refused
	// and the FSM parks at reconnect_required.
	if err := f.BeginResume(false); err != nil {
		t.Fatal(err)
	}
	if f.State() != ConnReconnectRequired {
		t.Fatalf("state %v", f.State())
	}
	if err := f.BeginResume(true); err == nil {
		t.Fatal("resume attempt accepted from reconnect_required")
	}
}

func TestFSMResumePath(t *testing.T) {
	f := newConnFSM()
	f.Begin()
	f.ContactFound()
	f.Commit(RouteDirect)
	f.PathLost(true)
	if err := f.BeginResume(true); err != nil {
		t.Fatal(err)
	}
	if err := f.ResumeCommitted(RouteNativeI2P); err != nil {
		t.Fatal(err)
	}
	if f.State() != ConnActiveI2P {
		t.Fatalf("state %v", f.State())
	}
}

func TestFSMIllegalTransitions(t *testing.T) {
	f := newConnFSM()
	if err := f.ContactFound(); err == nil {
		t.Fatalf("contact before begin accepted")
	}
	if _, err := f.Commit(RouteDirect); err == nil {
		t.Fatalf("commit before connecting accepted")
	}
	f.Begin()
	if err := f.Drained(); err == nil {
		t.Fatalf("drained before draining accepted")
	}
}

func TestFloorTracker(t *testing.T) {
	tracker := NewFloorTracker()
	key := FloorKey{Endpoint: EndpointID{1}, Fabric: PublicFastFabricID, Realm: PublicFastRealmID, Port: 47001, Format: 1}
	expiry := time.Now().Add(time.Hour).Unix()
	d1 := [32]byte{1}
	d2 := [32]byte{2}
	if err := tracker.Admit(key, 0, 5, d1, expiry); err != nil {
		t.Fatal(err)
	}
	if got := tracker.Check(key, 0, 5, d1); got != FloorReplay {
		t.Fatalf("replay: %v", got)
	}
	if err := tracker.Admit(key, 0, 4, d2, expiry); !errors.Is(err, CodeRecordStale) {
		t.Fatalf("rollback admitted: %v", err)
	}
	if err := tracker.Admit(key, 0, 5, d2, expiry); !errors.Is(err, CodeEquivocation) {
		t.Fatalf("equivocation admitted: %v", err)
	}
	if err := tracker.Admit(key, 0, 6, d2, expiry); err != nil {
		t.Fatalf("advance rejected: %v", err)
	}
	if err := tracker.Admit(key, 1, 0, d1, expiry); err != nil {
		t.Fatalf("incarnation advance rejected: %v", err)
	}
	// An unverified candidate never advances the floor.
	if got := tracker.Check(key, 2, 0, d1); got != FloorAdvance {
		t.Fatalf("check verdict: %v", got)
	}
	if err := tracker.Admit(key, 0, 7, d1, expiry); !errors.Is(err, CodeRecordStale) {
		t.Fatalf("stale record admitted after incarnation bump: %v", err)
	}
}

// TestFloorExpiryAndCap: an already-expired floor is never admitted; expired
// entries are reclaimed only when the table is full, and a table of live
// floors fails closed.
func TestFloorExpiryAndCap(t *testing.T) {
	tracker := NewFloorTracker()
	key := FloorKey{Endpoint: EndpointID{1}, Fabric: PublicFastFabricID, Realm: PublicFastRealmID, Port: 47001, Format: 1}
	if err := tracker.Admit(key, 0, 5, [32]byte{1}, time.Now().Unix()-1); !errors.Is(err, CodeRecordStale) {
		t.Fatalf("expired floor admitted: %v", err)
	}
	expiry := time.Now().Add(time.Hour).Unix()
	for i := 0; i < maxFloors; i++ {
		k := key
		k.Endpoint[0] = byte(i)
		k.Endpoint[1] = byte(i >> 8)
		k.Endpoint[2] = byte(i >> 16)
		if err := tracker.Admit(k, 0, 1, [32]byte{1}, expiry); err != nil {
			t.Fatalf("floor %d rejected: %v", i, err)
		}
	}
	if err := tracker.Admit(FloorKey{Endpoint: EndpointID{9}, Port: 1}, 0, 1, [32]byte{2}, expiry); !errors.Is(err, CodeRateLimited) {
		t.Fatalf("full live table admitted a floor: %v", err)
	}
}

// TestFloorExpirySweep: under capacity pressure, expired entries are swept to
// admit a new live floor.
func TestFloorExpirySweep(t *testing.T) {
	tracker := NewFloorTracker()
	key := FloorKey{Endpoint: EndpointID{1}, Fabric: PublicFastFabricID, Realm: PublicFastRealmID, Port: 47001, Format: 1}
	past := time.Now().Unix() - 1
	expiry := time.Now().Add(time.Hour).Unix()
	// Seed live entries, then force their NotAfter into the past to simulate
	// records whose lifetime has elapsed since admission.
	for i := 0; i < maxFloors; i++ {
		k := key
		k.Endpoint[0] = byte(i)
		k.Endpoint[1] = byte(i >> 8)
		k.Endpoint[2] = byte(i >> 16)
		if err := tracker.Admit(k, 0, 1, [32]byte{1}, expiry); err != nil {
			t.Fatalf("floor %d rejected: %v", i, err)
		}
	}
	tracker.mu.Lock()
	for k := range tracker.floors {
		pos := tracker.floors[k]
		pos.notAfter = past
		tracker.floors[k] = pos
	}
	tracker.mu.Unlock()
	fresh := FloorKey{Endpoint: EndpointID{9}, Port: 1}
	if err := tracker.Admit(fresh, 0, 1, [32]byte{2}, expiry); err != nil {
		t.Fatalf("live floor rejected after sweeping expired entries: %v", err)
	}
	if got := tracker.Check(fresh, 0, 1, [32]byte{2}); got != FloorReplay {
		t.Fatalf("swept-in floor verdict %v", got)
	}
}
