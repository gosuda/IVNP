package router

import (
	"encoding/binary"
	"errors"
	"testing"
)

func garlicPacket(n uint64) []byte {
	var packet [32]byte
	binary.LittleEndian.PutUint64(packet[:], n)
	return packet[:]
}

func TestGarlicPreauthWorkBudgetBoundary(t *testing.T) {
	a := newGarlicPreauthAdmission()
	peer := [32]byte{1}
	if err := a.admit(peer, garlicPacket(0), garlicPreauthBurstUnits, 1_000); err != nil {
		t.Fatal(err)
	}
	a.finish()
	if err := a.admit(peer, garlicPacket(1), 1, 1_000); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("budget exhausted: %v", err)
	}
	if err := a.admit(peer, garlicPacket(2), 1, 1_016); err != nil {
		t.Fatalf("budget failed to refill: %v", err)
	}
	a.finish()
	if err := a.admit(peer, garlicPacket(3), garlicPreauthBurstUnits+1, 1_000_000); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("over-capacity reservation: %v", err)
	}
}

func TestGarlicPreauthReplayBeforeBudget(t *testing.T) {
	a := newGarlicPreauthAdmission()
	peer := [32]byte{1}
	packet := garlicPacket(9)
	if err := a.admit(peer, packet, garlicPreauthBurstUnits, 1_000); err != nil {
		t.Fatal(err)
	}
	a.finish()
	if err := a.admit([32]byte{2}, packet, 1, 1_000); !errors.Is(err, ErrGarlicPreauthReplay) {
		t.Fatalf("identical ciphertext from a different source: %v", err)
	}
}

func TestGarlicPreauthConcurrentLimit(t *testing.T) {
	a := newGarlicPreauthAdmission()
	for index := uint64(0); index < garlicPreauthMaxConcurrent; index++ {
		if err := a.admit([32]byte{1}, garlicPacket(index), 1, 1000); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.admit([32]byte{1}, garlicPacket(3), 1, 1000); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("in-flight admission: %v", err)
	}
	a.finish()
	if err := a.admit([32]byte{1}, garlicPacket(3), 1, 1000); err != nil {
		t.Fatalf("released admission: %v", err)
	}
	a.finish()
	a.finish()
}

func TestGarlicPreauthPerSourceAndGlobalLimits(t *testing.T) {
	a := newGarlicPreauthAdmission()
	peer1, peer2 := [32]byte{1}, [32]byte{2}
	if err := a.admit(peer1, garlicPacket(0), garlicPreauthBurstUnits, 1_000); err != nil {
		t.Fatal(err)
	}
	a.finish()
	if err := a.admit(peer2, garlicPacket(1), 1, 1_000); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("global exhaustion despite fresh peer: %v", err)
	}
	if err := a.admit(peer2, garlicPacket(2), 2, 1_016); err != nil {
		t.Fatalf("global refill: %v", err)
	}
	a.finish()
	if err := a.admit(peer1, garlicPacket(3), 2, 1_016); !errors.Is(err, ErrGarlicPreauthLimit) {
		t.Fatalf("per-peer exhaustion: %v", err)
	}
}

func TestGarlicPreauthPeerAndReplayStateBounded(t *testing.T) {
	a := newGarlicPreauthAdmission()
	for index := uint64(0); index < garlicPreauthReplaySlots+4; index++ {
		var peer [32]byte
		binary.LittleEndian.PutUint64(peer[:], index)
		if err := a.admit(peer, garlicPacket(index), 1, 1_000+index*100); err != nil {
			t.Fatal(err)
		}
		a.finish()
	}
	if got := len(a.peers); got != garlicPreauthMaxPeers {
		t.Fatalf("peer budget entries = %d, max %d", got, garlicPreauthMaxPeers)
	}
	if got := len(a.seen); got > garlicPreauthReplaySlots {
		t.Fatalf("replay entries = %d, max %d", got, garlicPreauthReplaySlots)
	}
}
