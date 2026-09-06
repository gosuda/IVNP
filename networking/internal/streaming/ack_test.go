package streaming

import (
	"encoding/binary"
	"testing"
)

func TestAcknowledgementRetainsNACKedSequencesAndWraps(t *testing.T) {
	state := NewState(1, 2)
	state.Status = Open
	for range 3 {
		if _, ok := state.OnSend(false); !ok {
			t.Fatal("send blocked")
		}
	}
	nacks := make([]byte, 4)
	binary.BigEndian.PutUint32(nacks, 1)
	state.OnPacket(Packet{ReceiveStreamID: 1, AckThrough: 2, NACKs: nacks})
	if state.inflightCount != 1 || state.inflight[0] != 1 {
		t.Fatalf("inflight = %v", state.inflight[:state.inflightCount])
	}
	state.lastReceived = ^uint32(0) - 1
	state.haveReceived = true
	state.OnPacket(Packet{ReceiveStreamID: 1, Sequence: 1})
	if state.lastReceived != 1 {
		t.Fatalf("wrap sequence = %d", state.lastReceived)
	}
}

func TestNoACKPacketRequestsACKWithoutAcknowledgingOutboundData(t *testing.T) {
	state := NewState(1, 2)
	state.Status = Open
	for range InitialWindow {
		if _, ok := state.OnSend(false); !ok {
			t.Fatal("send blocked before filling window")
		}
	}
	action := state.OnPacket(Packet{ReceiveStreamID: 1, Sequence: 1, AckThrough: 2, Flags: FlagNoACK})
	if !action.SendACK {
		t.Fatal("NO_ACK data packet was not acknowledged")
	}
	if state.CanSend() {
		t.Fatal("NO_ACK packet incorrectly released the outbound window")
	}
	action = state.OnPacket(Packet{ReceiveStreamID: 1, AckThrough: 2})
	if action.SendACK {
		t.Fatal("pure ACK requested another ACK")
	}
	if !state.CanSend() {
		t.Fatal("pure ACK did not release the outbound window")
	}
}

func TestInitialSynchronizeDoesNotAcknowledgeOutboundData(t *testing.T) {
	state := NewState(1, 2)
	state.Status = Open
	for range InitialWindow {
		if _, ok := state.OnSend(false); !ok {
			t.Fatal("send blocked before filling window")
		}
	}
	action := state.OnPacket(Packet{ReceiveStreamID: 1, Flags: FlagSynchronize})
	if !action.SendACK || state.CanSend() {
		t.Fatalf("initial SYN action=%#v canSend=%t", action, state.CanSend())
	}
}
