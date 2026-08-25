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
