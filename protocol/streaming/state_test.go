package streaming

import "testing"

func TestStateTransitionsWindowAndAck(t *testing.T) {
	state := NewState(1, 2)
	if _, ok := state.OnSend(false); ok {
		t.Fatal("new stream sent before SYN")
	}
	action := state.OnPacket(Packet{Flags: FlagSynchronize, Sequence: 0})
	if state.Status != Open || !action.SendACK {
		t.Fatalf("SYN action=%#v state=%d", action, state.Status)
	}
	sequence, ok := state.OnSend(false)
	if !ok || sequence != 0 {
		t.Fatalf("send = %d, %t", sequence, ok)
	}
	state.OnPacket(Packet{Sequence: 1, AckThrough: 0})
	if state.inflightCount != 0 {
		t.Fatal("ack did not remove inflight packet")
	}
	beforeLoss := state.Window()
	state.OnLoss()
	if state.Window() >= beforeLoss {
		t.Fatal("loss did not reduce window")
	}
	closeAction := state.OnPacket(Packet{Flags: FlagClose, Sequence: 2})
	if state.Status != Closing || !closeAction.SendClose {
		t.Fatalf("close action=%#v state=%d", closeAction, state.Status)
	}
}
