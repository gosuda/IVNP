package streaming

const (
	FlagSynchronize = 0x0001
	FlagClose       = 0x0002
	FlagReset       = 0x0004
	FlagNoACK       = 0x0400
	InitialWindow   = 3
	MinWindow       = 1
	MaxWindow       = 128
	MaxResends      = 8
)

type Status uint8

const (
	New Status = iota
	Open
	Closing
	Closed
	Reset
)

type Action struct{ SendACK, SendClose, SendReset bool }

// State is a bounded streaming reliability state machine. Transport code owns
// timers and packet bytes; this type owns sequence/window transitions only.
type State struct {
	Status                        Status
	SendStreamID, ReceiveStreamID uint32
	nextSequence                  uint32
	lastReceived                  uint32
	haveReceived                  bool
	congestion                    CongestionWindow
	window                        uint16
	inflight                      [MaxWindow]uint32
	inflightCount                 uint16
}

func NewState(sendID, receiveID uint32) State {
	return State{Status: New, SendStreamID: sendID, ReceiveStreamID: receiveID, window: InitialWindow, congestion: NewCongestionWindow(InitialWindow)}
}
func (s *State) CanSend() bool { return s.Status == Open && s.inflightCount < s.Window() }
func (s *State) Window() uint16 {
	if window := s.congestion.Window(); window != 0 {
		return window
	}
	return s.window
}

func (s *State) OnSend(noACK bool) (uint32, bool) {
	if !s.CanSend() {
		return 0, false
	}
	sequence := s.nextSequence
	s.nextSequence++
	if !noACK {
		s.inflight[s.inflightCount], s.inflightCount = sequence, s.inflightCount+1
	}
	return sequence, true
}

func (s *State) OnPacket(packet Packet) Action {
	var action Action
	if s.Status == Reset || s.Status == Closed {
		return action
	}
	if s.SendStreamID != 0 && packet.ReceiveStreamID != 0 && packet.ReceiveStreamID != s.SendStreamID {
		action.SendReset = true
		return action
	}
	if packet.Flags&FlagReset != 0 {
		s.Status, action.SendReset = Reset, false
		return action
	}
	if packet.Flags&FlagSynchronize != 0 && s.Status == New {
		s.Status = Open
	}
	if packet.Flags&FlagClose != 0 {
		s.Status, action.SendClose = Closing, true
	}
	if packet.Flags&FlagNoACK == 0 {
		action.SendACK = true
	}
	if !s.haveReceived || sequenceAfter(packet.Sequence, s.lastReceived) {
		s.lastReceived, s.haveReceived = packet.Sequence, true
	}
	s.acknowledge(packet.AckThrough, packet.NACKs)
	return action
}

func (s *State) Acknowledge(through uint32) { s.acknowledge(through, nil) }

func (s *State) acknowledge(through uint32, nacks []byte) {
	write := 0
	var removed uint16
	for read := range int(s.inflightCount) {
		sequence := s.inflight[read]
		if sequenceBeforeOrEqual(sequence, through) && !containsNACK(nacks, sequence) {
			removed++
			continue
		}
		s.inflight[write] = sequence
		write++
	}
	s.inflightCount = uint16(write)
	if removed != 0 {
		s.congestion.Acknowledge(removed)
		s.window = s.congestion.Window()
	}
}

func containsNACK(nacks []byte, sequence uint32) bool {
	for len(nacks) >= 4 {
		if uint32(nacks[0])<<24|uint32(nacks[1])<<16|uint32(nacks[2])<<8|uint32(nacks[3]) == sequence {
			return true
		}
		nacks = nacks[4:]
	}
	return false
}

func sequenceAfter(left, right uint32) bool         { return int32(left-right) > 0 }
func sequenceBeforeOrEqual(left, right uint32) bool { return int32(left-right) <= 0 }

func (s *State) OnLoss() {
	s.congestion.Loss()
	s.window = s.congestion.Window()
}
