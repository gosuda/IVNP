package garlicecies

// The ring covers both sides of the highest authenticated index. The extra
// position is the consumed high-water tag, which separates history and lookahead.
type receiveTag struct {
	tag     [ratchetTagLen]byte
	index   uint32
	present bool
}

func (s *tagSet) recordInbound(tag [ratchetTagLen]byte, index uint16, lookahead int) {
	if len(s.receiveTags) == 0 {
		s.receiveTags = make([]receiveTag, 2*lookahead+1)
	}
	s.receiveTags[uint32(index)%uint32(len(s.receiveTags))] = receiveTag{tag: tag, index: uint32(index), present: true}
}

func (s *tagSet) forgetInbound(tag [ratchetTagLen]byte, index uint16) {
	if s == nil || len(s.receiveTags) == 0 {
		return
	}
	slot := &s.receiveTags[uint32(index)%uint32(len(s.receiveTags))]
	if slot.present && slot.index == uint32(index) && slot.tag == tag {
		*slot = receiveTag{}
	}
}

func (s *tagSet) inboundAt(index uint32) (receiveTag, bool) {
	if len(s.receiveTags) == 0 {
		return receiveTag{}, false
	}
	slot := s.receiveTags[index%uint32(len(s.receiveTags))]
	return slot, slot.present && slot.index == index
}

func (m *RatchetManager) pruneInboundBeforeLocked(set *tagSet, floor uint32) {
	for set.receiveFloor < floor {
		if slot, present := set.inboundAt(set.receiveFloor); present {
			m.removeInboundTagLocked(slot.tag)
		}
		set.receiveFloor++
	}
}

func (m *RatchetManager) removeTagSetTagsLocked(set *tagSet) {
	for index := range set.receiveTags {
		if slot := set.receiveTags[index]; slot.present {
			m.removeInboundTagLocked(slot.tag)
		}
	}
}

// Calculate eviction without changing either tag index. Under a tight budget,
// skipped historical packets lose priority to the future receive window.
func (m *RatchetManager) inboundPruneFloorLocked(set *tagSet, highWater uint32, needed int) (uint32, error) {
	floor := set.receiveFloor
	minimum := uint32(0)
	if highWater > uint32(m.config.TagLookahead)+1 {
		minimum = highWater - uint32(m.config.TagLookahead) - 1
	}
	available := m.config.MaxInboundTags - len(m.inbound)
	for floor < minimum {
		if _, present := set.inboundAt(floor); present {
			available++
		}
		floor++
	}
	for available < needed && floor < highWater {
		if _, present := set.inboundAt(floor); present {
			available++
		}
		floor++
	}
	if available < needed {
		return 0, ErrRatchetTagExhausted
	}
	return floor, nil
}

func (m *RatchetManager) advanceInboundWindowLocked(set *tagSet, received uint32) error {
	highWater := max(set.receivedHighWater, received+1)
	target := min(uint32(65536), highWater+uint32(m.config.TagLookahead))
	needed := 0
	if target > set.next {
		needed = int(target - set.next)
	}
	floor, err := m.inboundPruneFloorLocked(set, highWater, needed)
	if err != nil {
		return err
	}
	if needed > len(m.windowScratch) {
		return ErrRatchetTagExhausted
	}
	preview := *set
	preview.receiveTags = nil
	preview.previous = nil
	defer releaseTagSet(&preview)
	entries := m.windowScratch[:0]
	defer func() {
		for index := range entries {
			delete(m.windowTags, entries[index].tag)
		}
		clear(entries)
	}()
	for preview.next < target {
		entry, err := preview.deriveEntry()
		if err != nil {
			return err
		}
		entry.set = set
		_, inboundCollision := m.inbound[entry.tag]
		_, pendingCollision := m.pending[entry.tag]
		_, stagedCollision := m.windowTags[entry.tag]
		if inboundCollision || pendingCollision || stagedCollision {
			clear(entry.key[:])
			return ErrRatchet
		}
		m.windowTags[entry.tag] = struct{}{}
		entries = append(entries, entry)
	}
	m.pruneInboundBeforeLocked(set, floor)
	set.tagChain, set.keyChain, set.next = preview.tagChain, preview.keyChain, preview.next
	set.receivedHighWater = highWater
	for _, entry := range entries {
		m.addInboundTagLocked(entry)
	}
	return nil
}
