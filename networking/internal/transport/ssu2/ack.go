package ssu2

import (
	"encoding/binary"
	"errors"
	"sync"
)

const MaxACKRanges = 64

var ErrACK = errors.New("ssu2: invalid acknowledgement ranges")

type ACKRange struct{ Start, End uint32 }

// ACKTracker retains a bounded descending set of received packet ranges.
type ACKTracker struct {
	mu     sync.Mutex
	ranges [MaxACKRanges]ACKRange
	count  int
}

func (a *ACKTracker) Observe(packet uint32) {
	_ = a.ObserveNew(packet)
}

// ObserveNew records packet and reports whether it was not already acknowledged.
func (a *ACKTracker) ObserveNew(packet uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 0; i < a.count; i++ {
		r := &a.ranges[i]
		if packet >= r.Start && packet <= r.End {
			return false
		}
		if r.End != ^uint32(0) && packet == r.End+1 {
			r.End = packet
			a.merge(i)
			return true
		}
		if packet != ^uint32(0) && packet+1 == r.Start {
			r.Start = packet
			a.merge(i)
			return true
		}
		if packet > r.End {
			if a.count == MaxACKRanges {
				a.count--
			}
			copy(a.ranges[i+1:a.count+1], a.ranges[i:a.count])
			a.ranges[i] = ACKRange{Start: packet, End: packet}
			a.count++
			return true
		}
	}
	if a.count < MaxACKRanges {
		a.ranges[a.count] = ACKRange{Start: packet, End: packet}
		a.count++
		return true
	}
	return false
}

func (a *ACKTracker) merge(index int) {
	if index+1 < a.count && a.ranges[index+1].End != ^uint32(0) && a.ranges[index].Start <= a.ranges[index+1].End+1 {
		if a.ranges[index+1].Start < a.ranges[index].Start {
			a.ranges[index].Start = a.ranges[index+1].Start
		}
		copy(a.ranges[index+1:a.count-1], a.ranges[index+2:a.count])
		a.count--
	}
}

func (a *ACKTracker) RangesInto(dst []ACKRange) []ACKRange {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := min(cap(dst), a.count)
	dst = dst[:n]
	copy(dst, a.ranges[:n])
	return dst
}

// MarshalACKRanges encodes descending packet ranges as the compact SSU2 ACK
// data body, without the enclosing block header. The encoder retains at most
// MaxACKRanges wire ranges, deliberately forgetting the oldest acknowledgments.
func MarshalACKRanges(dst []byte, ranges []ACKRange) ([]byte, error) {
	if len(ranges) == 0 || !validACKRanges(ranges) {
		return nil, ErrACK
	}
	first := ranges[0]
	firstCount := min(uint64(first.End)-uint64(first.Start)+1, uint64(256))
	dst = append(dst, make([]byte, 5)...)
	binary.BigEndian.PutUint32(dst[len(dst)-5:len(dst)-1], first.End)
	dst[len(dst)-1] = byte(firstCount - 1)

	below := first.End - uint32(firstCount) + 1
	index := 0
	currentStart, currentEnd := first.Start, first.End
	if below > currentStart {
		currentEnd = below - 1
	} else {
		index++
	}
	pairs := 0
	for pairs < MaxACKRanges {
		if index >= len(ranges) {
			break
		}
		if currentEnd < currentStart || currentEnd >= below {
			currentStart, currentEnd = ranges[index].Start, ranges[index].End
		}
		if currentEnd >= below {
			return nil, ErrACK
		}
		gap := uint64(below) - uint64(currentEnd) - 1
		for gap > 255 && pairs < MaxACKRanges {
			dst = append(dst, 255, 0)
			below -= 255
			gap -= 255
			pairs++
		}
		if pairs == MaxACKRanges {
			break
		}
		count := min(uint64(currentEnd)-uint64(currentStart)+1, uint64(255))
		dst = append(dst, byte(gap), byte(count))
		pairs++
		below = currentEnd - uint32(count) + 1
		if below > currentStart {
			currentEnd = below - 1
		} else {
			index++
		}
	}
	return dst, nil
}

// ParseACKRanges decodes an SSU2 ACK data body into descending inclusive
// ranges. dst supplies bounded caller-owned storage and is never grown.
func ParseACKRanges(data []byte, dst []ACKRange) ([]ACKRange, error) {
	if len(data) < 5 || (len(data)-5)%2 != 0 {
		return nil, ErrACK
	}
	through := binary.BigEndian.Uint32(data[:4])
	firstCount := uint32(data[4])
	if firstCount > through {
		return nil, ErrACK
	}
	if cap(dst) == 0 {
		return nil, ErrACK
	}
	dst = dst[:0]
	dst = append(dst, ACKRange{Start: through - firstCount, End: through})
	below := through - firstCount
	for offset := 5; offset < len(data); offset += 2 {
		nack, ack := uint32(data[offset]), uint32(data[offset+1])
		if nack == 0 && ack == 0 {
			return nil, ErrACK
		}
		if nack > below {
			return nil, ErrACK
		}
		if ack == 0 {
			below -= nack
			continue
		}
		if nack == below {
			return nil, ErrACK
		}
		end := below - nack - 1
		if ack-1 > end || len(dst) == cap(dst) {
			return nil, ErrACK
		}
		start := end - (ack - 1)
		dst = append(dst, ACKRange{Start: start, End: end})
		below = start
	}
	return dst, nil
}

func validACKRanges(ranges []ACKRange) bool {
	for index, current := range ranges {
		if current.Start > current.End {
			return false
		}
		if index > 0 && current.End >= ranges[index-1].Start {
			return false
		}
	}
	return true
}
