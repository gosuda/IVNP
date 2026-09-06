package ssu2

import (
	"bytes"
	"testing"
)

func TestACKTrackerMergesAndOrdersRanges(t *testing.T) {
	var tracker ACKTracker
	for _, packet := range []uint32{5, 7, 6, 2} {
		tracker.Observe(packet)
	}
	ranges := tracker.RangesInto(make([]ACKRange, 0, 4))
	if len(ranges) != 2 || ranges[0] != (ACKRange{Start: 5, End: 7}) || ranges[1] != (ACKRange{Start: 2, End: 2}) {
		t.Fatalf("ranges = %#v", ranges)
	}
}

func TestACKRangesWireRoundTrip(t *testing.T) {
	ranges := []ACKRange{{Start: 8, End: 10}, {Start: 5, End: 6}, {Start: 0, End: 2}}
	encoded, err := MarshalACKRanges(nil, ranges)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 10, 2, 1, 2, 2, 3}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded ACK = %x, want %x", encoded, want)
	}
	decoded, err := ParseACKRanges(encoded, make([]ACKRange, 0, MaxACKRanges))
	if err != nil || len(decoded) != len(ranges) {
		t.Fatalf("decoded ACK = %#v, %v", decoded, err)
	}
	for index := range ranges {
		if decoded[index] != ranges[index] {
			t.Fatalf("decoded range %d = %#v, want %#v", index, decoded[index], ranges[index])
		}
	}
}

func TestACKRangesEncodeLongRunAndRejectMalformed(t *testing.T) {
	encoded, err := MarshalACKRanges(nil, []ACKRange{{Start: 0, End: 600}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseACKRanges(encoded, make([]ACKRange, 0, MaxACKRanges))
	if err != nil || len(decoded) != 3 || decoded[0] != (ACKRange{Start: 345, End: 600}) || decoded[1] != (ACKRange{Start: 90, End: 344}) || decoded[2] != (ACKRange{Start: 0, End: 89}) {
		t.Fatalf("long ACK = %#v, %v", decoded, err)
	}
	if _, err = MarshalACKRanges(nil, []ACKRange{{Start: 1, End: 2}, {Start: 2, End: 2}}); err == nil {
		t.Fatal("overlapping ranges were accepted")
	}
	if _, err = ParseACKRanges([]byte{0, 0, 0, 1, 0, 0, 0}, make([]ACKRange, 0, 2)); err == nil {
		t.Fatal("zero ACK range was accepted")
	}
}
