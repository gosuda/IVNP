package ssu2

import (
	"errors"
	"testing"
)

func TestBlockIteratorOrderingAndBounds(t *testing.T) {
	payload := []byte{BlockDateTime, 0, 4, 0, 0, 0, 1, BlockPadding, 0, 0}
	iterator := NewBlockIterator(payload)
	if _, ok, err := iterator.Next(); err != nil || !ok {
		t.Fatalf("datetime = %t, %v", ok, err)
	}
	if _, ok, err := iterator.Next(); err != nil || !ok {
		t.Fatalf("padding = %t, %v", ok, err)
	}
	if _, ok, err := iterator.Next(); err != nil || ok {
		t.Fatalf("end = %t, %v", ok, err)
	}
	bad := NewBlockIterator([]byte{BlockFirstFragment, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if _, _, err := bad.Next(); !errors.Is(err, ErrPacketLength) {
		t.Fatalf("first fragment bound = %v", err)
	}
}
