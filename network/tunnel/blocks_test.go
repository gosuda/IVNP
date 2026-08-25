package tunnel

import "testing"

func TestBlockIteratorFirstAndFollowOn(t *testing.T) {
	first := []byte{0x08, 0, 0, 0, 9, 0, 3, 1, 2, 3}
	follow := []byte{0x80 | (1 << 1) | 1, 0, 0, 0, 9, 0, 2, 4, 5}
	it := NewBlockIterator(append(first, follow...))
	one, ok, err := it.Next()
	blockIteratorFirstAndFollowOnRejected := err != nil || !ok || one.FollowOn || one.Last || one.MessageID != 9
	if !blockIteratorFirstAndFollowOnRejected {
		blockIteratorFirstAndFollowOnRejected = string(one.Data) != "\x01\x02\x03"
	}
	if blockIteratorFirstAndFollowOnRejected {
		t.Fatalf("first=%#v ok=%t err=%v", one, ok, err)
	}
	two, ok, err := it.Next()
	blockIteratorFirstAndFollowOnRejected = err != nil || !ok || !two.FollowOn || !two.Last || two.Fragment != 1
	if !blockIteratorFirstAndFollowOnRejected {
		blockIteratorFirstAndFollowOnRejected = string(two.Data) != "\x04\x05"
	}
	if blockIteratorFirstAndFollowOnRejected {
		t.Fatalf("follow=%#v ok=%t err=%v", two, ok, err)
	}
}

func TestBlockCodecRejectsZeroLengthFragments(t *testing.T) {
	for name, wire := range map[string][]byte{
		"initial":  {0, 0, 0},
		"followon": {0x80 | 1<<1 | 1, 0, 0, 0, 9, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			iterator := NewBlockIterator(wire)
			if _, ok, err := iterator.Next(); err != ErrBlock || ok {
				t.Fatalf("zero fragment parse = ok %t, err %v", ok, err)
			}
		})
	}
	for name, block := range map[string]Block{
		"initial":  {Delivery: DeliveryLocal, Last: true},
		"followon": {FollowOn: true, Fragment: 1, Last: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := blockLen(block); err != ErrGatewayBlock {
				t.Fatalf("zero fragment encode error = %v", err)
			}
			if _, err := marshalBlock(make([]byte, 16), block); err != ErrGatewayBlock {
				t.Fatalf("zero fragment marshal error = %v", err)
			}
		})
	}
}
