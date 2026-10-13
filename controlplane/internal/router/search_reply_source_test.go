package router

import (
	"context"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

func TestDatabaseSearchReplyBindsDirectTransportPeer(t *testing.T) {
	const now = uint64(1_000)

	key := foundation.Hash{9}
	responder := foundation.Hash{1}
	impostor := foundation.Hash{2}
	payload := make([]byte, 65)
	copy(payload[:32], key[:])
	copy(payload[33:], responder[:])

	var accepted []foundation.I2NPDatabaseSearchReplyMessage
	service, queue := newControlServiceForTest(t, nil, ControlSinks{
		DatabaseSearchReply: func(_ context.Context, reply foundation.I2NPDatabaseSearchReplyMessage) error {
			accepted = append(accepted, reply)
			return nil
		},
	})

	cases := []struct {
		name   string
		source dataplane.RouterI2NPSource
		want   bool
	}{
		{name: "different authenticated peer", source: dataplane.RouterI2NPSource{Peer: impostor, Direct: true}},
		{name: "missing authenticated peer", source: dataplane.RouterI2NPSource{Direct: true}},
		{name: "matching authenticated peer", source: dataplane.RouterI2NPSource{Peer: responder, Direct: true}, want: true},
		// Tunnel and decrypted one-time replies do not expose the original
		// router's authenticated identity at this handoff.
		{name: "unattributed tunnel reply", want: true},
	}

	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			message := foundation.I2NPMessage{
				Header: foundation.I2NPHeader{
					Type: foundation.I2NPDatabaseSearchReply, ID: uint32(index + 1), Expiration: now,
				},
				Payload: payload,
			}
			before := len(accepted)
			var err error
			if test.source.Direct {
				err = service.HandleI2NPFrom(test.source.Peer, message, now, false)
			} else {
				err = service.HandleI2NP(message, now, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := queue.Barrier(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := len(accepted) != before; got != test.want {
				t.Fatalf("reply delivered = %t, want %t", got, test.want)
			}
			if test.want {
				reply := accepted[len(accepted)-1]
				if reply.Key != key || reply.From != responder {
					t.Fatalf("delivered reply = %#v, want key %v from %v", reply, key, responder)
				}
			}
		})
	}
}
