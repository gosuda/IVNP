package noderuntime

import (
	"context"
	"errors"
	"testing"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

type replyDialRecorder struct {
	sessions map[foundation.Hash]bool
	sent     []foundation.Hash
}

func (r *replyDialRecorder) Send(_ context.Context, peer foundation.Hash, _ foundation.I2NPMessage) error {
	r.sent = append(r.sent, peer)
	return nil
}

func (r *replyDialRecorder) HasSession(peer foundation.Hash) bool { return r.sessions[peer] }

func TestDirectNetDBRepliesNeverDialSenderChosenRouters(t *testing.T) {
	recorder := &replyDialRecorder{sessions: map[foundation.Hash]bool{}}
	sender := daemonReplySender{sender: recorder, now: func() uint64 { return 1_000 }}
	gateway := foundation.Hash{7}
	status := foundation.I2NPDeliveryStatusMessage{MessageID: 9, Timestamp: 1_000}

	err := sender.SendStatus(t.Context(), gateway, 0, status)
	if !errors.Is(err, dataplane.RouterErrSessionUnavailable) {
		t.Fatalf("direct ack without session error = %v, want %v", err, dataplane.RouterErrSessionUnavailable)
	}
	lookupReply := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseSearchReply, ID: 1, Expiration: 2_000}}
	if err := sender.SendNetDBReply(t.Context(), gateway, 0, lookupReply); !errors.Is(err, dataplane.RouterErrSessionUnavailable) {
		t.Fatalf("direct lookup reply without session error = %v, want %v", err, dataplane.RouterErrSessionUnavailable)
	}
	if len(recorder.sent) != 0 {
		t.Fatalf("direct replies reached the dialing transport for %d routers without a session", len(recorder.sent))
	}

	recorder.sessions[gateway] = true
	if err := sender.SendStatus(t.Context(), gateway, 0, status); err != nil {
		t.Fatalf("direct ack over established session: %v", err)
	}
	if len(recorder.sent) != 1 || recorder.sent[0] != gateway {
		t.Fatalf("established-session ack sent to %v, want [%v]", recorder.sent, gateway)
	}
}

func TestDirectNetDBRepliesRequireSessionAwareTransport(t *testing.T) {
	sender := daemonReplySender{sender: replySendOnly{}, now: func() uint64 { return 1_000 }}
	err := sender.SendStatus(t.Context(), foundation.Hash{7}, 0, foundation.I2NPDeliveryStatusMessage{MessageID: 9})
	if !errors.Is(err, dataplane.RouterErrSessionUnavailable) {
		t.Fatalf("direct ack through session-unaware transport error = %v, want %v", err, dataplane.RouterErrSessionUnavailable)
	}
}

var errTestDirectReplySessionUnaware = errors.New("session-unaware transport must not be used for direct replies")

type replySendOnly struct{}

func (replySendOnly) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return errTestDirectReplySessionUnaware
}

func TestPeerAddressPolicyFollowsNetworkProfile(t *testing.T) {
	tests := []struct {
		profile state.ConfigurationNetworkProfile
		public  bool
	}{
		{state.ConfigurationNetworkProfilePublic, true},
		{"", true},
		{state.ConfigurationNetworkProfileDedicated, false},
		{state.ConfigurationNetworkProfileDirect, false},
	}
	for _, test := range tests {
		if got := requirePublicPeerAddresses(test.profile); got != test.public {
			t.Errorf("requirePublicPeerAddresses(%q) = %t, want %t", test.profile, got, test.public)
		}
	}
}
