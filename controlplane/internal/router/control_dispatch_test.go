package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"

	controlplanenetdb "gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

var errControlHandlerWithoutDeadline = errors.New("control handler has no deadline")

func newControlServiceForTest(t *testing.T, database *controlplanenetdb.Database, sinks ControlSinks) (*dataplane.RouterService, *ControlDispatcher) {
	t.Helper()
	queue, err := NewControlDispatcher(database, sinks, ControlDispatcherConfig{QueueLimits: dataplane.RouterDefaultControlQueueLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Error(err)
		}
	})
	return dataplane.RouterNewService(dataplane.RouterSinks{Control: queue}), queue
}

func TestServiceAcknowledgesSuccessfulDatabaseStoreOnce(t *testing.T) {
	const now = uint64(1_000)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	payload, key := testEncryptedDatabaseStore(t, 77, 9)
	replies := 0
	service, queue := newControlServiceForTest(t, database, ControlSinks{DatabaseStoreReply: func(_ context.Context, gateway foundation.Hash, tunnelID uint32, status foundation.I2NPDeliveryStatusMessage) error {
		replies++
		if gateway[0] != 1 || tunnelID != 9 {
			t.Errorf("reply route = %x/%d, want gateway 1/tunnel 9", gateway, tunnelID)
		}
		if status.MessageID != 77 || status.Timestamp != now {
			t.Errorf("reply status = %#v, want token 77 at %d", status, now)
		}
		if _, found := database.EncryptedLeaseSet(key); !found {
			t.Error("reply was sent before DatabaseStore admission")
		}
		return nil
	}})
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 1, Expiration: now},
		Payload: payload,
	}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := service.HandleI2NP(message, now, false); !errors.Is(err, dataplane.RouterErrDuplicate) {
		t.Fatalf("replayed database store = %v, want ErrDuplicate", err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if replies != 1 {
		t.Fatalf("database store replies = %d, want 1", replies)
	}
}

func TestServiceRejectsInvalidDatabaseStoreWithoutAcknowledging(t *testing.T) {
	const now = uint64(1_000)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	payload, key := testEncryptedDatabaseStore(t, 78, 9)
	payload[len(payload)-1] ^= 1
	replies, floods := 0, 0
	service, queue := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreFlood: func(dataplane.RouterI2NPSource, foundation.I2NPDatabaseStoreMessage) error {
			floods++
			return nil
		},
		DatabaseStoreReply: func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error {
			replies++
			return nil
		},
	})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 3, Expiration: now}, Payload: payload}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); !errors.Is(err, controlplanenetdb.ErrInvalidSignature) {
		t.Fatalf("invalid store result = %v", err)
	}
	if replies != 0 || floods != 0 {
		t.Fatalf("invalid store replies/floods = %d/%d, want 0/0", replies, floods)
	}
	if _, found := database.EncryptedLeaseSet(key); found {
		t.Fatal("invalid store entered NetDB")
	}
}

func TestServiceClassifiesLookupLeaseSetAsUnpublished(t *testing.T) {
	const now = uint64(2_000)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	payload, key := testEncryptedDatabaseStore(t, 79, 9)
	service, queue := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreExpected: func(foundation.I2NPDatabaseStoreMessage) bool { return true },
		DatabaseStoreReply:    func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error { return nil },
	})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 4, Expiration: now}, Payload: payload}
	if err := service.HandleI2NP(message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, published := database.StoredPublishedLeaseSet(key, now); published {
		t.Fatal("lookup-derived LeaseSet was exposed as a floodfill publication")
	}
	if _, retained := database.EncryptedLeaseSet(key); !retained {
		t.Fatal("lookup-derived LeaseSet was not retained for local routing")
	}
}

func TestServiceFloodsAdmittedReplyRequestBeforeAcknowledgement(t *testing.T) {
	const now = uint64(2_000)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	payload, key := testEncryptedDatabaseStore(t, 81, 12)
	peer := foundation.Hash{7}
	order := make([]string, 0, 2)
	service, queue := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreFlood: func(source dataplane.RouterI2NPSource, store foundation.I2NPDatabaseStoreMessage) error {
			if source != (dataplane.RouterI2NPSource{Peer: peer, Direct: true}) || store.Key != key || store.ReplyToken != 81 {
				t.Errorf("flood source/store = %#v / %#v", source, store)
			}
			if _, found := database.EncryptedLeaseSet(key); !found {
				t.Error("store was flooded before admission")
			}
			order = append(order, "flood")
			return nil
		},
		DatabaseStoreReply: func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error {
			order = append(order, "ack")
			return nil
		},
	})
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 2, Expiration: now}, Payload: payload}
	if err := service.HandleI2NPFrom(peer, message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "flood" || order[1] != "ack" {
		t.Fatalf("store handling order = %v", order)
	}
}

func TestFloodfillServiceAcceptsJavaLeaseSet2Corpus(t *testing.T) {
	corpus, err := os.ReadFile("../../../foundation/internal/netdb/testdata/java-fda1ced/database-store-ls2-over-4k.corpus")
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 4 {
		t.Fatal("Java LeaseSet2 corpus is truncated")
	}
	length := int(binary.BigEndian.Uint32(corpus[:4]))
	if length > len(corpus)-4 {
		t.Fatal("Java LeaseSet2 corpus record is truncated")
	}
	message, used, err := foundation.I2NPParse(corpus[4 : 4+length])
	if err != nil || used != length {
		t.Fatalf("parse Java DatabaseStore frame = %d/%d, %v", used, length, err)
	}
	store, err := foundation.I2NPParseDatabaseStore(message.Payload)
	if err != nil {
		t.Fatal(err)
	}
	leaseSet, err := foundation.NetworkDatabaseParseLeaseSet2(store.Data)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(leaseSet.Header.Published)*1000 + 1_000
	payload, err := foundation.NetworkDatabaseMarshalDatabaseStore(store.Key, store.Type, store.Data, 77, foundation.Hash{1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	message.Header.ID = 99
	message.Header.Expiration = now + 60_000
	message.Payload = payload
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	flooded := false
	service, queue := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreFlood: func(dataplane.RouterI2NPSource, foundation.I2NPDatabaseStoreMessage) error {
			flooded = true
			return nil
		},
		DatabaseStoreReply: func(context.Context, foundation.Hash, uint32, foundation.I2NPDeliveryStatusMessage) error { return nil },
	})
	if err = service.HandleI2NPFrom(foundation.Hash{2}, message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found := database.LeaseSet2(store.Key); !found || !flooded {
		t.Fatalf("Java LeaseSet2 admission/flood = %t/%t", found, flooded)
	}
}

func testEncryptedDatabaseStore(t *testing.T, replyToken, replyTunnelID uint32) ([]byte, foundation.Hash) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := make([]byte, 2+len(public)+4+2+2+2+foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	binary.BigEndian.PutUint16(unsigned[:2], uint16(foundation.SigningRedDSASHA512Ed25519))
	copy(unsigned[2:], public)
	binary.BigEndian.PutUint32(unsigned[2+len(public):2+len(public)+4], 1)
	binary.BigEndian.PutUint16(unsigned[2+len(public)+4:2+len(public)+6], 600)
	offset := 2 + len(public) + 4 + 2 + 2
	binary.BigEndian.PutUint16(unsigned[offset:offset+2], foundation.NetworkDatabaseMinEncryptedLeaseSetDataBytes)
	unsigned[offset+2] = 7
	signed := append([]byte{byte(foundation.I2NPStoreEncryptedLeaseSet)}, unsigned...)
	leaseSet := append(unsigned, ed25519.Sign(private, signed)...)
	parsed, err := foundation.NetworkDatabaseParseEncryptedLeaseSet(leaseSet)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.Hash()
	payload := make([]byte, 37+36+len(leaseSet))
	copy(payload[:32], key[:])
	payload[32] = byte(foundation.I2NPStoreEncryptedLeaseSet)
	binary.BigEndian.PutUint32(payload[33:37], replyToken)
	binary.BigEndian.PutUint32(payload[37:41], replyTunnelID)
	payload[41] = 1
	copy(payload[73:], leaseSet)
	return payload, key
}

func TestServiceRoutesGarlicUnwrappedOutboundBuildReplyOnly(t *testing.T) {
	const now = uint64(1_000_000)
	reply := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPOutboundTunnelBuildReply, ID: 7, Expiration: now + 1},
		Payload: make([]byte, 1+foundation.I2NPShortBuildRecordLen),
	}
	reply.Payload[0] = 1
	calls := 0
	service, queue := newControlServiceForTest(t, nil, ControlSinks{OutboundTunnelBuildReply: func(message foundation.I2NPMessage) error {
		calls++
		if message.Header.Type != reply.Header.Type || message.Header.ID != reply.Header.ID || len(message.Payload) != len(reply.Payload) {
			t.Errorf("routed reply = %#v", message)
		}
		return nil
	}})
	if err := service.HandleI2NP(reply, now, false); !errors.Is(err, dataplane.RouterErrUnhandledI2NP) {
		t.Fatalf("direct reply error = %v, want ErrUnhandledI2NP", err)
	}
	cloves := []dataplane.GarlicClove{{
		Delivery:   dataplane.GarlicDelivery{Type: dataplane.GarlicDeliveryLocal},
		Message:    reply,
		ID:         8,
		Expiration: now + 1,
	}}
	size, err := dataplane.GarlicCloveSetEncodedLen(cloves)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, size)
	if _, err = dataplane.GarlicMarshalCloveSetTo(encoded, cloves, 9, now+1); err != nil {
		t.Fatal(err)
	}
	set, err := dataplane.GarlicParseCloveSet(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.HandleGarlicCloveSet(set, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("garlic reply calls = %d, want 1", calls)
	}
}

func TestServiceQueuesAuthenticatedShortBuild(t *testing.T) {
	const now = uint64(1_000_000)
	message := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 9, Expiration: now + 1},
		Payload: append([]byte{1}, make([]byte, foundation.I2NPShortBuildRecordLen)...),
	}
	calls := 0
	peer := foundation.Hash{7}
	service, queue := newControlServiceForTest(t, nil, ControlSinks{TunnelBuild: func(_ context.Context, source dataplane.RouterI2NPSource, records foundation.I2NPBuildRecords, got foundation.I2NPMessage) error {
		calls++
		if source != (dataplane.RouterI2NPSource{Peer: peer, Direct: true}) || records.Count != 1 || got.Header != message.Header {
			t.Errorf("short build hand-off = %#v, %#v, %#v", source, records, got)
		}
		return nil
	}})
	if err := service.HandleI2NPFrom(peer, message, now, false); err != nil {
		t.Fatal(err)
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("short build calls = %d, want 1", calls)
	}
}

func TestServiceRejectsMissingStoreAcknowledgementRouteBeforeReplay(t *testing.T) {
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	service, queue := newControlServiceForTest(t, database, ControlSinks{})
	payload, _ := testEncryptedDatabaseStore(t, 77, 9)
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 1, Expiration: 1_000}, Payload: payload}
	for attempt := 0; attempt < 2; attempt++ {
		if err := service.HandleI2NP(message, 1_000, false); !errors.Is(err, dataplane.RouterErrUnhandledI2NP) {
			t.Fatalf("unroutable store attempt %d = %v", attempt, err)
		}
	}
	if err := queue.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type privacyTestNetwork struct {
	replies chan foundation.I2NPMessage
}

func (*privacyTestNetwork) Send(context.Context, controlplanenetdb.RouterRef, foundation.I2NPMessage) error {
	return nil
}
func (*privacyTestNetwork) DatabaseLookupReplyRoute() (foundation.Hash, uint32, bool) {
	return foundation.Hash{9}, 0, false
}
func (n *privacyTestNetwork) SendNetDBReply(_ context.Context, _ foundation.Hash, _ uint32, message foundation.I2NPMessage) error {
	message.Payload = append([]byte(nil), message.Payload...)
	n.replies <- message
	return nil
}

func TestQueuedLookupStoreRemainsPrivateAfterRequestExpiry(t *testing.T) {
	const now, deadline = uint64(2_000), uint64(2_100)
	database := controlplanenetdb.NewDatabase(foundation.Hash{}, controlplanenetdb.DefaultBucketCapacity)
	if err := database.AdmitRouterInfo(dataPlaneFloodfill(t), true, now); err != nil {
		t.Fatal(err)
	}
	network := &privacyTestNetwork{replies: make(chan foundation.I2NPMessage, 1)}
	requests, err := controlplanenetdb.NewRequestManager(database, network, network, controlplanenetdb.RequestManagerConfig{
		Capacity: 1, MaxCandidates: 1, TimeoutMillis: deadline - now, Now: func() uint64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := requests.Close(); err != nil {
			t.Error(err)
		}
	})
	payload, key := testEncryptedDatabaseStore(t, 77, 9)
	store, err := foundation.I2NPParseDatabaseStore(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = foundation.NetworkDatabaseMarshalDatabaseStore(key, store.Type, store.Data, 0, foundation.Hash{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := requests.LookupLeaseSet(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !requests.ExpectsDatabaseStore(store) {
		t.Fatal("lookup did not remain pending")
	}
	blocked, release := make(chan struct{}), make(chan struct{})
	service, control := newControlServiceForTest(t, database, ControlSinks{
		DatabaseStoreExpected:  requests.ExpectsDatabaseStore,
		DatabaseStoreCompleted: requests.HandleDatabaseStore,
		TunnelBuild: func(ctx context.Context, _ dataplane.RouterI2NPSource, _ foundation.I2NPBuildRecords, _ foundation.I2NPMessage) error {
			close(blocked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	build := foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 1, Expiration: now},
		Payload: append([]byte{1}, make([]byte, foundation.I2NPShortBuildRecordLen)...),
	}
	if err = service.HandleI2NP(build, now, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("control queue did not block")
	}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseStore, ID: 2, Expiration: now}, Payload: payload}
	if err = service.HandleI2NPFrom(foundation.Hash{7}, message, now, true); err != nil {
		t.Fatal(err)
	}
	if removed := requests.Expire(deadline); removed != 1 {
		t.Fatalf("expired requests = %d", removed)
	}
	if outcome := <-result; !errors.Is(outcome.Err, controlplanenetdb.ErrRequestExpired) {
		t.Fatalf("lookup outcome = %v", outcome.Err)
	}
	if requests.ExpectsDatabaseStore(store) {
		t.Fatal("expired lookup still classified as pending")
	}
	close(release)
	if err = control.WaitIdle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found := database.EncryptedLeaseSet(key); !found {
		t.Fatal("verified reply was not retained for private routing")
	}
	if _, _, published := database.StoredPublishedLeaseSet(key, deadline); published {
		t.Fatal("queued private reply became a public LeaseSet after request expiry")
	}
	responder, err := controlplanenetdb.NewLookupResponder(controlplanenetdb.LookupResponderConfig{
		Database: database, Sender: network, Local: foundation.Hash{8},
		Now: func() uint64 { return deadline }, Random: func() uint32 { return 3 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = responder.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := responder.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = responder.Enqueue(foundation.I2NPDatabaseLookupMessage{Key: key, From: foundation.Hash{9}, Flags: uint8(controlplanenetdb.LeaseSetLookup) << 2}); err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-network.replies:
		if reply.Header.Type != foundation.I2NPDatabaseSearchReply {
			t.Fatalf("lookup responder exposed private Store as type %d", reply.Header.Type)
		}
		search, err := foundation.I2NPParseDatabaseSearchReply(reply.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if search.Key != key {
			t.Fatalf("search reply key = %x, want %x", search.Key, key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup responder did not answer")
	}
}

func TestControlHandlerDeadlineAllowsFollowingWorkToComplete(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "default", want: 30 * time.Second},
		{name: "configured", configured: 17 * time.Second, want: 17 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				remaining := make(chan time.Duration, 2)
				expired, following := make(chan error, 1), make(chan error, 1)
				control, err := NewControlDispatcher(nil, ControlSinks{TunnelBuild: func(ctx context.Context, _ dataplane.RouterI2NPSource, _ foundation.I2NPBuildRecords, message foundation.I2NPMessage) error {
					deadline, ok := ctx.Deadline()
					if !ok {
						remaining <- 0
						return errControlHandlerWithoutDeadline
					}
					remaining <- time.Until(deadline)
					if message.Header.ID == 1 {
						<-ctx.Done()
						expired <- ctx.Err()
						return ctx.Err()
					}
					following <- ctx.Err()
					return nil
				}}, ControlDispatcherConfig{QueueLimits: dataplane.RouterDefaultControlQueueLimits(), HandlerTimeout: tc.configured})
				if err != nil {
					t.Fatal(err)
				}
				if err = control.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := control.Close(); err != nil {
						t.Error(err)
					}
				})
				message := dataplane.RouterControlMessage{Message: foundation.I2NPMessage{
					Header:  foundation.I2NPHeader{Type: foundation.I2NPShortTunnelBuild, ID: 1, Expiration: 1_000},
					Payload: append([]byte{1}, make([]byte, foundation.I2NPShortBuildRecordLen)...),
				}}
				if err = control.Enqueue(message); err != nil {
					t.Fatal(err)
				}
				message.Message.Header.ID = 2
				if err = control.Enqueue(message); err != nil {
					t.Fatal(err)
				}
				if got := <-remaining; got != tc.want {
					t.Fatalf("handler deadline in %s, want %s", got, tc.want)
				}
				if err := <-expired; !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("handler timeout = %v", err)
				}
				if got := <-remaining; got != tc.want {
					t.Fatalf("following handler deadline in %s, want full %s", got, tc.want)
				}
				if err := <-following; err != nil {
					t.Fatalf("following work inherited canceled context: %v", err)
				}
				if err := control.Barrier(t.Context()); err != nil {
					t.Fatalf("timed-out handler blocked barrier: %v", err)
				}
			})
		})
	}
}

func TestControlDispatcherRejectsNegativeHandlerTimeout(t *testing.T) {
	if control, err := NewControlDispatcher(nil, ControlSinks{}, ControlDispatcherConfig{QueueLimits: dataplane.RouterDefaultControlQueueLimits(), HandlerTimeout: -time.Second}); err == nil {
		if closeErr := control.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("negative control handler timeout was accepted")
	}
}
