package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

type packetTestInbox struct {
	messages chan *destination.ReceivedMessage
	done     chan struct{}
	once     sync.Once
}

func (s *packetTestInbox) Receive(ctx context.Context) (*destination.ReceivedMessage, error) {
	select {
	case m := <-s.messages:
		return m, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *packetTestInbox) Close() error {
	s.once.Do(func() {
		close(s.done)
		for {
			select {
			case m := <-s.messages:
				m.Release()
			default:
				return
			}
		}
	})
	return nil
}

type packetTestEndpoint struct {
	hash    Hash
	inbox   *packetTestInbox
	prepare func(context.Context, Hash) error
}

func (e *packetTestEndpoint) Hash() Hash          { return e.hash }
func (e *packetTestEndpoint) B32() string         { return foundation.B32(e.hash) }
func (e *packetTestEndpoint) Destination() []byte { return nil }
func (e *packetTestEndpoint) DialI2P(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *packetTestEndpoint) ListenI2P(context.Context, string) (net.Listener, error) {
	return nil, net.ErrClosed
}
func (e *packetTestEndpoint) SendMessage(context.Context, destination.Delivery) error {
	return nil
}
func (e *packetTestEndpoint) MarshalDatagramV1To(dst, payload []byte) (int, error) {
	return copy(dst, payload), nil
}
func (e *packetTestEndpoint) MarshalDatagramV2To(dst []byte, _ Hash, payload []byte) (int, error) {
	return copy(dst, payload), nil
}
func (e *packetTestEndpoint) MarshalDatagramV3To(dst, payload []byte) (int, error) {
	return dataplane.DatagramMarshalV3To(dst, e.hash, 3, foundation.Mapping{}, payload)
}
func (e *packetTestEndpoint) DatagramMaxPayload(uint8) (int, error) {
	return MaxSendDatagramSize, nil
}
func (e *packetTestEndpoint) Subscribe(destination.DestinationRoute, int) (destination.MessageSubscription, error) {
	return e.inbox, nil
}
func (e *packetTestEndpoint) SubscribeBounded(destination.DestinationRoute, int, int64, destination.ByteBudget) (destination.MessageSubscription, error) {
	return e.inbox, nil
}
func (e *packetTestEndpoint) PrepareDestination(ctx context.Context, target Hash) error {
	if e.prepare != nil {
		return e.prepare(ctx, target)
	}
	return nil
}
func (e *packetTestEndpoint) Close() error { return e.inbox.Close() }

func newPacketTestDestination(t *testing.T, prepare func(context.Context, Hash) error) (*Destination, *packetTestInbox) {
	t.Helper()
	inbox := &packetTestInbox{messages: make(chan *destination.ReceivedMessage, 16), done: make(chan struct{})}
	localHash := Hash{9}
	endpoint := &packetTestEndpoint{hash: localHash, inbox: inbox, prepare: prepare}
	ctx, cancel := context.WithCancel(context.Background())
	router := &Router{
		defaultNetwork: "i2p",
		packetBudget:   newPacketBudget(1 << 20),
		packetWrites:   make(chan struct{}, 1),
		ctx:            ctx,
		cancel:         cancel,
	}
	dest := &Destination{
		endpoints: map[string]destination.DestinationEndpoint{"i2p": endpoint},
		nets:      []string{"i2p"},
		owner:     router,
		ctx:       ctx,
		cancel:    cancel,
		hash:      localHash,
		b32:       endpoint.B32(),
		resources: make(map[io.Closer]struct{}),
	}
	t.Cleanup(func() {
		if err := dest.Close(); err != nil {
			t.Error(err)
		}
		cancel()
	})
	return dest, inbox
}

func packetTestListen(t *testing.T, prepare func(context.Context, Hash) error) (*PacketConn, *packetTestInbox) {
	t.Helper()
	dest, inbox := newPacketTestDestination(t, prepare)
	conn, err := dest.ListenPacket("udp", ":8000")
	if err != nil {
		t.Fatal(err)
	}
	return conn, inbox
}

func packetTestListenUnauth(t *testing.T, network string) (*UnauthPacketConn, *packetTestInbox) {
	t.Helper()
	dest, inbox := newPacketTestDestination(t, nil)
	conn, err := dest.ListenUnauthPacket(network, ":8000")
	if err != nil {
		t.Fatal(err)
	}
	return conn, inbox
}

func packetTestEnqueue(local Addr, protocol uint8, inbox *packetTestInbox, from Hash, payload []byte) {
	inbox.messages <- destination.NewReceivedMessage(destination.Delivery{From: from, To: local.Hash, FromPort: 42, ToPort: local.Port, Protocol: protocol, Payload: append([]byte(nil), payload...)}, nil)
}

func TestPacketReadDiscardsForgeryAndConsumesTruncatedMessage(t *testing.T) {
	key, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer key.ReleaseSensitive()
	identity, err := key.Identity()
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		c, inbox := packetTestListen(t, nil)
		local := c.LocalAddr().(Addr)
		encode := func(target Hash, payload string) []byte {
			b := make([]byte, MaxSendDatagramSize)
			n, err := dataplane.DatagramMarshalV2To(b, target, identity, 2, foundation.Mapping{}, foundation.OfflineSignature{}, []byte(payload), key.Sign)
			if err != nil {
				t.Fatal(err)
			}
			return b[:n]
		}
		valid := encode(local.Hash, "payload")
		forged := append([]byte(nil), valid...)
		forged[len(forged)-1] ^= 1
		packetTestEnqueue(local, 19, inbox, Hash{}, forged)
		packetTestEnqueue(local, 19, inbox, Hash{}, encode(Hash{8}, "wrong target"))
		packetTestEnqueue(local, 19, inbox, Hash{7}, valid)
		packetTestEnqueue(local, 19, inbox, Hash{}, valid)
		packetTestEnqueue(local, 19, inbox, key.Hash(), encode(local.Hash, ""))
		if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		p := make([]byte, 3)
		n, addr, err := c.ReadFrom(p)
		if n != 3 || string(p) != "pay" || !errors.Is(err, ErrMessageTruncated) {
			t.Fatalf("truncated read = %d %q %v", n, p, err)
		}
		if addr != (Addr{Hash: key.Hash(), Port: 42}) {
			t.Fatalf("verified source = %v", addr)
		}
		n, addr, err = c.ReadFrom(nil)
		if n != 0 || err != nil || addr != (Addr{Hash: key.Hash(), Port: 42}) {
			t.Fatalf("empty next message = %d %v %v", n, addr, err)
		}
	})
}

func TestUnsignedPacketClaimsNeverBecomeAuthenticatedSources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, tc := range []struct {
			network  string
			protocol uint8
		}{
			{network: "raw", protocol: 18},
			{network: "datagram3", protocol: 20},
		} {
			c, inbox := packetTestListenUnauth(t, tc.network)
			local := c.LocalAddr()
			payload := []byte("raw")
			if tc.protocol == 20 {
				b := make([]byte, 100)
				n, err := dataplane.DatagramMarshalV3To(b, Hash{}, 3, foundation.Mapping{}, payload)
				if err != nil {
					t.Fatal(err)
				}
				payload = b[:n]
			}
			packetTestEnqueue(local, tc.protocol, inbox, Hash{99}, payload)
			if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 20)
			n, meta, err := c.ReadPacket(b)
			if err != nil || string(b[:n]) != "raw" || meta.ClaimedSource != (Hash{}) || meta.HasClaimedSource != (tc.protocol == 20) || meta.FromPort != 42 {
				t.Fatalf("protocol %d: %q %+v %v", tc.protocol, b[:n], meta, err)
			}
		}
	})
}

func TestPacketReadDeadlineUpdateWakesBlockedReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := packetTestListen(t, nil)
		result := make(chan error, 1)
		go func() { _, _, err := c.ReadFrom(nil); result <- err }()
		synctest.Wait()
		if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		err := <-result
		var networkError net.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("read deadline = %v", err)
		}
	})
}

func TestPacketExtendedDeadlineDoesNotCancelPendingReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, inbox := packetTestListenUnauth(t, "raw")
		local := c.LocalAddr()
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, _, err := c.ReadPacket(nil); result <- err }()
		synctest.Wait()
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		observation := time.NewTimer(2 * time.Second)
		defer observation.Stop()
		<-observation.C
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("cleared deadline interrupted receive: %v", err)
		default:
		}
		packetTestEnqueue(local, 18, inbox, Hash{}, nil)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPacketWriteDeadlineCancelsPendingRoutePreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		c, _ := packetTestListen(t, func(ctx context.Context, _ Hash) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		})
		result := make(chan error, 1)
		go func() { _, err := c.WriteTo([]byte("pending"), Addr{Hash: Hash{4}, Port: 9}); result <- err }()
		<-entered
		if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("route preparation deadline = %v", err)
		}
		if err := c.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.WriteTo(make([]byte, MaxSendDatagramSize+1), Addr{Hash: Hash{4}, Port: 9}); !errors.Is(err, ErrMessageTooLarge) {
			t.Fatalf("oversize write before route preparation = %v", err)
		}
	})
}

func TestPacketCloseWakesPendingRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := packetTestListen(t, nil)
		done := make(chan error, 1)
		go func() { _, _, err := c.ReadFrom(nil); done <- err }()
		synctest.Wait()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after close = %v", err)
		}
		if err := c.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("deadline after close = %v", err)
		}
	})
}
