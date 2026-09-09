package ivnp

import (
	"context"
	"errors"
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
func packetTestSocket(t *testing.T, protocol uint8) (*packetSocket, *packetTestInbox) {
	t.Helper()
	inbox := &packetTestInbox{messages: make(chan *destination.ReceivedMessage, 16), done: make(chan struct{})}
	s := &packetSocket{owner: &Destination{ctx: context.Background()}, protocol: protocol, network: "i2p-datagram2", local: Addr{Hash: Hash{9}, Port: 8000}, subscription: inbox, operations: make(map[*packetOperation]struct{}), closeDone: make(chan struct{})}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, inbox
}
func packetTestEnqueue(s *packetSocket, inbox *packetTestInbox, from Hash, payload []byte) {
	inbox.messages <- destination.NewReceivedMessage(destination.Delivery{From: from, To: s.local.Hash, FromPort: 42, ToPort: s.local.Port, Protocol: s.protocol, Payload: append([]byte(nil), payload...)}, nil)
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
	s, inbox := packetTestSocket(t, 19)
	c := &PacketConn{socket: s}
	encode := func(target Hash, payload string) []byte {
		b := make([]byte, MaxSendDatagramSize)
		n, err := dataplane.DatagramMarshalV2To(b, target, identity, 2, foundation.Mapping{}, foundation.OfflineSignature{}, []byte(payload), key.Sign)
		if err != nil {
			t.Fatal(err)
		}
		return b[:n]
	}
	valid := encode(s.local.Hash, "payload")
	forged := append([]byte(nil), valid...)
	forged[len(forged)-1] ^= 1
	packetTestEnqueue(s, inbox, Hash{}, forged)
	packetTestEnqueue(s, inbox, Hash{}, encode(Hash{8}, "wrong target"))
	packetTestEnqueue(s, inbox, Hash{7}, valid)
	packetTestEnqueue(s, inbox, Hash{}, valid)
	packetTestEnqueue(s, inbox, key.Hash(), encode(s.local.Hash, ""))
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
}
func TestUnsignedPacketClaimsNeverBecomeAuthenticatedSources(t *testing.T) {
	for _, protocol := range []uint8{18, 20} {
		s, inbox := packetTestSocket(t, protocol)
		c := &UnauthPacketConn{socket: s}
		payload := []byte("raw")
		if protocol == 20 {
			b := make([]byte, 100)
			n, err := dataplane.DatagramMarshalV3To(b, Hash{}, 3, foundation.Mapping{}, payload)
			if err != nil {
				t.Fatal(err)
			}
			payload = b[:n]
		}
		packetTestEnqueue(s, inbox, Hash{99}, payload)
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 20)
		n, meta, err := c.ReadPacket(b)
		if err != nil || string(b[:n]) != "raw" || meta.ClaimedSource != (Hash{}) || meta.HasClaimedSource != (protocol == 20) || meta.FromPort != 42 {
			t.Fatalf("protocol %d: %q %+v %v", protocol, b[:n], meta, err)
		}
	}
}
func TestPacketReadDeadlineUpdateWakesBlockedReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := packetTestSocket(t, 19)
		c := &PacketConn{socket: s}
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
		s, inbox := packetTestSocket(t, 18)
		c := &UnauthPacketConn{socket: s}
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
		packetTestEnqueue(s, inbox, Hash{}, nil)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

type packetBlockedRoute struct {
	destination.DestinationEndpoint
	entered chan struct{}
}

func (e *packetBlockedRoute) PrepareDestination(ctx context.Context, _ Hash) error {
	close(e.entered)
	<-ctx.Done()
	return ctx.Err()
}
func TestPacketWriteDeadlineCancelsPendingRoutePreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := packetTestSocket(t, 18)
		endpoint := &packetBlockedRoute{entered: make(chan struct{})}
		s.owner.endpoint = endpoint
		s.owner.owner = &Router{packetWrites: make(chan struct{}, 1)}
		s.maxPayload = MaxSendDatagramSize
		c := &UnauthPacketConn{socket: s}
		result := make(chan error, 1)
		go func() { _, err := c.WriteTo([]byte("pending"), Addr{Hash: Hash{4}, Port: 9}); result <- err }()
		<-endpoint.entered
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
		s, _ := packetTestSocket(t, 19)
		c := &PacketConn{socket: s}
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
