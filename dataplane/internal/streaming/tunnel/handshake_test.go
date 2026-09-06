package streamingtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/foundation"
)

type handshakeFeedbackRecorder struct {
	TunnelSender
	established int
	timedOut    int
}

func (f *handshakeFeedbackRecorder) PrepareHandshake(context.Context, foundation.Hash) (HandshakeFeedback, error) {
	return f, nil
}

func (f *handshakeFeedbackRecorder) Established() { f.established++ }
func (f *handshakeFeedbackRecorder) NoResponse()  { f.timedOut++ }

type handshakeSendFunc func(context.Context, Delivery) error

func (f handshakeSendFunc) SendTunnel(ctx context.Context, delivery Delivery) error {
	return f(ctx, delivery)
}

func TestUnansweredHandshakeBoundsAndReleasesConnection(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		retries    int
		retransmit time.Duration
		want       time.Duration
	}{
		{name: "handshake budget", want: DefaultHandshakeTimeout},
		{name: "retry budget", retries: 1, retransmit: time.Second, want: time.Second},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, err := foundation.GenerateLegacyLocalDestination()
				if err != nil {
					t.Fatal(err)
				}
				feedback := new(handshakeFeedbackRecorder)
				var network *TunnelNetwork
				var connection *tunnelConn
				sends := 0
				sender := handshakeSendFunc(func(context.Context, Delivery) error {
					sends++
					network.mu.RLock()
					for _, candidate := range network.byID {
						connection = candidate
					}
					network.mu.RUnlock()
					return nil
				})
				feedback.TunnelSender = sender
				network, err = NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: sender, HandshakeObserver: feedback, MaxRetries: scenario.retries, RetransmitAfter: scenario.retransmit})
				if err != nil {
					t.Fatal(err)
				}
				defer network.Close()
				started := time.Now()
				_, err = network.DialI2P(t.Context(), net.JoinHostPort(foundation.B32(foundation.Hash{1}), "80"))
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("silent SYN = %v; want timeout", err)
				}
				if elapsed := time.Since(started); elapsed != scenario.want {
					t.Fatalf("handshake lasted %v; want %v", elapsed, scenario.want)
				}
				synctest.Wait()
				if feedback.timedOut != 1 || feedback.established != 0 {
					t.Fatalf("feedback = %+v", feedback)
				}
				if connection == nil {
					t.Fatal("SYN never reached sender")
				}
				if !connection.isDone() || !connection.retryDue().IsZero() || len(connection.pending) != 0 || len(connection.synchronize) != 0 {
					t.Fatal("failed handshake retained connection or retry packet ownership")
				}
				if network.Stats().Connections != 0 {
					t.Fatal("failed handshake remained registered")
				}
				sent := sends
				<-time.After(2 * DefaultHandshakeTimeout)
				synctest.Wait()
				if sends != sent {
					t.Fatalf("abandoned handshake sent %d more packets", sends-sent)
				}
			})
		})
	}
}

func TestCanceledHandshakeDoesNotReportRouteFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		feedback := new(handshakeFeedbackRecorder)
		sender := &blockingTunnelSender{started: make(chan struct{})}
		feedback.TunnelSender = sender
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: sender, HandshakeObserver: feedback})
		if err != nil {
			t.Fatal(err)
		}
		defer network.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			_, err := network.DialI2P(ctx, net.JoinHostPort(foundation.B32(foundation.Hash{1}), "80"))
			result <- err
		}()
		<-sender.started
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled SYN = %v", err)
		}
		synctest.Wait()
		if feedback.timedOut != 0 {
			t.Fatal("caller cancellation penalized route")
		}
		if network.Stats().Connections != 0 {
			t.Fatal("canceled handshake remained registered")
		}
	})
}

func TestEstablishedStreamOutlivesHandshakeAndCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fabric := &streamFabric{networks: make(map[foundation.Hash]*TunnelNetwork)}
		client, server := newTunnelNetworkPair(t, fabric, time.Second)
		feedback := new(handshakeFeedbackRecorder)
		feedback.TunnelSender = fabric
		client.handshakeObserver = feedback
		listener, err := server.ListenI2P(t.Context(), ":80")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		outbound, err := client.DialI2P(ctx, net.JoinHostPort(server.B32(), "80"))
		if err != nil {
			t.Fatal(err)
		}
		inbound, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		<-time.After(2 * DefaultHandshakeTimeout)
		payload := []byte("still connected")
		if _, err := outbound.Write(payload); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(inbound, received); err != nil {
			t.Fatal(err)
		}
		if string(received) != string(payload) {
			t.Fatalf("received %q", received)
		}
		if feedback.established != 1 || feedback.timedOut != 0 {
			t.Fatalf("feedback = %+v", feedback)
		}
	})
}

func TestBlockedHandshakeSendCancelsWithoutPeerPenalty(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		sender := &blockingTunnelSender{started: make(chan struct{})}
		feedback := &handshakeFeedbackRecorder{TunnelSender: sender}
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: sender, HandshakeObserver: feedback, HandshakeTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer network.Close()
		_, err = network.DialI2P(t.Context(), net.JoinHostPort(foundation.B32(foundation.Hash{1}), "80"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked send = %v", err)
		}
		synctest.Wait()
		if feedback.timedOut != 0 {
			t.Fatal("unsent SYN penalized peer")
		}
		if network.Stats().Connections != 0 {
			t.Fatal("blocked handshake remained registered")
		}
	})
}

func TestCallerHandshakeDeadlineDoesNotPenalizePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, err := foundation.GenerateLegacyLocalDestination()
		if err != nil {
			t.Fatal(err)
		}
		sender := discardTunnelSender{}
		feedback := &handshakeFeedbackRecorder{TunnelSender: sender}
		network, err := NewTunnelNetwork(TunnelNetworkConfig{Destination: local, Sender: sender, HandshakeObserver: feedback})
		if err != nil {
			t.Fatal(err)
		}
		defer network.Close()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err = network.DialI2P(ctx, net.JoinHostPort(foundation.B32(foundation.Hash{1}), "80"))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("caller deadline = %v", err)
		}
		synctest.Wait()
		if feedback.timedOut != 0 {
			t.Fatal("caller deadline penalized peer")
		}
		if network.Stats().Connections != 0 {
			t.Fatal("expired handshake remained registered")
		}
	})
}
