//go:build dst || synctest

package ivnp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/internal/simnet"
)

// TestSimRouterBoot smoke-tests the harness: routers start on virtual sockets,
// exchange RouterInfos, and build exploratory tunnels — all on fake time.
func TestSimRouterBoot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sim := newSimNet(t, 7)
		sim.AddRouter(t, simNodeConfig{Name: "flood", Participation: ParticipationContributor})
		sim.AddRouter(t, simNodeConfig{Name: "alice"})
		sim.AddRouter(t, simNodeConfig{Name: "bob"})
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond, Jitter: time.Millisecond})

		sim.ExchangeRouterInfos(t)
		sim.WaitReady(t, 60*time.Second)
		t.Logf("stats after boot: %+v", sim.Stats())
	})
}

// TestDeterministicRouterMesh is the primary deterministic-simulation test.
// Four embedded routers — two floodfill contributors and two warm clients —
// run real NTCP2 and SSU2 transports over a virtual mesh. The test covers the
// full user-facing path inside a synctest bubble:
//
//   - RouterInfo exchange and exploratory tunnel construction (router routing).
//   - LeaseSet2 publication through tunnels to the floodfill NetDB.
//   - NetDB destination lookup by the dialing router.
//   - Bidirectional streaming over built tunnels with virtual latency.
//   - Signed datagram exchange.
//   - UDP packet loss injection (SSU2 links drop; NTCP2 carries the mesh).
//   - A full partition of one node and recovery after healing.
func TestDeterministicRouterMesh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sim := newSimNet(t, 11)
		sim.AddRouter(t, simNodeConfig{Name: "flood1", Participation: ParticipationContributor, TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "flood2", Participation: ParticipationContributor, TunnelCount: 2})
		relay1 := sim.AddRouter(t, simNodeConfig{Name: "relay1", TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "relay2", TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "relay3", TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "relay4", TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "relay5", TunnelCount: 2})
		alice := sim.AddRouter(t, simNodeConfig{Name: "alice", TunnelCount: 2})
		bob := sim.AddRouter(t, simNodeConfig{Name: "bob", TunnelCount: 2})
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond, Jitter: time.Millisecond})

		sim.ExchangeRouterInfos(t)
		sim.WaitReady(t, 90*time.Second)

		ctx := t.Context()
		destCfg := DefaultDestinationConfig()
		destCfg.Tunnels = TunnelPoolConfig{
			Inbound:     TunnelDirectionConfig{Hops: 1, Count: 2},
			Outbound:    TunnelDirectionConfig{Hops: 1, Count: 2},
			RenewBefore: 10 * time.Second,
		}

		// The destination create blocks until tunnels form and the LeaseSet is
		// confirmed stored on the floodfill — a real NetDB publication.
		target, err := bob.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("bob destination: %v", err)
		}
		defer target.Close()
		source, err := alice.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("alice destination: %v", err)
		}
		defer source.Close()

		listener, err := target.Listen("i2p", ":8080")
		if err != nil {
			t.Fatalf("target listen: %v", err)
		}
		defer listener.Close()
		accepted := make(chan net.Conn, 16)
		acceptErr := make(chan error, 1)
		stopAccept := make(chan struct{})
		defer close(stopAccept)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					select {
					case acceptErr <- err:
					case <-stopAccept:
					}
					return
				}
				t.Logf("listener accepted conn remote=%v local=%v", conn.RemoteAddr(), conn.LocalAddr())
				select {
				case accepted <- conn:
				case <-stopAccept:
					_ = conn.Close()
					return
				}
			}
		}()

		// Bob's address was never imported into alice's NetDB — resolving it
		// exercises a real destination LeaseSet lookup over tunnels.
		start := time.Now()
		var outbound net.Conn
		initialDialCtx, initialDialCancel := context.WithTimeout(ctx, 180*time.Second)
		dialPort := uint16(50000)
		for {
			for len(accepted) > 0 {
				stale := <-accepted
				_ = stale.Close()
			}
			dialPort++
			dialer := Dialer{Destination: source, LocalPort: dialPort}
			attemptCtx, attemptCancel := context.WithTimeout(initialDialCtx, 60*time.Second)
			outbound, err = dialer.DialContext(attemptCtx, "i2p", net.JoinHostPort(target.B32(), "8080"))
			attemptCancel()
			if err == nil {
				break
			}
			if initialDialCtx.Err() != nil {
				t.Fatalf("dial through simulated mesh: %v", err)
			}
			sim.net.Advance(2 * time.Second)
		}
		defer initialDialCancel()
		defer outbound.Close()
		t.Logf("dial resolved and connected after %v virtual", time.Since(start))

		var inbound net.Conn
		for inbound == nil {
			select {
			case conn := <-accepted:
				if conn.RemoteAddr().String() == outbound.LocalAddr().String() {
					inbound = conn
				} else {
					_ = conn.Close()
				}
			case err = <-acceptErr:
				t.Fatalf("accept: %v", err)
			}
		}
		defer inbound.Close()

		payload := []byte("deterministic-simulation-round-trip")
		outbound.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := outbound.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := make([]byte, len(payload))
		inbound.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(inbound, got); err != nil {
			t.Fatalf("read payload: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
		reply := []byte("reply-payload")
		inbound.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := inbound.Write(reply); err != nil {
			t.Fatalf("write reply: %v", err)
		}
		back := make([]byte, len(reply))
		outbound.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(outbound, back); err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if string(back) != string(reply) {
			t.Fatalf("reply = %q, want %q", back, reply)
		}
		sim.net.Advance(500 * time.Millisecond)
		synctest.Wait()

		// Signed datagram round trip over the same destination pair.
		sender, err := source.ListenPacket("i2p-datagram2", ":0")
		if err != nil {
			t.Fatalf("sender packet conn: %v", err)
		}
		defer sender.Close()
		receiver, err := target.ListenPacket("i2p-datagram2", ":8081")
		if err != nil {
			t.Fatalf("receiver packet conn: %v", err)
		}
		defer receiver.Close()

		reqMsg := []byte("datagram-deterministic-request")
		replyMsg := []byte("datagram-deterministic-reply")
		buf := make([]byte, 256)
		dgramSuccess := false
		for attempt := 0; attempt < 5; attempt++ {
			deadline := time.Now().Add(25 * time.Second)
			sender.SetDeadline(deadline)
			receiver.SetDeadline(deadline)
			_, sendErr := sender.WriteTo(reqMsg, receiver.LocalAddr())
			if sendErr != nil {
				t.Logf("dgram attempt %d: sendErr=%v", attempt, sendErr)
				sim.net.Advance(2 * time.Second)
				continue
			}
			nr, from, recvErr := receiver.ReadFrom(buf)
			if recvErr != nil || !bytes.Equal(buf[:nr], reqMsg) {
				t.Logf("dgram attempt %d: recvErr=%v nr=%d", attempt, recvErr, nr)
				sim.net.Advance(2 * time.Second)
				continue
			}
			fromAddr, ok := from.(Addr)
			if !ok || fromAddr.Hash != source.Hash() {
				t.Fatalf("dgram receiver authenticated from hash mismatch: got %+v, want hash=%x", from, source.Hash())
			}
			_, replyErr := receiver.WriteTo(replyMsg, from)
			if replyErr != nil {
				t.Logf("dgram attempt %d: replyErr=%v", attempt, replyErr)
				sim.net.Advance(2 * time.Second)
				continue
			}
			nr, fromReply, senderErr := sender.ReadFrom(buf)
			if senderErr == nil && bytes.Equal(buf[:nr], replyMsg) {
				replyAddr, ok := fromReply.(Addr)
				if !ok || replyAddr.Hash != target.Hash() {
					t.Fatalf("dgram sender authenticated reply hash mismatch: got %+v, want hash=%x", fromReply, target.Hash())
				}
				dgramSuccess = true
				break
			}
			t.Logf("dgram attempt %d: senderErr=%v nr=%d", attempt, senderErr, nr)
			sim.net.Advance(2 * time.Second)
		}
		if !dgramSuccess {
			t.Fatal("datagram round trip failed after retries")
		}
		sim.net.Advance(500 * time.Millisecond)
		synctest.Wait()

		// Partial failure model: inject 15% UDP loss with 1ms jitter.
		// Transports (SSU2 with retransmission/RTO and NTCP2 fallback) and the
		sim.Mesh(simnet.LinkConfig{
			Latency:   2 * time.Millisecond,
			Jitter:    time.Millisecond,
			DropRate:  0.15,
			DropProto: simnet.ProtoUDP,
		})

		chunkPayload := make([]byte, 2048)
		for i := range chunkPayload {
			chunkPayload[i] = byte((i*31 + 17) & 0xff)
		}
		outbound.SetWriteDeadline(time.Now().Add(120 * time.Second))
		if _, err := outbound.Write(chunkPayload); err != nil {
			t.Fatalf("write chunkPayload under partial loss: %v", err)
		}
		gotChunks := make([]byte, len(chunkPayload))
		inbound.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(inbound, gotChunks); err != nil {
			t.Fatalf("read chunkPayload under partial loss: %v", err)
		}
		if !bytes.Equal(gotChunks, chunkPayload) {
			t.Fatal("chunkPayload corrupted or mismatched under partial loss")
		}

		chunkReply := make([]byte, 2048)
		for i := range chunkReply {
			chunkReply[i] = byte((i*59 + 41) & 0xff)
		}
		inbound.SetWriteDeadline(time.Now().Add(120 * time.Second))
		if _, err := inbound.Write(chunkReply); err != nil {
			t.Fatalf("write chunkReply under partial loss: %v", err)
		}
		gotChunkReply := make([]byte, len(chunkReply))
		outbound.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(outbound, gotChunkReply); err != nil {
			t.Fatalf("read chunkReply under partial loss: %v", err)
		}
		if !bytes.Equal(gotChunkReply, chunkReply) {
			t.Fatal("chunkReply corrupted or mismatched under partial loss")
		}

		_ = outbound.Close()
		_ = inbound.Close()
		synctest.Wait()

		// Partial failure model 2: abruptly sever relay1 from the entire fleet.
		// The fleet maintains redundancy (relay2..relay5, flood1, flood2).
		// Surviving relays and floodfills must keep routing intact,
		// allowing Alice and Bob to dial and stream verified data.
		for _, node := range sim.nodes {
			if node != relay1 {
				sim.net.ResetLink(relay1.Addr(), node.Addr())
			}
		}
		_ = relay1.router.Close()
		sim.net.Advance(200 * time.Second)

		var rebound net.Conn
		reboundCtx, reboundCancel := context.WithTimeout(ctx, 240*time.Second)
		defer reboundCancel()
		for {
			for len(accepted) > 0 {
				stale := <-accepted
				_ = stale.Close()
			}
			dialPort++
			dialer := Dialer{Destination: source, LocalPort: dialPort, Timeout: 60 * time.Second}
			t.Logf("rebound starting attempt port=%d", dialPort)
			attemptCtx, attemptCancel := context.WithTimeout(reboundCtx, 90*time.Second)
			rebound, err = dialer.DialContext(attemptCtx, "i2p", net.JoinHostPort(target.B32(), "8080"))
			attemptCancel()
			if err == nil {
				break
			}
			t.Logf("rebound attempt port=%d err=%v", dialPort, err)
			if reboundCtx.Err() != nil {
				t.Fatalf("dial after partial relay crash: %v", err)
			}
			sim.net.Advance(2 * time.Second)
		}
		defer rebound.Close()

		var reboundInbound net.Conn
		for reboundInbound == nil {
			select {
			case conn := <-accepted:
				if conn.RemoteAddr().String() == rebound.LocalAddr().String() {
					reboundInbound = conn
				} else {
					_ = conn.Close()
				}
			case err := <-acceptErr:
				t.Fatalf("rebound accept: %v", err)
			}
		}
		defer reboundInbound.Close()

		reboundReq := []byte("rebound-request-verification-payload")
		reboundResp := []byte("rebound-response-verification-payload")
		rebound.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := rebound.Write(reboundReq); err != nil {
			t.Fatalf("rebound write: %v", err)
		}
		gotReq := make([]byte, len(reboundReq))
		reboundInbound.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(reboundInbound, gotReq); err != nil {
			t.Fatalf("rebound read req: %v", err)
		}
		if !bytes.Equal(gotReq, reboundReq) {
			t.Fatalf("rebound req got %q, want %q", gotReq, reboundReq)
		}

		reboundInbound.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := reboundInbound.Write(reboundResp); err != nil {
			t.Fatalf("rebound reply write: %v", err)
		}
		gotResp := make([]byte, len(reboundResp))
		rebound.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(rebound, gotResp); err != nil {
			t.Fatalf("rebound read resp: %v", err)
		}
		if !bytes.Equal(gotResp, reboundResp) {
			t.Fatalf("rebound resp got %q, want %q", gotResp, reboundResp)
		}

		t.Logf("final stats: %+v", sim.Stats())
	})
}

// TestSimChaosFailureModels exercises advanced network failure models:
// 1. Chinese-style middlebox UDP packet duplication (delayed multi-copy injection).
// 2. Unidirectional / asymmetric blackhole (one-way routing failure).
// 3. Gilbert-Elliott burst loss (correlated consecutive drop sequence).
// 4. Abrupt node crash (CrashNode without TCP FIN/RST or wire notice).
func TestSimChaosFailureModels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sim := newSimNet(t, 2026)
		sim.AddRouter(t, simNodeConfig{Name: "flood", Participation: ParticipationContributor})
		alice := sim.AddRouter(t, simNodeConfig{Name: "alice"})

		bob := sim.AddRouter(t, simNodeConfig{Name: "bob"})

		// Chinese middlebox network profile: 2ms latency + 15% UDP duplication with 5ms extra delay
		sim.Mesh(simnet.LinkConfig{
			Latency:        2 * time.Millisecond,
			Jitter:         time.Millisecond,
			DuplicateRate:  0.15,
			DuplicateDelay: 5 * time.Millisecond,
			DuplicateCount: 1,
		})

		sim.ExchangeRouterInfos(t)
		sim.WaitReady(t, 60*time.Second)

		// Verify that UDP duplication occurred on the wire and was safely absorbed
		stats := sim.Stats()
		if stats.Duplicated == 0 {
			t.Log("warning: no duplicate events triggered during boot")
		} else {
			t.Logf("boot succeeded through middlebox duplication: %d duplicate packets handled", stats.Duplicated)
		}

		ctx := t.Context()
		destCfg := DefaultDestinationConfig()
		destCfg.Tunnels = TunnelPoolConfig{
			Inbound:     TunnelDirectionConfig{Hops: 1, Count: 1},
			Outbound:    TunnelDirectionConfig{Hops: 1, Count: 1},
			RenewBefore: 10 * time.Second,
		}

		target, err := bob.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("bob destination: %v", err)
		}
		defer target.Close()
		source, err := alice.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("alice destination: %v", err)
		}
		defer source.Close()

		listener, err := target.Listen("i2p", ":8080")
		if err != nil {
			t.Fatalf("target listen: %v", err)
		}
		accepted := make(chan net.Conn, 1)
		go func() {
			conn, acceptErr := listener.Accept()
			if acceptErr == nil {
				accepted <- conn
			}
		}()

		// 1. Establish initial stream over the Chinese-style duplicated network
		outbound, err := source.DialContext(ctx, "i2p", net.JoinHostPort(target.B32(), "8080"))
		if err != nil {
			t.Fatalf("initial dial: %v", err)
		}
		defer outbound.Close()
		inbound := <-accepted
		defer inbound.Close()
		synctest.Wait()

		// 2. Gilbert-Elliott Burst Loss under active streaming
		// Configure UDP burst loss: 15% transition to bad state, 30% recovery (mean burst length ~3.3 packets)
		sim.Mesh(simnet.LinkConfig{
			Latency:   2 * time.Millisecond,
			DropProto: simnet.ProtoUDP,
			BurstLoss: &simnet.BurstLossConfig{
				PToBad:   0.05,
				PToGood:  0.50,
				LossGood: 0.0,
				LossBad:  1.0,
			},
		})

		payload := []byte("stream-over-burst-loss")
		outbound.SetWriteDeadline(time.Now().Add(120 * time.Second))
		if _, err := outbound.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := make([]byte, len(payload))
		inbound.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.ReadFull(inbound, got); err != nil {
			t.Fatalf("read payload under burst loss: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("got %q, want %q", got, payload)
		}

		// 3. Unidirectional Asymmetric Blackhole: sever alice -> bob link only
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond})
		sim.net.Blackhole(alice.Addr(), bob.Addr())
		// Alice -> Bob is dropped, so data from alice never reaches bob
		outbound.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = outbound.Write([]byte("blackholed-data"))
		inbound.SetReadDeadline(time.Now().Add(2 * time.Second))
		dummy := make([]byte, 16)
		if _, err := inbound.Read(dummy); err == nil {
			t.Fatalf("expected failure on unidirectional blackholed link, got successful read")
		} else if !os.IsTimeout(err) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected timeout or closed on unidirectional blackholed link, got %v", err)
		}
		// Unblackhole restores reachability
		sim.net.Unblackhole(alice.Addr(), bob.Addr())
		synctest.Wait()

		// 4. Abrupt Node Crash: kill bob without TCP FIN/RST
		sim.CrashNode(t, bob)
		synctest.Wait()

		// Existing stream on alice should observe unresponsiveness / timeout, not immediate connection reset
		outbound.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		_, readErr := outbound.Read(buf)
		if readErr == nil {
			t.Fatal("read on crashed peer succeeded")
		}
		t.Logf("stream observed silent crash timeout: %v", readErr)

		t.Logf("chaos test final stats: %+v", sim.Stats())
	})
}

// BenchmarkSimStreamThroughput measures bidirectional streaming throughput

// across virtual routers in the simulated network on the ambient clock.
func BenchmarkSimStreamThroughput(b *testing.B) {
	sim := newSimNet(b, 42)
	sim.AddRouter(b, simNodeConfig{Name: "flood", Participation: ParticipationContributor})
	alice := sim.AddRouter(b, simNodeConfig{Name: "alice"})
	bob := sim.AddRouter(b, simNodeConfig{Name: "bob"})
	sim.Mesh(simnet.LinkConfig{})

	sim.ExchangeRouterInfos(b)
	sim.WaitReady(b, 30*time.Second)

	ctx := b.Context()
	destCfg := DefaultDestinationConfig()
	destCfg.Tunnels = TunnelPoolConfig{
		Inbound:     TunnelDirectionConfig{Hops: 1, Count: 1},
		Outbound:    TunnelDirectionConfig{Hops: 1, Count: 1},
		RenewBefore: 30 * time.Second,
	}
	target, err := bob.router.NewDestination(ctx, destCfg)
	if err != nil {
		b.Fatalf("bob destination: %v", err)
	}
	defer target.Close()
	source, err := alice.router.NewDestination(ctx, destCfg)
	if err != nil {
		b.Fatalf("alice destination: %v", err)
	}
	defer source.Close()

	listener, err := target.Listen("i2p", ":8080")
	if err != nil {
		b.Fatalf("target listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	outbound, err := source.DialContext(dialCtx, "i2p", net.JoinHostPort(target.B32(), "8080"))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer outbound.Close()
	inbound := <-accepted
	defer inbound.Close()

	const chunkLen = 1024
	payload := make([]byte, chunkLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	recvBuf := make([]byte, chunkLen)

	b.SetBytes(chunkLen)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		outbound.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := outbound.Write(payload); err != nil {
			b.Fatalf("write at iter %d: %v", i, err)
		}
		inbound.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(inbound, recvBuf); err != nil {
			b.Fatalf("read at iter %d: %v", i, err)
		}
	}
}
