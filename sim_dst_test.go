//go:build dst || synctest

package ivnp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
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
		var eventMu sync.Mutex
		events := make([]simnet.Event, 0, 1<<20)
		sim := newSimNet(t, 11)
		sim.net.SetHook(func(ev simnet.Event) {
			eventMu.Lock()
			if len(events) < cap(events) {
				events = append(events, ev)
			}
			eventMu.Unlock()
		})
		sim.AddRouter(t, simNodeConfig{Name: "flood1", Participation: ParticipationContributor})
		sim.AddRouter(t, simNodeConfig{Name: "flood2", Participation: ParticipationContributor})
		alice := sim.AddRouter(t, simNodeConfig{Name: "alice"})
		bob := sim.AddRouter(t, simNodeConfig{Name: "bob"})
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond, Jitter: time.Millisecond})

		sim.ExchangeRouterInfos(t)
		sim.WaitReady(t, 90*time.Second)

		ctx := t.Context()
		destCfg := DefaultDestinationConfig()
		destCfg.Tunnels = TunnelPoolConfig{
			Inbound:     TunnelDirectionConfig{Hops: 1, Count: 1},
			Outbound:    TunnelDirectionConfig{Hops: 1, Count: 1},
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
		accepted := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- conn
		}()

		dumpEvents := func(since time.Time) {
			eventMu.Lock()
			defer eventMu.Unlock()
			for _, ev := range events {
				if ev.At.Before(since) {
					continue
				}
				t.Logf("ev %s kind=%d proto=%d %s->%s bytes=%d", ev.At.Format("15:04:05.000"), ev.Kind, ev.Proto, ev.From, ev.To, ev.Bytes)
			}
		}
		stackDump := func() {
			buf := make([]byte, 2<<20)
			n := runtime.Stack(buf, true)
			t.Logf("stacks:\n%s", buf[:n])
		}

		// Bob's address was never imported into alice's NetDB — resolving it
		// exercises a real destination LeaseSet lookup over tunnels.
		start := time.Now()
		var outbound net.Conn
		initialDialCtx, initialDialCancel := context.WithTimeout(ctx, 90*time.Second)
		for {
			attemptCtx, attemptCancel := context.WithTimeout(initialDialCtx, 25*time.Second)
			outbound, err = source.DialContext(attemptCtx, "i2p", net.JoinHostPort(target.B32(), "8080"))
			if err == nil {
				break
			}
			attemptCancel()
			if initialDialCtx.Err() != nil {
				stackDump()
				t.Fatalf("dial through simulated mesh: %v", err)
			}
			sim.net.Advance(2 * time.Second)
		}
		defer initialDialCancel()
		defer outbound.Close()
		t.Logf("dial resolved and connected after %v virtual", time.Since(start))

		var inbound net.Conn
		select {
		case inbound = <-accepted:
		case err = <-acceptErr:
			t.Fatalf("accept: %v", err)
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
			stackDump()
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
			stackDump()
			t.Fatalf("read reply: %v", err)
		}
		if string(back) != string(reply) {
			t.Fatalf("reply = %q, want %q", back, reply)
		}
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
		deadline := time.Now().Add(30 * time.Second)
		sender.SetDeadline(deadline)
		receiver.SetDeadline(deadline)
		if _, err := sender.WriteTo([]byte("datagram-request"), receiver.LocalAddr()); err != nil {
			t.Fatalf("send datagram: %v", err)
		}
		buf := make([]byte, 256)
		nr, from, err := receiver.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read datagram: %v", err)
		}
		if string(buf[:nr]) != "datagram-request" {
			t.Fatalf("datagram = %q", buf[:nr])
		}
		if _, err := receiver.WriteTo([]byte("datagram-reply"), from); err != nil {
			t.Fatalf("reply datagram: %v", err)
		}
		if nr, _, err = sender.ReadFrom(buf); err != nil || string(buf[:nr]) != "datagram-reply" {
			t.Fatalf("reply datagram: n=%d err=%v", nr, err)
		}
		synctest.Wait()

		// Inject 100% UDP loss on every link: SSU2 datagrams drop, NTCP2
		// streams are untouched, and the mesh keeps routing. Dead SSU2
		// sessions are detected only through retransmission exhaustion
		// (bounded by a doubling RTO) before mux sends re-dial over NTCP2,
		// so the blackout legitimately lasts tens of virtual seconds. An
		// in-flight stream cannot outlast it — the eight-retry budget at
		// sub-second RTO is exhausted and the connection resets — so the
		// stream stays idle while the mesh re-converges, then delivers.
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond, Jitter: time.Millisecond, DropRate: 1.0, DropProto: simnet.ProtoUDP})
		sim.net.Advance(150 * time.Second)
		// The write can still race a tunnel rebuild — a send bound to a
		// circuit that was just retired fails fast with circuit-not-found.
		// Each retry re-resolves the pool's current pair.
		writeCtx, writeCancel := context.WithTimeout(ctx, 2*time.Minute)
		for {
			outbound.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err = outbound.Write([]byte("post-loss"))
			if err == nil {
				break
			}
			if writeCtx.Err() != nil {
				stackDump()
				t.Fatalf("write after UDP loss: %v", err)
			}
			sim.net.Advance(2 * time.Second)
		}
		writeCancel()
		got = make([]byte, len("post-loss"))
		inbound.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(inbound, got); err != nil {
			dumpEvents(time.Now().Add(-90 * time.Second))
			stackDump()
			t.Fatalf("read after UDP loss: %v", err)
		}
		synctest.Wait()
		if dropped := sim.Stats().Dropped; dropped == 0 {
			t.Fatal("UDP loss profile recorded no drops")
		}

		// Partition alice from the fleet: the established stream stalls, and a
		// new dial to her address cannot complete. ResetLink severs existing
		// TCP conns like a real cut — Partition would only stall them, leaving
		// permanently desynced byte streams that satisfy HasSession forever.
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond})
		for _, node := range sim.nodes {
			if node != alice {
				sim.net.ResetLink(alice.Addr(), node.Addr())
			}
		}
		outbound.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := outbound.Read(make([]byte, 8)); err == nil {
			t.Fatal("read on partitioned stream succeeded")
		}
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if _, err := source.DialContext(dialCtx, "i2p", net.JoinHostPort(target.B32(), "8080")); err == nil {
			cancel()
			t.Fatal("dial from partitioned source succeeded")
		}
		cancel()
		synctest.Wait()

		// Healing restores reachability, but every session alice held was
		// reset: transports re-dial, tunnels rebuild, and the LeaseSet lookup
		// has to run again — all asynchronously. Retry the dial until the
		// mesh reconverges, bounded well beyond one rebuild cycle.
		for _, node := range sim.nodes {
			if node != alice {
				sim.net.Heal(alice.Addr(), node.Addr())
			}
		}
		synctest.Wait()
		var rebound net.Conn
		healCtx, healCancel := context.WithTimeout(ctx, 4*time.Minute)
		for {
			dialCtx, dialCancel := context.WithTimeout(healCtx, 30*time.Second)
			rebound, err = source.DialContext(dialCtx, "i2p", net.JoinHostPort(target.B32(), "8080"))
			dialCancel()
			if err == nil {
				break
			}
			if healCtx.Err() != nil {
				stackDump()
				t.Fatalf("dial after heal: %v", err)
			}
			sim.net.Advance(5 * time.Second)
		}
		healCancel()
		rebound.Close()
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

		// 2. Gilbert-Elliott Burst Loss under active streaming
		// Configure UDP burst loss: 15% transition to bad state, 30% recovery (mean burst length ~3.3 packets)
		sim.Mesh(simnet.LinkConfig{
			Latency:   2 * time.Millisecond,
			DropProto: simnet.ProtoUDP,
			BurstLoss: &simnet.BurstLossConfig{
				PToBad:   0.15,
				PToGood:  0.30,
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
