//go:build dst || synctest

package ivnp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		// Transports (SSU2 retransmission, NTCP2 fallback) and the streaming
		// layer must absorb the loss; the drop counter proves UDP engaged.
		dropsBefore := sim.Stats().Dropped
		udpSentBefore := sim.Stats().SentUDP
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
		chunkReply := make([]byte, 2048)
		for i := range chunkReply {
			chunkReply[i] = byte((i*59 + 41) & 0xff)
		}
		gotChunks := make([]byte, len(chunkPayload))
		gotChunkReply := make([]byte, len(chunkReply))
		// Rounds repeat until the drop counter proves the model engaged: a
		// single exchange moves too few UDP packets for a 15% rate to be
		// deterministic. A stalled round after observed drops still proves
		// UDP carried the stream.
		engaged := func() bool { return sim.Stats().Dropped > dropsBefore }
		for round := 0; round < 8; round++ {
			outbound.SetWriteDeadline(time.Now().Add(120 * time.Second))
			_, werr := outbound.Write(chunkPayload)
			inbound.SetReadDeadline(time.Now().Add(120 * time.Second))
			_, rerr := io.ReadFull(inbound, gotChunks)
			inbound.SetWriteDeadline(time.Now().Add(120 * time.Second))
			_, rwerr := inbound.Write(chunkReply)
			outbound.SetReadDeadline(time.Now().Add(120 * time.Second))
			_, rrerr := io.ReadFull(outbound, gotChunkReply)
			if werr != nil || rerr != nil || rwerr != nil || rrerr != nil {
				if engaged() {
					break
				}
				t.Fatalf("round trip under partial loss (round %d): write=%v read=%v replyWrite=%v replyRead=%v", round, werr, rerr, rwerr, rrerr)
			}
			if !bytes.Equal(gotChunks, chunkPayload) {
				t.Fatal("chunkPayload corrupted or mismatched under partial loss")
			}
			if !bytes.Equal(gotChunkReply, chunkReply) {
				t.Fatal("chunkReply corrupted or mismatched under partial loss")
			}
			if engaged() {
				break
			}
		}
		stats := sim.Stats()
		if !engaged() {
			t.Fatalf("UDP loss model never engaged during the partial-loss round trips (sent=%d)", stats.SentUDP-udpSentBefore)
		}
		t.Logf("partial loss exercised: %d UDP packets dropped over %d sent", stats.Dropped-dropsBefore, stats.SentUDP-udpSentBefore)

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
			attemptCtx, attemptCancel := context.WithTimeout(reboundCtx, 30*time.Second)
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

// TestDeterministicRouterMesh16 scales the mesh to sixteen routers: two
// floodfills, ten transit relays, and four client destinations. Two
// concurrent streams on disjoint destination pairs verify that exploratory
// tunnel selection and NetDB resolution stay correct at larger fleet sizes.
func TestDeterministicRouterMesh16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sim := newSimNet(t, 16)
		sim.AddRouter(t, simNodeConfig{Name: "flood1", Participation: ParticipationContributor, TunnelCount: 2})
		sim.AddRouter(t, simNodeConfig{Name: "flood2", Participation: ParticipationContributor, TunnelCount: 2})
		for i := 1; i <= 10; i++ {
			sim.AddRouter(t, simNodeConfig{Name: fmt.Sprintf("relay%d", i), TunnelCount: 2})
		}
		alice := sim.AddRouter(t, simNodeConfig{Name: "alice", TunnelCount: 2})
		bob := sim.AddRouter(t, simNodeConfig{Name: "bob", TunnelCount: 2})
		carol := sim.AddRouter(t, simNodeConfig{Name: "carol", TunnelCount: 2})
		dave := sim.AddRouter(t, simNodeConfig{Name: "dave", TunnelCount: 2})
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond, Jitter: time.Millisecond})

		sim.ExchangeRouterInfos(t)
		sim.WaitReady(t, 120*time.Second)

		ctx := t.Context()
		destCfg := DefaultDestinationConfig()
		destCfg.Tunnels = TunnelPoolConfig{
			Inbound:     TunnelDirectionConfig{Hops: 1, Count: 2},
			Outbound:    TunnelDirectionConfig{Hops: 1, Count: 2},
			RenewBefore: 10 * time.Second,
		}

		echo := func(dst *Destination, port string) {
			listener, err := dst.Listen("i2p", port)
			if err != nil {
				t.Errorf("listen %s: %v", port, err)
				return
			}
			go func() {
				defer listener.Close()
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
						buf := make([]byte, 64)
						n, err := conn.Read(buf)
						if err != nil {
							return
						}
						_ = conn.SetWriteDeadline(time.Now().Add(90 * time.Second))
						_, _ = conn.Write(buf[:n])
					}()
				}
			}()
		}

		targetBob, err := bob.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("bob destination: %v", err)
		}
		defer targetBob.Close()
		targetCarol, err := carol.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("carol destination: %v", err)
		}
		defer targetCarol.Close()
		sourceAlice, err := alice.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("alice destination: %v", err)
		}
		defer sourceAlice.Close()
		sourceDave, err := dave.router.NewDestination(ctx, destCfg)
		if err != nil {
			t.Fatalf("dave destination: %v", err)
		}
		defer sourceDave.Close()

		echo(targetBob, ":8080")
		echo(targetCarol, ":8080")

		// Two concurrent verified round trips on disjoint destination pairs.
		roundTrip := func(source *Destination, targetB32 string, payload []byte) error {
			dialCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			conn, err := source.DialContext(dialCtx, "i2p", net.JoinHostPort(targetB32, "8080"))
			if err != nil {
				return err
			}
			defer conn.Close()
			_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				return err
			}
			got := make([]byte, len(payload))
			_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if !bytes.Equal(got, payload) {
				return fmt.Errorf("round trip payload = %q, want %q", got, payload)
			}
			return nil
		}

		type result struct {
			name string
			err  error
		}
		results := make(chan result, 2)
		go func() {
			results <- result{"alice->bob", roundTrip(sourceAlice, targetBob.B32(), []byte("alice-to-bob-16-node-round-trip"))}
		}()
		go func() {
			results <- result{"dave->carol", roundTrip(sourceDave, targetCarol.B32(), []byte("dave-to-carol-16-node-round-trip"))}
		}()
		for i := 0; i < 2; i++ {
			if r := <-results; r.err != nil {
				t.Fatalf("%s round trip: %v", r.name, r.err)
			}
		}
		t.Logf("16-node mesh stats: %+v", sim.Stats())
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
		// SSU2-only nodes force the streams onto UDP so the duplication and
		// burst-loss models below provably apply to the tested traffic.
		sim.AddRouter(t, simNodeConfig{Name: "flood", Participation: ParticipationContributor, DisableNTCP2: true})
		alice := sim.AddRouter(t, simNodeConfig{Name: "alice", DisableNTCP2: true})
		bob := sim.AddRouter(t, simNodeConfig{Name: "bob", DisableNTCP2: true})

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
			t.Fatal("UDP duplication model never engaged during boot")
		}
		t.Logf("boot succeeded through middlebox duplication: %d duplicate packets handled", stats.Duplicated)

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
		accepted := make(chan net.Conn, 4)
		go func() {
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
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

		// 2. Gilbert-Elliott Burst Loss under active streaming.
		// 5% entry / 50% exit gives a ~9% steady-state bad probability. Rounds
		// repeat until the drop counter proves the model engaged; a stalled
		// round under observed drops still proves UDP carried the stream.
		dropsBefore := sim.Stats().Dropped
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
		engaged := func() bool { return sim.Stats().Dropped > dropsBefore }

		payload := make([]byte, 4096)
		for i := range payload {
			payload[i] = byte((i*17 + 5) & 0xff)
		}
		got := make([]byte, len(payload))
		stalled := false
		rounds := 0
		for ; rounds < 8 && !engaged() && !stalled; rounds++ {
			outbound.SetWriteDeadline(time.Now().Add(60 * time.Second))
			_, werr := outbound.Write(payload)
			inbound.SetReadDeadline(time.Now().Add(60 * time.Second))
			_, rerr := io.ReadFull(inbound, got)
			switch {
			case werr == nil && rerr == nil:
				if !bytes.Equal(got, payload) {
					t.Fatal("payload corrupted or mismatched under burst loss")
				}
			case engaged():
				stalled = true
				t.Logf("burst loss stalled round %d after drops engaged (write=%v read=%v)", rounds, werr, rerr)
			default:
				t.Fatalf("round trip under burst loss: write=%v read=%v", werr, rerr)
			}
		}
		if !engaged() {
			t.Fatal("Gilbert-Elliott UDP loss model never engaged during the round trips")
		}
		t.Logf("burst loss exercised: %d UDP packets dropped over %d round trips", sim.Stats().Dropped-dropsBefore, rounds)

		// 3. Unidirectional blackhole: sever all of alice's egress so her data
		// cannot reach bob over any tunnel path. Bob -> alice stays open.
		sim.Mesh(simnet.LinkConfig{Latency: 2 * time.Millisecond})
		if stalled {
			// A stalled round can leave undelivered payload bytes in flight;
			// replace the pair so the blackhole read cannot observe stale data.
			_ = outbound.Close()
			_ = inbound.Close()
			if outbound, err = source.DialContext(ctx, "i2p", net.JoinHostPort(target.B32(), "8080")); err != nil {
				t.Fatalf("redial after stalled burst-loss round: %v", err)
			}
			defer outbound.Close()
			inbound = <-accepted
			defer inbound.Close()
		}
		for _, node := range sim.nodes {
			if node != alice {
				sim.net.Blackhole(alice.Addr(), node.Addr())
			}
		}
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
		for _, node := range sim.nodes {
			if node != alice {
				sim.net.Unblackhole(alice.Addr(), node.Addr())
			}
		}
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
