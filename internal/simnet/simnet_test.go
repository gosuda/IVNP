//go:build dst || synctest

package simnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestUDPDeliveryAndLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 1})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetLink(a.Addr(), b.Addr(), LinkConfig{Latency: 10 * time.Millisecond})

		sa, err := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		if err != nil {
			t.Fatal(err)
		}
		sb, err := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		if err != nil {
			t.Fatal(err)
		}

		start := time.Now()
		if _, err := sa.WriteToUDPAddrPort([]byte("ping"), netip.AddrPortFrom(b.Addr(), 9000)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		buf := make([]byte, 64)
		nr, from, err := sb.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:nr]); got != "ping" {
			t.Fatalf("payload = %q", got)
		}
		if from != sa.AddrPort() {
			t.Fatalf("source = %v, want %v", from, sa.AddrPort())
		}
		if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
			t.Fatalf("delivered after %v, before 10ms latency", elapsed)
		}
		if s := n.Stats(); s.Delivered != 1 || s.Dropped != 0 {
			t.Fatalf("stats = %+v", s)
		}
	})
}

func TestUDPDropRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 2})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetLink(a.Addr(), b.Addr(), LinkConfig{DropRate: 1.0})

		sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		sb.SetReadDeadline(time.Now().Add(time.Second))

		for range 8 {
			sa.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(b.Addr(), 9000))
		}
		synctest.Wait()

		_, _, err := sb.ReadFromUDPAddrPort(make([]byte, 8))
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("expected timeout, got %v", err)
		}
		if !os.IsTimeout(err) {
			t.Fatalf("os.IsTimeout = false for %v", err)
		}
		if s := n.Stats(); s.Dropped != 8 || s.Delivered != 0 {
			t.Fatalf("stats = %+v", s)
		}
	})
}

func TestUDPQueueDrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 3, UDPQueueLimit: 2})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")

		sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		dst := netip.AddrPortFrom(b.Addr(), 9000)
		for range 4 {
			sa.WriteToUDPAddrPort([]byte("x"), dst)
		}
		synctest.Wait()

		buf := make([]byte, 8)
		got := 0
		for {
			sb.SetReadDeadline(time.Now().Add(time.Millisecond))
			if _, _, err := sb.ReadFromUDPAddrPort(buf); err != nil {
				break
			}
			got++
		}
		if got != 2 {
			t.Fatalf("received %d, want 2", got)
		}
		if s := n.Stats(); s.QueueDropped != 2 {
			t.Fatalf("stats = %+v", s)
		}
	})
}

func TestUDPBindConflict(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{})
		defer n.Close()
		a := n.Host("a")
		if _, err := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000")); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000")); !errors.Is(err, ErrBound) {
			t.Fatalf("rebind err = %v", err)
		}
	})
}

func TestTCPEcho(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 4})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetBidirectional(a.Addr(), b.Addr(), LinkConfig{Latency: 5 * time.Millisecond})

		l, err := b.ListenTCP(netip.MustParseAddrPort("0.0.0.0:80"))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			io.Copy(c, c)
			c.Close()
		}()

		start := time.Now()
		conn, err := a.DialTCP(context.Background(), netip.AddrPortFrom(b.Addr(), 80))
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
			t.Fatalf("dial completed in %v < 5ms link latency", elapsed)
		}

		msg := []byte("hello simnet")
		go conn.Write(msg)
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("echo = %q", buf)
		}
		conn.Close()
		synctest.Wait()
	})
}

// TestTCPStreamOrderedUnderJitter pins the stream invariant real TCP gives:
// jitter may delay chunks but must never reorder the delivered byte stream.
func TestTCPStreamOrderedUnderJitter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 9})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetBidirectional(a.Addr(), b.Addr(), LinkConfig{Latency: 2 * time.Millisecond, Jitter: 2 * time.Millisecond})

		l, err := b.ListenTCP(netip.MustParseAddrPort("0.0.0.0:80"))
		if err != nil {
			t.Fatal(err)
		}
		received := make(chan byte, 256)
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 64)
			for {
				nr, err := c.Read(buf)
				for i := range nr {
					received <- buf[i]
				}
				if err != nil {
					return
				}
			}
		}()
		conn, err := a.DialTCP(context.Background(), netip.AddrPortFrom(b.Addr(), 80))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		const total = 64
		for i := range total {
			if _, err := conn.Write([]byte{byte(i)}); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		for i := range total {
			select {
			case got := <-received:
				if got != byte(i) {
					t.Fatalf("stream byte %d = %d: stream reordered", i, got)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("stream stalled after %d bytes", i)
			}
		}
	})
}

func TestTCPDialRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 5})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetLink(a.Addr(), b.Addr(), LinkConfig{Latency: time.Millisecond})

		_, err := a.DialTCP(context.Background(), netip.AddrPortFrom(b.Addr(), 9999))
		if !errors.Is(err, ErrConnRefused) {
			t.Fatalf("dial err = %v", err)
		}
		if s := n.Stats(); s.Refused != 1 {
			t.Fatalf("stats = %+v", s)
		}
	})
}

func TestTCPPartitionStallsThenResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 6})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetBidirectional(a.Addr(), b.Addr(), LinkConfig{Latency: time.Millisecond})

		l, _ := b.ListenTCP(netip.MustParseAddrPort("0.0.0.0:80"))
		go func() {
			c, _ := l.Accept()
			if c != nil {
				io.Copy(io.Discard, c)
			}
		}()
		conn, err := a.DialTCP(context.Background(), netip.AddrPortFrom(b.Addr(), 80))
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()

		n.Partition(a.Addr(), b.Addr())
		conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := conn.Read(make([]byte, 8)); !os.IsTimeout(err) {
			t.Fatalf("partitioned read = %v, want timeout", err)
		}

		// A dial through a partition stalls until its context ends.
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if _, err := a.DialTCP(ctx, netip.AddrPortFrom(b.Addr(), 80)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("partitioned dial = %v, want ctx deadline", err)
		}

		n.ResetLink(a.Addr(), b.Addr())
		if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, ErrConnReset) && !errors.Is(err, ErrClosed) {
			t.Fatalf("reset read = %v", err)
		}
	})
}

func TestDeterministicJitterSequence(t *testing.T) {
	run := func() []time.Duration {
		var seq []time.Duration
		synctest.Test(t, func(t *testing.T) {
			n := NewNetwork(Config{Seed: 42})
			defer n.Close()
			a, b := n.Host("a"), n.Host("b")
			n.SetLink(a.Addr(), b.Addr(), LinkConfig{Latency: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
			sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
			sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
			dst := netip.AddrPortFrom(b.Addr(), 9000)
			buf := make([]byte, 8)
			for range 6 {
				start := time.Now()
				sa.WriteToUDPAddrPort([]byte("x"), dst)
				sb.ReadFromUDPAddrPort(buf)
				seq = append(seq, time.Since(start))
			}
		})
		return seq
	}
	first, second := run(), run()
	if len(first) != len(second) {
		t.Fatal("length mismatch")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("run divergence at %d: %v vs %v", i, first[i], second[i])
		}
		if first[i] < 5*time.Millisecond || first[i] > 15*time.Millisecond {
			t.Fatalf("delay %v outside [5ms,15ms] jitter bound", first[i])
		}
	}
}

func TestTCPSlidingWindowReorderDrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const reorderWindow = 4
		n := NewNetwork(Config{Seed: 99, TCPReorderWindow: reorderWindow})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		l, err := b.ListenTCP(netip.MustParseAddrPort("0.0.0.0:8080"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := l.Accept()
			accepted <- c
		}()

		clientConn, err := a.DialTCP(context.Background(), netip.AddrPortFrom(b.Addr(), 8080))
		if err != nil {
			t.Fatal(err)
		}
		defer clientConn.Close()
		serverConn := <-accepted
		defer serverConn.Close()

		sc := serverConn.(*TCPConn)
		// deliverSegment with seq within window: recvSeq (0) + 2 < 0 + 4 -> buffered
		sc.deliverSegment(2, []byte("in-window"))
		sc.mu.Lock()
		if _, ok := sc.pending[2]; !ok {
			sc.mu.Unlock()
			t.Fatal("expected seq 2 to be buffered in pending")
		}
		sc.mu.Unlock()

		// deliverSegment with seq at or beyond window: recvSeq (0) + 4 >= 0 + 4 -> dropped
		sc.deliverSegment(4, []byte("out-of-window"))
		sc.mu.Lock()
		if _, ok := sc.pending[4]; ok {
			sc.mu.Unlock()
			t.Fatal("expected seq 4 to be dropped outside sliding window")
		}
		sc.mu.Unlock()

		if drops := n.Stats().Dropped; drops != 1 {
			t.Fatalf("expected 1 dropped out-of-window segment, got %d", drops)
		}
	})
}

func TestGilbertElliottBurstLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 1234})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetLink(a.Addr(), b.Addr(), LinkConfig{
			BurstLoss: &BurstLossConfig{
				PToBad:   0.3,
				PToGood:  0.2, // mean burst loss length: 5 packets
				LossGood: 0.0,
				LossBad:  1.0,
			},
		})

		sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		dst := netip.AddrPortFrom(b.Addr(), 9000)

		const total = 50
		for i := range total {
			sa.WriteToUDPAddrPort([]byte{byte(i)}, dst)
		}
		synctest.Wait()

		received := make(map[byte]bool)
		buf := make([]byte, 16)
		for {
			sb.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			nr, _, err := sb.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			received[buf[0]] = true
			_ = nr
		}

		stats := n.Stats()
		if stats.Dropped == 0 || stats.Delivered == 0 {
			t.Fatalf("expected both delivered and dropped packets under burst loss: %+v", stats)
		}

		// Verify burstiness: find at least one consecutive drop sequence of length >= 2
		consecutiveDrops := 0
		maxConsecutiveDrops := 0
		for i := range byte(total) {
			if !received[i] {
				consecutiveDrops++
				if consecutiveDrops > maxConsecutiveDrops {
					maxConsecutiveDrops = consecutiveDrops
				}
			} else {
				consecutiveDrops = 0
			}
		}
		if maxConsecutiveDrops < 2 {
			t.Fatalf("expected consecutive burst loss >= 2, got max %d (received %d of %d)", maxConsecutiveDrops, len(received), total)
		}
	})
}

func TestChineseStyleUDPDuplication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 55})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")
		n.SetLink(a.Addr(), b.Addr(), LinkConfig{
			Latency:        5 * time.Millisecond,
			DuplicateRate:  1.0,
			DuplicateDelay: 15 * time.Millisecond,
			DuplicateCount: 2, // 1 original + 2 duplicates = 3 total copies
		})

		sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		dst := netip.AddrPortFrom(b.Addr(), 9000)

		start := time.Now()
		sa.WriteToUDPAddrPort([]byte("gfw-duplicated-packet"), dst)
		synctest.Wait()

		buf := make([]byte, 64)
		var arrivalTimes []time.Duration
		for range 3 {
			sb.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			nr, _, err := sb.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("failed to read expected copy: %v", err)
			}
			arrivalTimes = append(arrivalTimes, time.Since(start))
			if string(buf[:nr]) != "gfw-duplicated-packet" {
				t.Fatalf("payload mismatch: %q", buf[:nr])
			}
		}

		// First copy arrives around 5ms (Latency)
		if arrivalTimes[0] < 5*time.Millisecond || arrivalTimes[0] >= 15*time.Millisecond {
			t.Fatalf("original arrived at %v, expected ~5ms", arrivalTimes[0])
		}
		// Duplicates arrive around 20ms (Latency + DuplicateDelay)
		for i := 1; i <= 2; i++ {
			if arrivalTimes[i] < 20*time.Millisecond {
				t.Fatalf("duplicate %d arrived too early at %v, expected >= 20ms", i, arrivalTimes[i])
			}
		}

		stats := n.Stats()
		if stats.Duplicated != 2 {
			t.Fatalf("expected 2 duplicate events, got %d (stats: %+v)", stats.Duplicated, stats)
		}
	})
}

func TestAsymmetricBlackhole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := NewNetwork(Config{Seed: 77})
		defer n.Close()
		a, b := n.Host("a"), n.Host("b")

		sa, _ := a.ListenUDP(netip.MustParseAddrPort("0.0.0.0:0"))
		sb, _ := b.ListenUDP(netip.MustParseAddrPort("0.0.0.0:9000"))
		addrA := sa.AddrPort()
		addrB := netip.AddrPortFrom(b.Addr(), 9000)

		// A -> B is blackholed, but B -> A is NOT blackholed
		n.Blackhole(a.Addr(), b.Addr())

		// A -> B must drop
		sa.WriteToUDPAddrPort([]byte("a-to-b"), addrB)
		synctest.Wait()

		buf := make([]byte, 32)
		sb.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, _, err := sb.ReadFromUDPAddrPort(buf); !os.IsTimeout(err) {
			t.Fatalf("expected timeout on blackholed A->B link, got %v", err)
		}

		// B -> A must deliver normally
		sb.WriteToUDPAddrPort([]byte("b-to-a"), addrA)
		synctest.Wait()

		sa.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		nr, _, err := sa.ReadFromUDPAddrPort(buf)
		if err != nil || string(buf[:nr]) != "b-to-a" {
			t.Fatalf("expected B->A to deliver successfully, got nr=%d err=%v", nr, err)
		}

		// Unblackhole restores A -> B
		n.Unblackhole(a.Addr(), b.Addr())
		sa.WriteToUDPAddrPort([]byte("a-to-b-restored"), addrB)
		synctest.Wait()

		sb.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		nr, _, err = sb.ReadFromUDPAddrPort(buf)
		if err != nil || string(buf[:nr]) != "a-to-b-restored" {
			t.Fatalf("expected restored A->B delivery, got nr=%d err=%v", nr, err)
		}
	})
}
