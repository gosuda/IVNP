//go:build integration

package ivnp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp"
)

// TestLiveI2PRoundTrip bootstraps two client-mode routers on the official
// I2P network (netId=2) using live HTTPS reseeds and real network peers.
// It verifies a wide spectrum of IVNP capabilities over live I2P:
// - Destination identity and .b32.i2p address resolution
// - Multi-port concurrent services on a single destination
// - Stream bidirectional echo, deadlines, and multi-chunk transfer
// - HTTP/1.1 client & server transport over live B32 destination (eepsite)
// - Cryptographically authenticated signed datagrams (i2p-datagram2)
// - Unauthenticated datagrams with metadata (i2p-datagram3)
// - Clean resource teardown and socket closure
func TestLiveI2PRoundTrip(t *testing.T) {
	if os.Getenv("IVNP_LIVE_ROUNDTRIP") != "1" {
		t.Skip("set IVNP_LIVE_ROUNDTRIP=1 to run the live I2P network round trip test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// 1. Configure Router A (target: server/responder)
	cfgA := ivnp.DefaultRouterConfig()
	cfgA.Persistence = &ivnp.PersistenceConfig{Directory: t.TempDir()}
	cfgA.Exploratory.Inbound.Hops = 1
	cfgA.Exploratory.Outbound.Hops = 1
	cfgA.Exploratory.Inbound.Count = 2
	cfgA.Exploratory.Outbound.Count = 2

	routerA, err := ivnp.NewRouter(ctx, cfgA)
	if err != nil {
		t.Fatalf("start target router A: %v", err)
	}
	defer routerA.Close()

	t.Log("Waiting for router A readiness on live I2P network...")
	if err := routerA.WaitReady(ctx); err != nil {
		t.Fatalf("wait for router A ready: %v", err)
	}
	t.Log("Router A ready on live I2P network.")

	// Create Target Destination on Router A
	destCfgA := ivnp.DefaultDestinationConfig()
	destCfgA.Tunnels.Inbound.Hops = 1
	destCfgA.Tunnels.Outbound.Hops = 1
	destCfgA.Tunnels.Inbound.Count = 2
	destCfgA.Tunnels.Outbound.Count = 2

	destA, err := routerA.NewDestination(ctx, destCfgA)
	if err != nil {
		t.Fatalf("create target destination A: %v", err)
	}
	defer destA.Close()

	targetB32 := destA.B32()
	t.Logf("Target destination A created: %s (hash: %s)", targetB32, destA.Hash())

	// Verify Destination identity invariants
	if len(targetB32) != 60 || !bytes.HasSuffix([]byte(targetB32), []byte(".b32.i2p")) {
		t.Fatalf("invalid target B32 address format: %q", targetB32)
	}
	if len(destA.Destination()) == 0 {
		t.Fatal("target destination binary bytes empty")
	}

	// 2. Configure Multi-Port Listeners on Destination A
	// - Port 8080: Raw Stream Echo
	streamListener, err := destA.Listen("i2p", ":8080")
	if err != nil {
		t.Fatalf("listen on target stream: %v", err)
	}
	defer streamListener.Close()

	// - Port 8082: HTTP Server (Eepsite)
	httpListener, err := destA.Listen("i2p", ":8082")
	if err != nil {
		t.Fatalf("listen on target HTTP: %v", err)
	}
	defer httpListener.Close()

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"network": "live-i2p",
		})
	})
	httpMux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Echoed-Header", r.Header.Get("X-IVNP-Header"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	httpServer := &http.Server{Handler: httpMux}
	go func() {
		_ = httpServer.Serve(httpListener)
	}()
	defer httpServer.Close()

	// - Port 8081: Authenticated Datagram (i2p-datagram2)
	packetReceiver2, err := destA.ListenPacket("i2p-datagram2", ":8081")
	if err != nil {
		t.Fatalf("listen on target datagram2: %v", err)
	}
	defer packetReceiver2.Close()

	// - Port 8083: Modern Datagram 3 (i2p-datagram3)
	packetReceiver3, err := destA.ListenUnauthPacket("i2p-datagram3", ":8083")
	if err != nil {
		t.Fatalf("listen on target datagram3: %v", err)
	}
	defer packetReceiver3.Close()

	// 3. Configure Router B (source: client/dialer)
	cfgB := ivnp.DefaultRouterConfig()
	cfgB.Persistence = &ivnp.PersistenceConfig{Directory: t.TempDir()}
	cfgB.Exploratory.Inbound.Hops = 1
	cfgB.Exploratory.Outbound.Hops = 1
	cfgB.Exploratory.Inbound.Count = 2
	cfgB.Exploratory.Outbound.Count = 2

	routerB, err := ivnp.NewRouter(ctx, cfgB)
	if err != nil {
		t.Fatalf("start source router B: %v", err)
	}
	defer routerB.Close()

	t.Log("Waiting for router B readiness on live I2P network...")
	if err := routerB.WaitReady(ctx); err != nil {
		t.Fatalf("wait for router B ready: %v", err)
	}
	t.Log("Router B ready on live I2P network.")

	// Create Source Destination on Router B
	destCfgB := ivnp.DefaultDestinationConfig()
	destCfgB.Tunnels.Inbound.Hops = 1
	destCfgB.Tunnels.Outbound.Hops = 1
	destCfgB.Tunnels.Inbound.Count = 2
	destCfgB.Tunnels.Outbound.Count = 2

	destB, err := routerB.NewDestination(ctx, destCfgB)
	if err != nil {
		t.Fatalf("create source destination B: %v", err)
	}
	defer destB.Close()
	t.Logf("Source destination B created: %s (hash: %s)", destB.B32(), destB.Hash())

	// 4. Test Address Resolution via destB
	t.Run("resolve target B32 address", func(t *testing.T) {
		resolved, resErr := destB.ResolveAddr(ctx, net.JoinHostPort(targetB32, "8080"))
		if resErr != nil {
			t.Fatalf("resolve target B32: %v", resErr)
		}
		if resolved.Hash != destA.Hash() {
			t.Fatalf("resolved hash = %v, want %v", resolved.Hash, destA.Hash())
		}
		if resolved.Port != 8080 {
			t.Fatalf("resolved port = %d, want 8080", resolved.Port)
		}
		if resolved.Network() != "i2p" {
			t.Fatalf("resolved network = %q, want i2p", resolved.Network())
		}
	})

	// 5. Test Streaming Ping-Pong, Deadlines & Chunked Data Transfer
	t.Run("streaming echo deadlines and chunked transfer", func(t *testing.T) {
		accepted := make(chan net.Conn, 4)
		acceptErr := make(chan error, 4)
		stopAccept := make(chan struct{})
		defer close(stopAccept)

		go func() {
			for {
				conn, acceptErrVal := streamListener.Accept()
				if acceptErrVal != nil {
					select {
					case acceptErr <- acceptErrVal:
					case <-stopAccept:
					}
					return
				}
				select {
				case accepted <- conn:
				case <-stopAccept:
					_ = conn.Close()
					return
				}
			}
		}()

		dialAddr := net.JoinHostPort(targetB32, "8080")
		backoff := 2 * time.Second

		var lastErr error
		for attempt := 1; attempt <= 3; attempt++ {
			// Drain any stale connection received from an earlier timed-out attempt
			for len(accepted) > 0 {
				stale := <-accepted
				_ = stale.Close()
			}

			t.Logf("Streaming transfer over live I2P (attempt %d/3)...", attempt)
			dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
			outbound, dialErr := destB.DialContext(dialCtx, "i2p", dialAddr)
			if dialErr != nil {
				dialCancel()
				lastErr = fmt.Errorf("dial: %w", dialErr)
				t.Logf("attempt %d dial failed: %v", attempt, dialErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			var inbound net.Conn
			var acceptFailed bool
			acceptTimer := time.NewTimer(15 * time.Second)
			for inbound == nil && !acceptFailed {
				select {
				case cand := <-accepted:
					if cand.RemoteAddr().String() == outbound.LocalAddr().String() {
						inbound = cand
					} else {
						t.Logf("attempt %d discarding stale connection from %s (want %s)", attempt, cand.RemoteAddr(), outbound.LocalAddr())
						_ = cand.Close()
					}
				case errVal := <-acceptErr:
					dialCancel()
					_ = outbound.Close()
					lastErr = fmt.Errorf("accept: %w", errVal)
					t.Logf("attempt %d accept failed: %v", attempt, errVal)
					acceptFailed = true
				case <-acceptTimer.C:
					dialCancel()
					_ = outbound.Close()
					lastErr = errors.New("timeout waiting for accepted connection")
					t.Logf("attempt %d timed out waiting for accepted connection", attempt)
					acceptFailed = true
				case <-ctx.Done():
					acceptTimer.Stop()
					dialCancel()
					_ = outbound.Close()
					t.Fatalf("context canceled: %v", ctx.Err())
				}
			}
			acceptTimer.Stop()
			if acceptFailed {
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}
			dialCancel()

			// Test SetDeadline on established connection
			deadline := time.Now().Add(60 * time.Second)
			if err := outbound.SetDeadline(deadline); err != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("outbound set deadline: %w", err)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}
			if err := inbound.SetDeadline(deadline); err != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("inbound set deadline: %w", err)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			// Ping: Source -> Target
			pingMsg := []byte("live-ping-stream-verification")
			if _, writeErr := outbound.Write(pingMsg); writeErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("write ping: %w", writeErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			recvBuf := make([]byte, len(pingMsg))
			if _, readErr := io.ReadFull(inbound, recvBuf); readErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("read ping: %w", readErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}
			if !bytes.Equal(recvBuf, pingMsg) {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("received %q, want %q", recvBuf, pingMsg)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			// Pong: Target -> Source
			pongMsg := []byte("live-pong-stream-response")
			if _, writeErr := inbound.Write(pongMsg); writeErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("write pong: %w", writeErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			recvBuf = make([]byte, len(pongMsg))
			if _, readErr := io.ReadFull(outbound, recvBuf); readErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("read pong: %w", readErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}
			if !bytes.Equal(recvBuf, pongMsg) {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("received %q, want %q", recvBuf, pongMsg)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			// Multi-chunk bulk data transfer test (8KB pseudo-random payload)
			payload := make([]byte, 8192)
			_, _ = rand.Read(payload)

			writeErrCh := make(chan error, 1)
			go func() {
				_, wErr := outbound.Write(payload)
				writeErrCh <- wErr
			}()

			receivedChunk := make([]byte, len(payload))
			if _, readErr := io.ReadFull(inbound, receivedChunk); readErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("read bulk chunk: %w", readErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}
			if !bytes.Equal(receivedChunk, payload) {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = errors.New("bulk chunk corrupted over live stream")
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			if wErr := <-writeErrCh; wErr != nil {
				_ = outbound.Close()
				_ = inbound.Close()
				lastErr = fmt.Errorf("write bulk chunk: %w", wErr)
				if attempt < 3 {
					time.Sleep(backoff)
					backoff *= 2
				}
				continue
			}

			_ = outbound.Close()
			_ = inbound.Close()
			lastErr = nil
			break
		}

		if lastErr != nil {
			t.Fatalf("streaming echo deadlines and chunked transfer failed after 3 attempts: %v", lastErr)
		}

		t.Log("Streaming echo, deadlines, and chunked transfer over live B32 succeeded.")
	})

	// 6. Test HTTP Transport (Eepsite) over live B32 Destination
	t.Run("http eepsite get and post over live B32", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: destB.DialContext,
			},
			Timeout: 45 * time.Second,
		}

		// GET /health
		healthURL := "http://" + net.JoinHostPort(targetB32, "8082") + "/health"
		resp, getErr := httpClient.Get(healthURL)
		if getErr != nil {
			t.Fatalf("HTTP GET /health: %v", getErr)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /health status = %d, want 200", resp.StatusCode)
		}
		var healthResp map[string]string
		if decErr := json.NewDecoder(resp.Body).Decode(&healthResp); decErr != nil {
			t.Fatalf("decode health JSON: %v", decErr)
		}
		if healthResp["status"] != "ok" || healthResp["network"] != "live-i2p" {
			t.Fatalf("unexpected health body: %v", healthResp)
		}

		// POST /echo
		echoURL := "http://" + net.JoinHostPort(targetB32, "8082") + "/echo"
		postPayload := []byte("hello-ivnp-http-live-integration")
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, echoURL, bytes.NewReader(postPayload))
		if reqErr != nil {
			t.Fatalf("create POST request: %v", reqErr)
		}
		req.Header.Set("X-IVNP-Header", "custom-live-value")

		postResp, postErr := httpClient.Do(req)
		if postErr != nil {
			t.Fatalf("HTTP POST /echo: %v", postErr)
		}
		defer postResp.Body.Close()

		if postResp.StatusCode != http.StatusOK {
			t.Fatalf("POST /echo status = %d, want 200", postResp.StatusCode)
		}
		if headerVal := postResp.Header.Get("X-Echoed-Header"); headerVal != "custom-live-value" {
			t.Fatalf("echoed header = %q, want custom-live-value", headerVal)
		}
		echoedBody, readErr := io.ReadAll(postResp.Body)
		if readErr != nil {
			t.Fatalf("read POST echo body: %v", readErr)
		}
		if !bytes.Equal(echoedBody, postPayload) {
			t.Fatalf("echoed body = %q, want %q", echoedBody, postPayload)
		}
		t.Log("HTTP client & server over live B32 destination succeeded.")
	})

	// 7. Test Signed Datagrams (i2p-datagram2)
	t.Run("signed authenticated datagram ping pong", func(t *testing.T) {
		packetSender2, packetErr := destB.ListenPacket("i2p-datagram2", ":0")
		if packetErr != nil {
			t.Fatalf("listen on source datagram2: %v", packetErr)
		}
		defer packetSender2.Close()

		dgramPing := []byte("live-ping-datagram2-authenticated")
		targetPacketAddr := packetReceiver2.LocalAddr()
		if _, writeErr := packetSender2.WriteTo(dgramPing, targetPacketAddr); writeErr != nil {
			t.Fatalf("send datagram ping: %v", writeErr)
		}

		recvBuf := make([]byte, 512)
		n, from, readErr := packetReceiver2.ReadFrom(recvBuf)
		if readErr != nil {
			t.Fatalf("receive datagram ping: %v", readErr)
		}
		if !bytes.Equal(recvBuf[:n], dgramPing) {
			t.Fatalf("received datagram %q, want %q", recvBuf[:n], dgramPing)
		}

		fromAddr, ok := from.(ivnp.Addr)
		if !ok || fromAddr.Hash != destB.Hash() {
			t.Fatalf("received datagram from unexpected hash: %v (want %v)", from, destB.Hash())
		}
		if fromAddr.Port == 0 {
			t.Fatal("ephemeral sender port was not preserved in datagram header")
		}

		// Pong datagram: Target -> Source (reply to verified 'from')
		dgramPong := []byte("live-pong-datagram2-response")
		if _, writeErr := packetReceiver2.WriteTo(dgramPong, from); writeErr != nil {
			t.Fatalf("send datagram pong: %v", writeErr)
		}

		n, fromPong, readErr := packetSender2.ReadFrom(recvBuf)
		if readErr != nil {
			t.Fatalf("receive datagram pong: %v", readErr)
		}
		if !bytes.Equal(recvBuf[:n], dgramPong) {
			t.Fatalf("received datagram reply %q, want %q", recvBuf[:n], dgramPong)
		}

		replyAddr, ok := fromPong.(ivnp.Addr)
		if !ok || replyAddr.Hash != destA.Hash() {
			t.Fatalf("received pong from unexpected hash: %v (want %v)", fromPong, destA.Hash())
		}
		if replyAddr.Port != 8081 {
			t.Fatalf("reply port = %d, want 8081", replyAddr.Port)
		}
		t.Log("Signed authenticated datagram ping-pong succeeded.")
	})

	// 8. Test Modern Datagrams 3 (i2p-datagram3)
	t.Run("datagram3 ping pong", func(t *testing.T) {
		packetSender3, packetErr := destB.ListenUnauthPacket("i2p-datagram3", ":0")
		if packetErr != nil {
			t.Fatalf("listen on source datagram3: %v", packetErr)
		}
		defer packetSender3.Close()

		dgram3Msg := []byte("live-datagram3-message")
		targetAddr3 := packetReceiver3.LocalAddr()
		if _, writeErr := packetSender3.WriteTo(dgram3Msg, targetAddr3); writeErr != nil {
			t.Fatalf("send datagram3: %v", writeErr)
		}

		recvBuf := make([]byte, 512)
		n, meta, readErr := packetReceiver3.ReadPacket(recvBuf)
		if readErr != nil {
			t.Fatalf("read datagram3: %v", readErr)
		}
		if !bytes.Equal(recvBuf[:n], dgram3Msg) {
			t.Fatalf("received datagram3 %q, want %q", recvBuf[:n], dgram3Msg)
		}
		if meta.HasClaimedSource && meta.ClaimedSource != destB.Hash() {
			t.Fatalf("claimed source = %v, want %v", meta.ClaimedSource, destB.Hash())
		}
		t.Log("Datagram3 transfer succeeded.")
	})
}
