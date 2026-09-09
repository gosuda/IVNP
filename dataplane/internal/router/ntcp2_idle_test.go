package router

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	dataplanentcp2 "gosuda.org/ivnp/dataplane/internal/transport/ntcp2"
	"gosuda.org/ivnp/foundation"
)

func TestNTCP2IdleTimeoutRenewsOnReadOrWrite(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				left, right := net.Pipe()
				manager := &NTCP2Manager{idleTimeout: time.Minute}
				conn := manager.establishedConn(left)
				defer conn.Close()
				defer right.Close()
				activity := time.NewTicker(45 * time.Second)
				defer activity.Stop()
				for range 3 {
					<-activity.C
					done := make(chan error, 1)
					reader, writer := conn, right
					if operation == "write" {
						reader, writer = right, conn
					}
					go func() {
						_, err := writer.Write([]byte{42})
						done <- err
					}()
					var payload [1]byte
					if _, err := io.ReadFull(reader, payload[:]); err != nil {
						t.Fatalf("active %s session closed: %v", operation, err)
					}
					if err := <-done; err != nil {
						t.Fatalf("active transfer failed: %v", err)
					}
					if payload[0] != 42 {
						t.Fatalf("payload = %d, want 42", payload[0])
					}
				}
				activity.Stop()
				idleSince := time.Now()
				if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("idle read error = %v, want closed pipe", err)
				}
				if elapsed := time.Since(idleSince); elapsed != time.Minute {
					t.Fatalf("idle session closed after %s, want %s", elapsed, time.Minute)
				}
			})
		})
	}
}

func TestNTCP2IdleTimeoutRetiresSessionAndUnblocksIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, static, iv := newNTCP2TestLocal(t, "127.0.0.1:1")
		manager, err := NewNTCP2Manager(NTCP2ManagerConfig{StaticPrivate: static, StaticIV: iv, NetworkID: 2, IdleTimeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context(), TransportBindings{
			LocalInfo: local, Clock: WallClock{},
			HandleI2NP: func(foundation.I2NPMessage, uint64, bool) error { return nil },
		}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = manager.Close()
			if err := manager.Wait(); err != nil {
				t.Error(err)
			}
		}()
		left, right := net.Pipe()
		defer right.Close()
		newDirection := func() *dataplanentcp2.Direction {
			direction, err := dataplanentcp2.NewDirection(make([]byte, 32), make([]byte, 16), make([]byte, 8))
			if err != nil {
				t.Fatal(err)
			}
			return direction
		}
		session := dataplanentcp2.NewSession(manager.establishedConn(left), newDirection(), newDirection())
		peer := foundation.Hash{1}
		if !manager.install(peer, session) {
			t.Fatal("session installation failed")
		}
		writeDone := make(chan error, 1)
		idleSince := time.Now()
		go func() { writeDone <- session.Write([]byte{1}) }()
		synctest.Wait()
		if err := <-writeDone; !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("pending write error = %v, want closed pipe", err)
		}
		if elapsed := time.Since(idleSince); elapsed != time.Minute {
			t.Fatalf("blocked session closed after %s, want %s", elapsed, time.Minute)
		}
		synctest.Wait()
		if manager.HasSession(peer) {
			t.Fatal("idle session remains available")
		}
		if _, err := right.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("remote read error = %v, want EOF", err)
		}
	})
}

func TestNTCP2ActivityPreservesCallerReadDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		manager := &NTCP2Manager{idleTimeout: time.Minute}
		conn := manager.establishedConn(left)
		defer conn.Close()
		defer right.Close()
		readDeadline := time.Now().Add(10 * time.Second)
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			t.Fatal(err)
		}
		activity := time.NewTimer(5 * time.Second)
		defer activity.Stop()
		<-activity.C
		done := make(chan error, 1)
		go func() {
			_, err := right.Read(make([]byte, 1))
			done <- err
		}()
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read error = %v, want caller deadline exceeded", err)
		}
		if !time.Now().Equal(readDeadline) {
			t.Fatalf("read completed at %s, want original deadline %s", time.Now(), readDeadline)
		}
	})
}
