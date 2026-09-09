package noderuntime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/state"
)

var errTestNoConnectedPeers = errors.New("no connected peers")

type idleNodeTransport struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (m *idleNodeTransport) Start(ctx context.Context, _ dataplane.RouterTransportBindings) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	return nil
}
func (m *idleNodeTransport) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}
func (m *idleNodeTransport) Wait() error {
	if m.ctx != nil {
		<-m.ctx.Done()
	}
	return nil
}
func (m *idleNodeTransport) Send(context.Context, foundation.Hash, foundation.I2NPMessage) error {
	return errTestNoConnectedPeers
}
func (m *idleNodeTransport) Status() dataplane.RouterTransportStatus {
	return dataplane.RouterTransportStatus{Running: m.ctx != nil && m.ctx.Err() == nil}
}

func TestDaemonEmbeddedSAMReadinessTimeoutDestroysOwnerGraph(t *testing.T) {
	cfg := nodeTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	cfg.Tunnel.Enabled = true
	cfg.NTCP2.Enabled = false
	cfg.Tunnel.MaintenanceInterval = time.Hour
	cfg.SAM = state.ConfigurationListener{Enabled: true, Address: state.ConfigurationEndpoint{Host: "127.0.0.1"}, MaxConnections: 8, ReadinessTimeout: 100 * time.Millisecond}
	cfg.AddressBook = state.ConfigurationAddressBook{Enabled: true, StatePath: filepath.Join(cfg.StateDir, "addressbook.json"), MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20}
	d, err := New(cfg, Options{Transport: &idleNodeTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close(); _ = d.Wait() })
	if err = d.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := d.ActiveDestinationCount()
	connection, err := net.Dial("tcp", d.samServer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	if _, err = io.WriteString(connection, "HELLO VERSION MIN=3.3 MAX=3.3\n"); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "RESULT=OK") {
		t.Fatalf("hello = %q, %v", line, err)
	}
	if _, err = io.WriteString(connection, "SESSION CREATE STYLE=RAW ID=daemon-live DESTINATION=TRANSIENT PROTOCOL=18\n"); err != nil {
		t.Fatal(err)
	}
	line, err = reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "RESULT=I2P_ERROR") {
		t.Fatalf("session readiness timeout = %q, %v", line, err)
	}
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for d.ActiveDestinationCount() != before {
		select {
		case <-deadline.C:
			t.Fatal("readiness timeout left the SAM destination graph registered")
		case <-ticker.C:
		}
	}
}
