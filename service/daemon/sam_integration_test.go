package daemon

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gosuda.org/ivnp/support/config"
)

func TestDaemonEmbeddedSAMReadinessTimeoutDestroysOwnerGraph(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	cfg := daemonTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	cfg.Tunnel.Enabled = true
	cfg.NTCP2.Enabled = false
	cfg.Tunnel.MaintenanceInterval = time.Hour
	cfg.SAM = config.Listener{Enabled: true, Address: config.Endpoint{Host: "127.0.0.1", Port: 0}, MaxConnections: 8, ReadinessTimeout: 100 * time.Millisecond}
	cfg.AddressBook = config.AddressBook{Enabled: true, StatePath: filepath.Join(cfg.StateDir, "addressbook.json"), MaxEntries: 100, MaxFileBytes: 1 << 20, MaxResponseBytes: 1 << 20}
	d, err := New(cfg, Options{Transport: network.transport()})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(context.Background()); err != nil {
		_ = d.Close()
		t.Fatal(err)
	}
	defer func() { _ = d.Close(); _ = d.Wait() }()
	before := len(d.clientRuntimeSnapshot())
	connection, err := net.Dial("tcp", d.samServer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	_, _ = io.WriteString(connection, "HELLO VERSION MIN=3.3 MAX=3.3\n")
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "RESULT=OK") {
		t.Fatalf("hello = %q, %v", line, err)
	}
	_, _ = io.WriteString(connection, "SESSION CREATE STYLE=RAW ID=daemon-live DESTINATION=TRANSIENT PROTOCOL=18\n")
	line, err = reader.ReadString('\n')
	if err != nil || line != "SESSION STATUS RESULT=I2P_ERROR MESSAGE=SESSION_NOT_READY\n" {
		t.Fatalf("session readiness timeout = %q, %v", line, err)
	}
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for len(d.clientRuntimeSnapshot()) != before {
		select {
		case <-deadline.C:
			t.Fatal("readiness timeout left the SAM destination graph registered")
		case <-ticker.C:
		}
	}
}
