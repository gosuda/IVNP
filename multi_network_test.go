package ivnp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"gosuda.org/ivnp/dataplane"
)

// multiNetTestConfig builds a two-context router configuration: the "i2p"
// public context on netId 2 and a dedicated "corp" context on netId 77. The
// contexts share nothing — each has its own transports, NetDB, and state
// directory — so a dedicated network is literally a second I2P instance.
func multiNetTestConfig(t *testing.T) RouterConfig {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultRouterConfig()
	cfg.Persistence = &PersistenceConfig{Directory: base}
	pool := TunnelPoolConfig{
		Inbound:     TunnelDirectionConfig{Hops: 1, Count: 1},
		Outbound:    TunnelDirectionConfig{Hops: 1, Count: 1},
		RenewBefore: 10 * time.Second,
	}
	transport := TransportConfig{
		Enabled:     true,
		Bind:        netip.MustParseAddrPort("127.0.0.1:0"),
		Advertised:  netip.MustParseAddrPort("192.0.2.1:12345"),
		MaxSessions: 256, IdleTimeout: 10 * time.Minute,
	}
	cfg.SetNetworks(
		NetworkConfig{Name: networkNativeName, NetworkID: NetworkIDPublicI2P, NTCP2: transport, Exploratory: pool},
		NetworkConfig{Name: "corp", NetworkID: 77, NTCP2: transport, Exploratory: pool},
	)
	return cfg
}

// TestEmbeddedMultiNetworkDestination binds one destination to the public and
// a dedicated network, then checks that unqualified dials race both, named
// dials isolate one context, and one merged listen accepts from either.
func TestEmbeddedMultiNetworkDestination(t *testing.T) {
	flood2 := embeddedTestFloodfillNet(t, 2)
	flood77 := embeddedTestFloodfillNet(t, 77)
	net2 := newEmbeddedMemoryNetwork(flood2)
	net77 := newEmbeddedMemoryNetwork(flood77)

	transportsFor := func(t2, t77 *embeddedMemoryTransport) func(string) dataplane.RouterTransportManager {
		return func(name string) dataplane.RouterTransportManager {
			if name == "corp" {
				return t77
			}
			return t2
		}
	}

	// Boot once per router to publish each context's RouterInfo, then seed the
	// peer RIs into the matching context's bootstrap set — a net-77 context
	// rejects netId-2 records, so the two meshes stay isolated.
	configs := []RouterConfig{multiNetTestConfig(t), multiNetTestConfig(t), multiNetTestConfig(t)}
	infos2 := make([][]byte, len(configs))
	infos77 := make([][]byte, len(configs))
	for i := range configs {
		t2, t77 := net2.transport(), net77.transport()
		router := newEmbeddedTestRouterN(t, configs[i], transportsFor(t2, t77))
		infos2[i] = append([]byte(nil), t2.routerInfo().Bytes()...)
		infos77[i] = append([]byte(nil), t77.routerInfo().Bytes()...)
		if len(infos2[i]) == 0 || len(infos77[i]) == 0 {
			t.Fatal("context did not publish its RouterInfo")
		}
		if err := router.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for i := range configs {
		seeds2 := [][]byte{flood2.Bytes()}
		seeds77 := [][]byte{flood77.Bytes()}
		for j := range configs {
			if j != i {
				seeds2 = append(seeds2, infos2[j])
				seeds77 = append(seeds77, infos77[j])
			}
		}
		configs[i].Networks[0].Bootstrap.RouterInfos = seeds2
		configs[i].Networks[1].Bootstrap.RouterInfos = seeds77
	}

	routers := make([]*Router, 0, len(configs))
	for _, cfg := range configs {
		routers = append(routers, newEmbeddedTestRouterN(t, cfg, transportsFor(net2.transport(), net77.transport())))
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()
	destinationConfig := DefaultDestinationConfig()
	destinationConfig.Tunnels = configs[0].Networks[0].Exploratory
	// The dedicated network is listed first, so unqualified dials prefer it and
	// the public context hedges 250ms later.
	destinationConfig.Networks = []string{"corp", networkNativeName}
	source, err := routers[0].NewDestination(ctx, destinationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := routers[1].NewDestination(ctx, destinationConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if got := target.Networks(); len(got) != 2 || got[0] != "corp" || got[1] != networkNativeName {
		t.Fatalf("bound networks = %v", got)
	}

	// One listen address accepts on every bound network.
	listener, err := target.Listen("ivnp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- conn
		}
	}()

	echo := func(t *testing.T, network string) {
		t.Helper()
		outbound, err := source.DialContext(ctx, network, net.JoinHostPort(target.B32(), "8080"))
		if err != nil {
			t.Fatalf("dial %q: %v", network, err)
		}
		defer outbound.Close()
		var inbound net.Conn
		select {
		case inbound = <-accepted:
		case <-ctx.Done():
			t.Fatalf("accept after %q dial: %v", network, ctx.Err())
		}
		defer inbound.Close()
		deadline := time.Now().Add(5 * time.Second)
		if err = outbound.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if err = inbound.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		payload := []byte("over " + network)
		if _, err = outbound.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(inbound, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(payload) {
			t.Fatalf("received %q, want %q", got, payload)
		}
	}

	// The dedicated context alone proves the same address space lives on a
	// separate NetDB; the raced and named-public paths prove dual reachability.
	echo(t, "corp")
	echo(t, networkNativeName)
	echo(t, "ivnp")

	// A datagram socket on the dedicated context only.
	sender, err := source.ListenPacket("corp-datagram2", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := target.ListenPacket("corp-datagram2", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err = sender.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	request := []byte("dedicated datagram")
	if n, err := sender.WriteTo(request, receiver.LocalAddr()); err != nil || n != len(request) {
		t.Fatalf("send dedicated datagram: bytes=%d error=%v", n, err)
	}
	buffer := make([]byte, 128)
	n, from, err := receiver.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(request) {
		t.Fatalf("dedicated datagram = %q, want %q", buffer[:n], request)
	}
	if address, ok := from.(Addr); !ok || address.Hash != source.Hash() {
		t.Fatalf("dedicated datagram source = %v", from)
	}
}
