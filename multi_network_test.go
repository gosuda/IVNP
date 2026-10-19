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
	"gosuda.org/ivnp/foundation"
)

// multiNetTestConfig builds a two-context router configuration: the "i2p"
// public context on netId 2 and a dedicated "corp" context on netId 77. The
// contexts share nothing (each has its own transports, NetDB, and state
// directory), so a dedicated network operates as a second I2P instance.
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
	// peer RIs into the matching context's bootstrap set; a net-77 context
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

// TestEmbeddedTwoNodeOfficeLANMesh verifies that a 2-node office LAN mesh on a
// shared /24 subnet forms 1-hop exploratory and client tunnels, publishes
// LeaseSets without a dedicated third-party floodfill, and exchanges stream
// traffic using NewOfficeLANNetwork and OfficeLANDestinationConfig.
func TestEmbeddedTwoNodeOfficeLANMesh(t *testing.T) {
	const netID = 88
	mesh := newEmbeddedMemoryNetwork(foundation.NetworkDatabaseRouterInfo{})

	makeNodeConfig := func(t *testing.T, advertised string) RouterConfig {
		t.Helper()
		base := t.TempDir()
		if err := os.Chmod(base, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultRouterConfig()
		cfg.Persistence = &PersistenceConfig{Directory: base}
		bind := netip.MustParseAddrPort("127.0.0.1:0")
		adv := netip.MustParseAddrPort(advertised)
		cfg.SetNetworks(NewOfficeLANNetwork(
			"office",
			netID,
			WithListenAddress(bind, bind),
			WithAdvertisedAddress(adv, adv),
		))
		return cfg
	}

	configs := []RouterConfig{
		makeNodeConfig(t, "192.0.2.10:19001"),
		makeNodeConfig(t, "192.0.2.11:19002"),
	}
	infos := make([][]byte, len(configs))
	for i := range configs {
		tr := mesh.transport()
		router := newEmbeddedTestRouterN(t, configs[i], func(string) dataplane.RouterTransportManager { return tr })
		infos[i] = append([]byte(nil), tr.routerInfo().Bytes()...)
		if len(infos[i]) == 0 {
			t.Fatal("office node did not publish its RouterInfo")
		}
		if err := router.Close(); err != nil {
			t.Fatal(err)
		}
	}
	configs[0].Networks[0].Bootstrap.RouterInfos = [][]byte{infos[1]}
	configs[1].Networks[0].Bootstrap.RouterInfos = [][]byte{infos[0]}

	routers := make([]*Router, len(configs))
	for i, cfg := range configs {
		tr := mesh.transport()
		routers[i] = newEmbeddedTestRouterN(t, cfg, func(string) dataplane.RouterTransportManager { return tr })
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()
	destCfg := OfficeLANDestinationConfig()
	destCfg.Networks = []string{"office"}
	source, err := routers[0].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := routers[1].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	listener, err := target.Listen("office", ":9090")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	outbound, err := source.DialContext(ctx, "office", net.JoinHostPort(target.B32(), "9090"))
	if err != nil {
		t.Fatalf("2-node office dial failed: %v", err)
	}
	defer outbound.Close()

	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-ctx.Done():
		t.Fatalf("2-node office accept timed out: %v", ctx.Err())
	}
	defer inbound.Close()

	deadline := time.Now().Add(5 * time.Second)
	_ = outbound.SetDeadline(deadline)
	_ = inbound.SetDeadline(deadline)
	payload := []byte("two-node office lan")
	if _, err := outbound.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(inbound, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}
}

// TestEmbeddedSmallPrivateMeshWithPeerAdmission verifies that a 3-node
// SmallPrivate mesh on a shared /24 subnet builds 2-hop client tunnels,
// confirms K = 2 LeaseSet2 publications, exchanges stream and Datagram2
// traffic, and enforces PeerAdmission allowlists.
func TestEmbeddedSmallPrivateMeshWithPeerAdmission(t *testing.T) {
	const netID = 42
	mesh := newEmbeddedMemoryNetwork(foundation.NetworkDatabaseRouterInfo{})

	makeNodeConfig := func(t *testing.T, advertised string, opts ...NetworkOption) RouterConfig {
		t.Helper()
		base := t.TempDir()
		if err := os.Chmod(base, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultRouterConfig()
		cfg.Persistence = &PersistenceConfig{Directory: base}
		bind := netip.MustParseAddrPort("127.0.0.1:0")
		adv := netip.MustParseAddrPort(advertised)
		baseOpts := []NetworkOption{
			WithListenAddress(bind, bind),
			WithAdvertisedAddress(adv, adv),
		}
		baseOpts = append(baseOpts, opts...)
		cfg.SetNetworks(NewSmallPrivateNetwork("priv", netID, baseOpts...))
		return cfg
	}

	configs := []RouterConfig{
		makeNodeConfig(t, "192.0.2.21:19101"),
		makeNodeConfig(t, "192.0.2.22:19102"),
		makeNodeConfig(t, "192.0.2.23:19103"),
	}
	infos := make([][]byte, len(configs))
	allowedHashes := make([]Hash, len(configs))
	for i := range configs {
		tr := mesh.transport()
		router := newEmbeddedTestRouterN(t, configs[i], func(string) dataplane.RouterTransportManager { return tr })
		infos[i] = append([]byte(nil), tr.routerInfo().Bytes()...)
		allowedHashes[i] = router.Hash()
		if len(infos[i]) == 0 {
			t.Fatal("small-private node did not publish its RouterInfo")
		}
		if err := router.Close(); err != nil {
			t.Fatal(err)
		}
	}

	admitAllowed := AdmitPeers(allowedHashes...)
	var outsider Hash
	outsider[0] = 0xff
	if err := admitAllowed(context.Background(), PeerAdmission{Peer: outsider}); err == nil {
		t.Fatal("AdmitPeers admitted unlisted outsider hash")
	}

	for i := range configs {
		var seeds [][]byte
		for j := range configs {
			if j != i {
				seeds = append(seeds, infos[j])
			}
		}
		configs[i].Networks[0].Bootstrap.RouterInfos = seeds
		configs[i].Networks[0].AdmitPeer = admitAllowed
	}

	routers := make([]*Router, len(configs))
	for i, cfg := range configs {
		tr := mesh.transport()
		routers[i] = newEmbeddedTestRouterN(t, cfg, func(string) dataplane.RouterTransportManager { return tr })
	}

	ctx, cancel := context.WithTimeout(context.Background(), embeddedTestTimeout)
	defer cancel()
	destCfg := SmallPrivateDestinationConfig()
	destCfg.Networks = []string{"priv"}
	source, err := routers[0].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := routers[2].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	listener, err := target.Listen("priv", ":9092")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	outbound, err := source.DialContext(ctx, "priv", net.JoinHostPort(target.B32(), "9092"))
	if err != nil {
		t.Fatalf("small-private 2-hop dial failed: %v", err)
	}
	defer outbound.Close()

	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-ctx.Done():
		t.Fatalf("small-private accept timed out: %v", ctx.Err())
	}
	defer inbound.Close()

	deadline := time.Now().Add(5 * time.Second)
	_ = outbound.SetDeadline(deadline)
	_ = inbound.SetDeadline(deadline)
	payload := []byte("small-private-2hop-stream")
	if _, err := outbound.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(inbound, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}

	sender, err := source.ListenPacket("priv-datagram2", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := target.ListenPacket("priv-datagram2", ":9093")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	_ = sender.SetDeadline(deadline)
	_ = receiver.SetDeadline(deadline)
	dgram := []byte("small-private-2hop-datagram2")
	if _, err := sender.WriteTo(dgram, receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, from, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(dgram) {
		t.Fatalf("datagram = %q, want %q", buf[:n], dgram)
	}
	if addr, ok := from.(Addr); !ok || addr.Hash != source.Hash() {
		t.Fatalf("datagram sender = %v, want %v", from, source.Hash())
	}
}

type loopbackSocketRuntime struct {
	virtualByPort map[uint16]netip.AddrPort
}

func (r *loopbackSocketRuntime) ListenStream(_ context.Context, endpoint dataplane.RouterEndpoint) (net.Listener, error) {
	return net.Listen("tcp", endpoint.Address)
}

func (r *loopbackSocketRuntime) DialStream(ctx context.Context, endpoint dataplane.RouterEndpoint) (net.Conn, error) {
	addrPort, err := netip.ParseAddrPort(endpoint.Address)
	if err != nil {
		return nil, err
	}
	target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), addrPort.Port())
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target.String())
}

func (r *loopbackSocketRuntime) ListenUDP(_ context.Context, endpoint dataplane.RouterEndpoint) (dataplane.RouterUDPSocket, error) {
	addr, err := net.ResolveUDPAddr("udp", endpoint.Address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &loopbackUDPSocket{UDPConn: conn, virtualByPort: r.virtualByPort}, nil
}

type loopbackUDPSocket struct {
	*net.UDPConn
	virtualByPort map[uint16]netip.AddrPort
}

func (s *loopbackUDPSocket) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := s.UDPConn.ReadFromUDPAddrPort(b)
	if err == nil {
		if mapped, ok := s.virtualByPort[addr.Port()]; ok {
			addr = mapped
		}
	}
	return n, addr, err
}

func (s *loopbackUDPSocket) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), addr.Port())
	return s.UDPConn.WriteToUDPAddrPort(b, target)
}

// TestE2ELoopbackOfficeLANMesh boots two real embedded Routers over live
// kernel TCP/UDP loopback sockets using NewOfficeLANNetwork, exchanges their
// signed RouterInfos, waits for router readiness, and verifies end-to-end
// streaming and Datagram2 communication.
func TestE2ELoopbackOfficeLANMesh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	reserveLoopbackPair := func(t *testing.T) (netip.AddrPort, netip.AddrPort) {
		t.Helper()
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcpAddr := netip.MustParseAddrPort(tcpLn.Addr().String())
		_ = tcpLn.Close()

		udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udpAddr := netip.MustParseAddrPort(udpConn.LocalAddr().String())
		_ = udpConn.Close()
		return tcpAddr, udpAddr
	}

	sockRuntime := &loopbackSocketRuntime{virtualByPort: make(map[uint16]netip.AddrPort)}
	routers := make([]*Router, 2)
	virtualHosts := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.11"),
	}
	for i := range routers {
		tcpBind, udpBind := reserveLoopbackPair(t)
		tcpAdv := netip.AddrPortFrom(virtualHosts[i], tcpBind.Port())
		udpAdv := netip.AddrPortFrom(virtualHosts[i], udpBind.Port())
		sockRuntime.virtualByPort[tcpBind.Port()] = tcpAdv
		sockRuntime.virtualByPort[udpBind.Port()] = udpAdv

		cfg := DefaultRouterConfig()
		cfg.SetNetworks(NewOfficeLANNetwork(
			"lan",
			88,
			WithListenAddress(tcpBind, udpBind),
			WithAdvertisedAddress(tcpAdv, udpAdv),
			WithTunnelTiming(2*time.Second, 5*time.Second, 1),
		))
		specs, def, err := networkSpecs(cfg)
		if err != nil {
			t.Fatalf("networkSpecs %d: %v", i, err)
		}
		for j := range specs {
			specs[j].Options.SocketRuntime = sockRuntime
		}
		r, err := newRouter(ctx, cfg, specs, def)
		if err != nil {
			t.Fatalf("start loopback office router %d: %v", i, err)
		}
		t.Cleanup(func() { _ = r.Close() })
		routers[i] = r
	}

	ri0, err := routers[0].Node().ExportLocalRouterInfo("lan")
	if err != nil {
		t.Fatalf("export router 0 RouterInfo: %v", err)
	}
	ri1, err := routers[1].Node().ExportLocalRouterInfo("lan")
	if err != nil {
		t.Fatalf("export router 1 RouterInfo: %v", err)
	}
	if _, err := routers[0].Node().ImportRouterInfo(ctx, "lan", ri1); err != nil {
		t.Fatalf("import router 1 RouterInfo into router 0: %v", err)
	}
	if _, err := routers[1].Node().ImportRouterInfo(ctx, "lan", ri0); err != nil {
		t.Fatalf("import router 0 RouterInfo into router 1: %v", err)
	}

	for i, r := range routers {
		if err := r.WaitReady(ctx); err != nil {
			t.Fatalf("router %d WaitReady: %v", i, err)
		}
	}

	destCfg := OfficeLANDestinationConfig()
	destCfg.Networks = []string{"lan"}
	source, err := routers[0].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatalf("router 0 NewDestination: %v", err)
	}
	defer source.Close()
	target, err := routers[1].NewDestination(ctx, destCfg)
	if err != nil {
		t.Fatalf("router 1 NewDestination: %v", err)
	}
	defer target.Close()

	listener, err := target.Listen("lan", ":8080")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	outbound, err := source.DialContext(ctx, "lan", net.JoinHostPort(target.B32(), "8080"))
	if err != nil {
		t.Fatalf("live loopback office dial: %v", err)
	}
	defer outbound.Close()

	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-ctx.Done():
		t.Fatalf("live loopback office accept timed out: %v", ctx.Err())
	}
	defer inbound.Close()

	deadline := time.Now().Add(10 * time.Second)
	_ = outbound.SetDeadline(deadline)
	_ = inbound.SetDeadline(deadline)
	msg := []byte("live-kernel-loopback-office-lan")
	if _, err := outbound.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(inbound, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}
