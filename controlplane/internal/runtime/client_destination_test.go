package noderuntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
)

func TestNeutralDestinationControllerUsesDaemonOwnedIsolatedGraph(t *testing.T) {
	now := uint64(time.Now().UnixMilli())
	flood := daemonProductionFloodfill(t, now)
	network := newDaemonMemoryNetwork(flood, func() uint64 { return uint64(time.Now().UnixMilli()) })
	cfg := daemonTestConfig(t)
	cfg.StateDir = filepath.Dir(cfg.StatePath)
	cfg.Tunnel.Enabled = true
	cfg.NTCP2.Enabled = false
	cfg.Tunnel.MaintenanceInterval = time.Hour
	d, err := NewController(cfg, ControllerOptions{Transport: network.transport()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	beforeRuntime := d.clientRuntimeSnapshot()
	beforeDurable := len(d.bundle.DestinationPrivate)
	source, err := foundation.GenerateLegacyLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	public := string(source.Destination())
	controller := clientDestinationController{daemon: d}
	endpoint, err := controller.CreateDestination(context.Background(), destination.DestinationSpec{Local: source, Policy: destination.LeaseSetPolicy{CryptoTypes: []uint16{7, 6, 4}}})
	source.ReleaseSensitive()
	if err != nil {
		t.Fatal(err)
	}
	if string(endpoint.Destination()) != public {
		t.Fatal("controller did not clone supplied destination")
	}
	after := d.clientRuntimeSnapshot()
	if len(after) != len(beforeRuntime)+1 {
		t.Fatalf("runtime count = %d", len(after))
	}
	transient := after[len(after)-1]
	if transient.pool == beforeRuntime[0].pool || transient.pool.Owner() != endpoint.Hash() {
		t.Fatal("transient destination reused another owner pool")
	}
	if len(d.bundle.DestinationPrivate) != beforeDurable {
		t.Fatal("transient destination was persisted")
	}
	if err = controller.DestroyDestination(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if transient.active() {
		t.Fatal("DestroyDestination left transient graph active")
	}
	if len(d.clientRuntimeSnapshot()) != len(beforeRuntime) {
		t.Fatal("DestroyDestination left transient owner registered")
	}
}

func TestPreparationWaitsForDestinationPair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := daemonTestConfig(t)
		cfg.Tunnel.Enabled = true
		d, err := NewController(cfg, ControllerOptions{SocketRuntime: new(recordingSockets)})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		endpoint, err := d.DestinationController().CreateDestination(t.Context(), destination.DestinationSpec{})
		if err != nil {
			t.Fatal(err)
		}
		defer endpoint.Close()
		preparation := endpoint.(destination.PreparingDestinationEndpoint)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- preparation.PrepareDestination(ctx, foundation.Hash{19}) }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("preparation reached resolver before its owner pair existed: %v", err)
		default:
		}
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("pair wait cancellation = %v", err)
		}
	})
}

type missingDestinationPair struct{}

func (missingDestinationPair) Pair(uint64) (tunnel.CircuitPair, bool) {
	return tunnel.CircuitPair{}, false
}

func TestDestinationLookupDoesNotFallBackAfterPairLoss(t *testing.T) {
	payload, err := netdb.BuildDatabaseLookup(foundation.Hash{3}, netdb.LeaseSetLookup, requestReplyRouteCapture{gateway: foundation.Hash{2}, tunnel: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	direct := new(requestDirectCapture)
	throughTunnel := new(requestTunnelCapture)
	sender := muxRequestSender{sender: direct, tunnels: throughTunnel, pairs: missingDestinationPair{}, now: func() uint64 { return 100 }, private: true}
	message := foundation.I2NPMessage{Header: foundation.I2NPHeader{Type: foundation.I2NPDatabaseLookup, ID: 9, Expiration: 1000}, Payload: payload}
	if err := sender.Send(t.Context(), netdb.RouterRef{Hash: foundation.Hash{1}}, message); !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
		t.Fatalf("lookup after owner pair loss = %v", err)
	}
	if direct.calls != 0 || throughTunnel.calls != 0 {
		t.Fatalf("lookup escaped lost pair: direct=%d tunnel=%d", direct.calls, throughTunnel.calls)
	}
}

func TestDestinationLookupRejectsReusedOutboundCircuit(t *testing.T) {
	const now = uint64(100)
	owner := foundation.Hash{1}
	wire := new(requestDirectCapture)
	runtime := dataplane.TunnelNewRuntime(dataplane.TunnelRuntimeConfig{Sender: wire, Now: func() uint64 { return now }})
	token, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, Owner: owner, FirstHop: foundation.Hash{2}, NextTunnelID: 3, ExpiresAt: 1000})
	if err != nil {
		t.Fatal(err)
	}
	pool := tunnel.NewOwnedPool(owner, 1)
	if err := pool.Add(tunnel.Entry{ID: 1, Owner: owner, Circuit: token, Direction: tunnel.Outbound, Expires: 1000}, now); err != nil {
		t.Fatal(err)
	}
	runtime.RemoveCircuit(token)
	replacement, err := runtime.RegisterOutbound(dataplane.TunnelOutboundCircuit{ID: 1, Owner: foundation.Hash{9}, FirstHop: foundation.Hash{2}, NextTunnelID: 3, ExpiresAt: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.RemoveCircuit(replacement)
	path := destinationRequestPath{pool: pool, tunnels: runtime, now: func() uint64 { return now }}
	err = path.SendBlock(t.Context(), 1, dataplane.TunnelBlock{Delivery: dataplane.TunnelDeliveryRouter, Gateway: foundation.Hash{4}, Last: true, Data: []byte{1}})
	if !errors.Is(err, dataplane.TunnelErrCircuitNotFound) {
		t.Fatalf("lookup on reused circuit = %v", err)
	}
	if wire.calls != 0 {
		t.Fatal("lookup escaped through a replacement owner's circuit")
	}
}
func TestClientDestinationRejectsRemovedCryptoType5(t *testing.T) {
	controller := clientDestinationController{daemon: &Controller{
		destinationFactory: new(destinationRuntimeFactory),
		destinations:       new(dataplane.RouterDestinationManager),
	}}
	endpoint, err := controller.CreateDestination(context.Background(), destination.DestinationSpec{
		Policy: destination.LeaseSetPolicy{CryptoTypes: []uint16{5}},
	})
	if !errors.Is(err, errDestinationCryptoTypes) || endpoint != nil {
		t.Fatalf("CreateDestination(type 5) = %#v, %v", endpoint, err)
	}
}

func TestClientDestinationRejectsOfflineDatagram1(t *testing.T) {
	longTerm, err := foundation.GenerateLocalDestination()
	if err != nil {
		t.Fatal(err)
	}
	defer longTerm.ReleaseSensitive()
	state := make([]byte, longTerm.PrivateEncodedLen())
	defer clear(state)
	if _, err := longTerm.MarshalPrivateTo(state); err != nil {
		t.Fatal(err)
	}
	publicLength := int(binary.BigEndian.Uint16(state[:2]))
	clear(state[2+publicLength : 2+publicLength+ed25519.PrivateKeySize])
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	seed := private.Seed()
	defer clear(seed)
	offline := foundation.OfflineSignature{
		Expires: uint32(time.Now().Add(time.Hour).Unix()),
		Type:    foundation.SigningEdDSASHA512Ed25519, PublicKey: public,
	}
	var content [6 + ed25519.PublicKeySize]byte
	n, err := offline.MarshalSignedContentTo(content[:])
	if err != nil {
		t.Fatal(err)
	}
	offline.Signature, err = longTerm.Sign(content[:n])
	if err != nil {
		t.Fatal(err)
	}
	local, err := foundation.ImportLocalDestinationOffline(state, offline, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer local.ReleaseSensitive()
	endpoint := &clientDestinationEndpoint{runtime: &destinationRuntime{local: local}}
	var packet [1024]byte
	if n, err := endpoint.MarshalDatagramV1To(packet[:], []byte("hello")); n != 0 || !errors.Is(err, foundation.ErrInvalidIdentity) {
		t.Fatalf("offline Datagram1 = %d, %v; want invalid identity", n, err)
	}
}
