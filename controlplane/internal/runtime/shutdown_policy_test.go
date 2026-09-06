package noderuntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/controlplane/internal/tunnel"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

type policyDrainTransport struct {
	ctx     context.Context
	cancel  context.CancelFunc
	entered chan struct{}
	once    sync.Once
}

func (m *policyDrainTransport) Start(ctx context.Context, _ dataplane.RouterTransportBindings) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	return nil
}
func (m *policyDrainTransport) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}
func (m *policyDrainTransport) Wait() error {
	if m.ctx != nil {
		<-m.ctx.Done()
	}
	return nil
}
func (m *policyDrainTransport) Status() dataplane.RouterTransportStatus {
	return dataplane.RouterTransportStatus{Running: m.ctx != nil && m.ctx.Err() == nil}
}
func (m *policyDrainTransport) Send(_ context.Context, _ foundation.Hash, message foundation.I2NPMessage) error {
	if message.Header.Type != foundation.I2NPTunnelData {
		return nil
	}
	m.once.Do(func() { close(m.entered) })
	<-m.ctx.Done()
	return m.ctx.Err()
}

func TestControllerCloseCancelsSendBeforeDrainingPolicyUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := daemonTestConfig(t)
		cfg.Tunnel.Enabled = true
		cfg.NTCP2.Enabled = false
		cfg.Tunnel.MaintenanceInterval = time.Hour
		transport := &policyDrainTransport{entered: make(chan struct{})}
		controller, err := NewController(cfg, ControllerOptions{Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = controller.Close(); _ = controller.Wait() })
		if err = controller.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		runtime := controller.clientRuntimeSnapshot()[0]
		owner := runtime.local.Hash()
		peer := foundation.Hash{1}
		now := uint64(time.Now().UnixMilli())
		expires := now + 60_000
		token, err := controller.tunnels.RegisterOutbound(dataplane.TunnelOutboundCircuit{Owner: owner, ID: 9001, FirstHop: peer, NextTunnelID: 9002, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		if err = runtime.pool.Add(tunnel.Entry{ID: 9001, Circuit: token, Owner: owner, Direction: tunnel.Outbound, Expires: expires}, now); err != nil {
			t.Fatal(err)
		}
		local, err := netdb.NewLocalLeaseSet2(runtime.local)
		if err != nil {
			t.Fatal(err)
		}
		if err = local.ReplaceInboundLeases([]foundation.NetworkDatabaseLease{{Gateway: peer, TunnelID: 9003, EndDate: expires}}); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 4096)
		n, err := local.MarshalTo(wire, now, runtime.local.Sign)
		if err != nil {
			t.Fatal(err)
		}
		if err = controller.database.HandleDatabaseStore(foundation.I2NPDatabaseStoreMessage{Key: owner, Type: foundation.I2NPStoreLeaseSet2, Data: wire[:n]}, false, now); err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() {
			sent <- runtime.sender.SendTunnel(context.Background(), dataplane.StreamingTunnelDelivery{From: owner, To: owner, Protocol: 17, Payload: []byte("pending policy send")})
		}()
		<-transport.entered
		updated := make(chan error, 1)
		go func() { updated <- controller.UpdateDestinationAddressPolicies(runtime.name, nil) }()
		synctest.Wait()
		select {
		case err := <-updated:
			t.Fatalf("policy update returned before active send drained: %v", err)
		default:
		}
		closed := make(chan error, 1)
		go func() { closed <- controller.Close() }()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := <-sent; !errors.Is(err, context.Canceled) {
			t.Fatalf("active send = %v", err)
		}
		if err := <-updated; err != nil {
			t.Fatal(err)
		}
	})
}
