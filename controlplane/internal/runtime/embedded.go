package noderuntime

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"gosuda.org/ivnp/controlplane/internal/netdb"
	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
	"gosuda.org/ivnp/interfaces/destination"
	"gosuda.org/ivnp/state"
)

func validateEmbeddedPool(pool destination.TunnelPoolConfig) error {
	for _, direction := range [...]destination.TunnelDirectionConfig{pool.Inbound, pool.Outbound} {
		if direction.Hops < 1 || direction.Hops > 7 {
			return fmt.Errorf("%w: invalid embedded tunnel hops", state.ConfigurationErrInvalidOperating)
		}
		if direction.Count < 1 || direction.Count > 16 {
			return fmt.Errorf("%w: invalid embedded tunnel count", state.ConfigurationErrInvalidOperating)
		}
		validBackup := direction.Backup >= 0 && direction.Backup <= 15
		if !validBackup || direction.Count+direction.Backup > 16 {
			return fmt.Errorf("%w: invalid embedded tunnel direction", state.ConfigurationErrInvalidOperating)
		}
	}
	if pool.RenewBefore < time.Second || pool.RenewBefore >= 10*time.Minute {
		return fmt.Errorf("%w: invalid embedded tunnel renewal lead time", state.ConfigurationErrInvalidOperating)
	}
	if pool.BuildPendingCapacity < 0 || pool.BuildPendingCapacity > 256 {
		return fmt.Errorf("%w: invalid embedded tunnel build pending capacity", state.ConfigurationErrInvalidOperating)
	}
	return nil
}

func validateBootstrapRouterInfo(wire []byte, cfg state.ConfigurationOperating, now uint64) (foundation.NetworkDatabaseRouterInfo, error) {
	info, err := foundation.NetworkDatabaseParseRouterInfo(wire)
	if err != nil {
		return info, err
	}
	valid, err := info.Verify()
	if err != nil {
		return info, err
	}
	if !valid {
		return info, netdb.ErrInvalidSignature
	}
	if err := netdb.RouterInfoFresh(info, now); err != nil {
		return info, err
	}
	if !(cfg.NTCP2.Enabled && dataplane.RouterNTCP2PeerCapable(info, now)) && !(cfg.SSU2.Enabled && dataplane.RouterSSU2PeerCapable(info, now/1000)) {
		return info, fmt.Errorf("bootstrap RouterInfo: no usable enabled transport")
	}
	iterator := info.Options.Iterator()
	for {
		key, value, ok, err := iterator.Next()
		if err != nil {
			return info, err
		}
		if !ok {
			return info, fmt.Errorf("bootstrap RouterInfo: missing network id")
		}
		if string(key) == "netId" {
			id, err := strconv.ParseUint(string(value), 10, 32)
			if err != nil || uint32(id) != cfg.Network.ID {
				return info, fmt.Errorf("bootstrap RouterInfo: network id does not match %d", cfg.Network.ID)
			}
			return info, nil
		}
	}
}

// Hash returns the immutable router identity, including after shutdown.
func (d *Controller) Hash() foundation.Hash {
	if d == nil || d.localInfo == nil {
		return foundation.Hash{}
	}
	return d.localInfo.Hash()
}

// WaitReady waits for the router-owned exploratory pair, never a client pool.
func (d *Controller) WaitReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d == nil {
		return net.ErrClosed
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		d.mu.Lock()
		closed, lifetime := d.closed, d.ctx
		d.mu.Unlock()
		if closed || lifetime == nil {
			return net.ErrClosed
		}
		if d.pool != nil && d.pool.Owner() == (foundation.Hash{}) && d.maintainer != nil {
			if _, ready := d.maintainer.Pair(uint64(d.clock.Now().UnixMilli())); ready {
				return nil
			}
		}
		d.requestExploratoryMaintenance()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-lifetime.Done():
			return net.ErrClosed
		case <-ticker.C:
		}
	}
}
