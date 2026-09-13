package noderuntime

import (
	"context"
	"errors"
	"net"

	"gosuda.org/ivnp/foundation"
)

// This file is the narrow boundary the node layer's overlay bridge consumes.
// Every method verifies or reuses the controller's own records; none of them
// widen authority, accept caller-claimed provenance, or bypass the lookup
// path's verification.

var errOverlayControllerDown = errors.New("daemon: controller is not running")

var errOverlayLookupEmpty = errors.New("lookup completed without a stored record")

var errOverlayForeignRouter = errors.New("daemon: cannot publish a foreign router record")

var errOverlayNoOwnedDestination = errors.New("daemon: no owned destination matches the record key")

// LookupRouterRecord resolves one RouterInfo by hash: a verified table hit is
// returned directly, otherwise a bounded netDB lookup runs first. The raw
// bytes are the stored record's canonical serialization.
func (d *Controller) LookupRouterRecord(ctx context.Context, hash foundation.Hash) ([]byte, error) {
	if d == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ref, ok := d.database.Routers().Get(hash); ok {
		return append([]byte(nil), ref.Info.Bytes()...), nil
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.requests != nil
	requests := d.requests
	d.mu.Unlock()
	if !available {
		return nil, errOverlayControllerDown
	}
	result, err := requests.LookupRouterInfo(ctx, hash)
	if err != nil {
		return nil, err
	}
	select {
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if ref, ok := d.database.Routers().Get(hash); ok {
		return append([]byte(nil), ref.Info.Bytes()...), nil
	}
	return nil, errors.Join(net.ErrClosed, errOverlayLookupEmpty)
}

// LookupDestinationRecord resolves one LeaseSet-family record by key: local
// verified records are returned directly, otherwise a bounded netDB lookup
// runs first. encrypted reports an Encrypted LS2 so callers do not conflate
// blinded records with cleartext ones.
func (d *Controller) LookupDestinationRecord(ctx context.Context, hash foundation.Hash) (raw []byte, encrypted bool, err error) {
	if d == nil {
		return nil, false, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if record, ok := d.destinationRecord(hash); ok {
		return record.raw, record.encrypted, nil
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.requests != nil
	requests := d.requests
	d.mu.Unlock()
	if !available {
		return nil, false, errOverlayControllerDown
	}
	result, err := requests.LookupLeaseSet(ctx, hash)
	if err != nil {
		return nil, false, err
	}
	select {
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, false, outcome.Err
		}
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	if record, ok := d.destinationRecord(hash); ok {
		return record.raw, record.encrypted, nil
	}
	return nil, false, errors.Join(net.ErrClosed, errOverlayLookupEmpty)
}

type destinationRecord struct {
	raw       []byte
	encrypted bool
}

// destinationRecord reads the verified local copy of a lease-family record.
// Encrypted takes precedence so a blinded record is never reported as its
// cleartext sibling under the same key.
func (d *Controller) destinationRecord(hash foundation.Hash) (destinationRecord, bool) {
	if set, ok := d.database.EncryptedLeaseSet(hash); ok {
		return destinationRecord{raw: append([]byte(nil), set.Bytes()...), encrypted: true}, true
	}
	if set, ok := d.database.LeaseSet2(hash); ok {
		return destinationRecord{raw: append([]byte(nil), set.Bytes()...)}, true
	}
	if set, ok := d.database.LeaseSet(hash); ok {
		return destinationRecord{raw: append([]byte(nil), set.Bytes()...)}, true
	}
	return destinationRecord{}, false
}

// PublishOwnedRouter republishes the local RouterInfo immediately. The record
// argument is advisory: the controller publishes its current verified local
// record, and a record naming a different router hash is rejected rather than
// substituted.
func (d *Controller) PublishOwnedRouter(ctx context.Context, hash foundation.Hash) (confirmed bool, err error) {
	if d == nil {
		return false, net.ErrClosed
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.localInfo != nil
	local := d.localInfo
	d.mu.Unlock()
	if !available {
		return false, errOverlayControllerDown
	}
	if local.Hash() != hash {
		return false, errOverlayForeignRouter
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := local.Publish(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// PublishOwnedDestination republishes one owned destination's LeaseSet through
// its own confirmed publisher. Unknown or unowned hashes are rejected.
func (d *Controller) PublishOwnedDestination(ctx context.Context, hash foundation.Hash) (confirmed bool, err error) {
	if d == nil {
		return false, net.ErrClosed
	}
	d.mu.Lock()
	available := d.started && !d.closed
	d.mu.Unlock()
	if !available {
		return false, errOverlayControllerDown
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.local == nil || runtime.publisher == nil || runtime.local.IdentityHash() != hash {
			continue
		}
		if _, err := runtime.publisher.Maintain(ctx); err != nil {
			return false, err
		}
		return runtime.publisher.Confirmed(), nil
	}
	return false, errOverlayNoOwnedDestination
}

// PublishOwnedDestinationOptions installs mapping entries — extension
// contracts such as x-ov.* / x-ivnp.* — on the owned destination's record,
// republishes it through its confirmed publisher, and returns the stored
// record bytes. Unknown or unowned hashes are rejected; a nil or empty
// option set restores the canonical empty mapping.
func (d *Controller) PublishOwnedDestinationOptions(ctx context.Context, hash foundation.Hash, options []foundation.MappingEntry) (raw []byte, confirmed bool, err error) {
	if d == nil {
		return nil, false, net.ErrClosed
	}
	d.mu.Lock()
	available := d.started && !d.closed
	d.mu.Unlock()
	if !available {
		return nil, false, errOverlayControllerDown
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, runtime := range d.clientRuntimeSnapshot() {
		if runtime.local == nil || runtime.publisher == nil || runtime.local.IdentityHash() != hash {
			continue
		}
		if err := runtime.publisher.PublishWithOptions(ctx, options); err != nil {
			return nil, false, err
		}
		record, ok := d.destinationRecord(hash)
		if !ok {
			return nil, false, errors.Join(net.ErrClosed, errOverlayLookupEmpty)
		}
		return record.raw, runtime.publisher.Confirmed(), nil
	}
	return nil, false, errOverlayNoOwnedDestination
}

// OverlayConnectivity reports the native context's readiness evidence: running
// transports and the verified peer count. It asserts nothing about an
// individual lookup.
func (d *Controller) OverlayConnectivity() (running bool, peers int, err error) {
	if d == nil {
		return false, 0, net.ErrClosed
	}
	d.mu.Lock()
	available := d.started && !d.closed && d.router != nil
	runtime := d.router
	d.mu.Unlock()
	if !available {
		return false, 0, errOverlayControllerDown
	}
	status := runtime.Status()
	return status.Transport.Running && runtime.Running(), d.database.Routers().Len(), nil
}

// OverlayConfig reports the controller's operating configuration so the bridge
// can read the native network number without a second source of truth.
func (d *Controller) OverlayNetworkID() uint32 {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.config.Network.ID
}
