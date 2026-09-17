package router

import (
	"context"
	"errors"
	"fmt"

	"gosuda.org/ivnp/foundation"
)

type EstablishedSessionRegistry interface {
	HasSession(foundation.Hash) bool
	Send(context.Context, foundation.Hash, foundation.I2NPMessage) error
}

// EstablishedSender borrows manager-owned registries, not setup capabilities.
// Its fixed transport order applies only to already-authenticated sessions.
type EstablishedSender struct {
	registries []EstablishedSessionRegistry
}

func NewEstablishedSender(registries ...EstablishedSessionRegistry) *EstablishedSender {
	return &EstablishedSender{registries: append([]EstablishedSessionRegistry(nil), registries...)}
}

func (s *EstablishedSender) Send(ctx context.Context, peer foundation.Hash, message foundation.I2NPMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var lastErr error
	for _, registry := range s.registries {
		if !registry.HasSession(peer) {
			continue
		}
		err := registry.Send(ctx, peer, message)
		if err == nil {
			return nil
		}
		// A failed write may have delivered part of the message, so only
		// pre-delivery failures fall through to the next session: a missing
		// session or a congestion-stalled send both guarantee zero bytes left.
		if !errors.Is(err, ErrSessionUnavailable) && !errors.Is(err, ErrSSU2SendStalled) {
			return err
		}
		lastErr = err
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: %s", ErrSessionUnavailable, foundation.EncodeI2PBase64(peer[:]))
}
