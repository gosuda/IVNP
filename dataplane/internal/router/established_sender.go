package router

import (
	"context"

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
	for _, registry := range s.registries {
		if registry.HasSession(peer) {
			// A failed write may have delivered part of the message.
			return registry.Send(ctx, peer, message)
		}
	}
	return ErrSessionUnavailable
}
