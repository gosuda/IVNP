//go:build dst || synctest

package router

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"gosuda.org/ivnp/dataplane"
	"gosuda.org/ivnp/foundation"
)

// Waiting for the queued writer requires the durable, build-tagged RWMutex.
func TestHandshakeSendFailureDoesNotDeadlockSenderRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sender, deliveries, wire := routeControlFixture(t, nil)
		feedback, err := sender.PrepareHandshake(t.Context(), deliveries[0].To)
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		wire.handle = func(context.Context, foundation.I2NPMessage) error {
			close(entered)
			<-release
			return dataplane.RouterErrSSU2SendStalled
		}
		result := make(chan error, 1)
		go func() { result <- feedback.SendTunnel(t.Context(), deliveries[0]) }()
		<-entered
		stopped := make(chan struct{})
		go func() {
			sender.ReleaseSensitive()
			close(stopped)
		}()
		synctest.Wait()
		close(release)
		if err := <-result; !errors.Is(err, dataplane.RouterErrSSU2SendStalled) {
			t.Fatalf("blocked handshake send = %v", err)
		}
		<-stopped
	})
}
