# IVNP

IVNP is a Go 1.27 implementation of an embeddable I2P router and its client
services. Applications should import `gosuda.org/ivnp`, the stable top-level
facade.

## Install

```sh
go get gosuda.org/ivnp
```

## Embed a router

```go
package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"gosuda.org/ivnp"
)

func main() {
	cfg, err := ivnp.LoadOrCreateConfig("ivnp.conf")
	if err != nil {
		log.Fatal(err)
	}

	router, err := ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer router.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	if err = router.Start(ctx); err != nil {
		log.Fatal(err)
	}
	if err = router.Wait(); err != nil {
		log.Fatal(err)
	}
}
```

`LoadOrCreateConfig` creates the configuration file when it does not exist.
Review that file before exposing listeners. `New` opens and locks the encrypted
router state but performs no network I/O. `Start` opens the transports and
client-service listeners enabled by the configuration. Always call `Close`;
then use `Wait` to observe worker termination when shutdown is initiated outside
the context passed to `Start`.

`Options` supplies host-owned collaborators such as transport, socket, clock,
HTTP, logging, and NAT implementations. Leave a field zero-valued to use the
production implementation.

## Open an application destination

After the node starts, an embedded application can create an isolated,
transient destination and use it directly:

```go
readyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
defer cancel()

endpoint, err := router.DestinationController().CreateDestination(
	readyCtx,
	ivnp.DestinationSpec{},
)
if err != nil {
	return err
}
defer endpoint.Close()

ready, ok := endpoint.(ivnp.ReadyDestinationEndpoint)
if !ok {
	return errors.New("destination does not report readiness")
}
if err = ready.WaitReady(readyCtx); err != nil {
	return err
}

listener, err := endpoint.ListenI2P(readyCtx, ":8080")
if err != nil {
	return err
}
defer listener.Close()

connection, err := endpoint.DialI2P(readyCtx, "stats.i2p:80")
if err != nil {
	return err
}
defer connection.Close()
```

The zero `DestinationSpec` generates a new transient local destination. A
non-nil `DestinationSpec.Local` is cloned; the caller retains ownership of its
input key material. `WaitReady` waits for usable inbound and outbound tunnels,
so pass a bounded context. Closing the endpoint releases its destination
runtime; closing the node releases every remaining endpoint and wipes
node-owned sensitive state.

For complete, compile-checked programs, see `example_test.go`.

