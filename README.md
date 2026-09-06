# IVNP

IVNP is a Go 1.27 implementation of an embeddable I2P router and its client
services. Applications should import `gosuda.org/ivnp`, the stable top-level
facade.

## Subsystems

`controlplane` owns NetDB, peer and tunnel policy, destination lifecycle, and
prepared routes. `dataplane` executes installed routes and authenticated transport
sessions; it retains packet-local cryptographic and reliability state without
performing NetDB discovery or connection setup on the bulk path. `node` composes
these owners with the client services and coordinates startup and shutdown.

The planes run in the same process. Route and circuit generations prevent stale
work from adopting replacement state. Control ingress has independent item and
byte limits, preserves private lookup provenance, and runs under bounded handler
deadlines. Cross-subsystem imports use the canonical roots; the former
`networking` package has been removed. Shared wire types and codecs are exported
by `foundation`.

## Install

```sh
go get gosuda.org/ivnp
```

Windows builds support amd64 and arm64 without CGO. Store configuration and router
state on a local NTFS drive. Private files use owner-controlled ACLs, exclusive
creation and byte-range locking; symlinks, reparse points, hard-linked private
files, alternate data streams and UNC/device paths are rejected. Existing state
must be owned by the current user and must not grant access beyond that user,
SYSTEM or administrators. Unix retains ownership, mode and no-follow checks.

The Windows workflow cross-builds both architectures and runs focused storage
security regressions on amd64. Cross-compilation alone does not verify Windows
ACL or filesystem behavior.

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

## Receive IRC server messages

Start the router and leave it running:

```sh
go run ./cmd/ivnpd -config ivnp.conf
```

After its tunnel pools are ready, run in another terminal:

```sh
go run ./cmd/toyirc -sam 127.0.0.1:7656 -server irc.postman.i2p -port 6667 -timeout 5m
```

`toyirc` prints received server messages, answers PING, and exits successfully
after numeric `001` (welcome). It sends QUIT without joining a channel or posting
channel messages. This checks an actual IRC registration, not just a SAM or
transport connection. Cold-start reseeding and tunnel construction may take
several minutes. Set `[paths] data_dir` explicitly when isolating router state;
the default `./data` is relative to the daemon's working directory.
