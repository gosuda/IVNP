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
input key material. `WaitReady` waits for usable inbound and outbound tunnels
and confirmed LeaseSet publication, so pass a bounded context. Closing the endpoint releases its destination
runtime; closing the node releases every remaining endpoint and wipes
node-owned sensitive state.

`PreparingDestinationEndpoint.PrepareDestination(ctx, remoteHash)` can run
concurrently with `WaitReady`. It waits for the destination's own circuit pair,
then prepares a remote route without sending application data. Preparation is
optional: its failure does not make a locally ready destination unusable.

For complete, compile-checked programs, see `example_test.go`.

## Receive IRC server messages

Start the router and leave it running:

```sh
go run ./cmd/ivnpd -config ivnp.conf
```

Once the SAM listener is available, run in another terminal; session creation waits for destination readiness:

```sh
go run ./cmd/toyirc -sam 127.0.0.1:7656 -server irc.postman.i2p -port 6667 -timeout 5m
```

`toyirc` prints received server messages, answers PING, and exits successfully
after numeric `001` (welcome). It sends QUIT without joining a channel or posting
channel messages. This checks an actual IRC registration, not just a SAM or
transport connection. Cold-start reseeding and tunnel construction may take
several minutes. Set `[paths] data_dir` explicitly when isolating router state;
the default `./data` is relative to the daemon's working directory.

To retain the SAM destination and reconnect IRC streams after disconnection:

```sh
go run ./cmd/toyirc -persistent -server irc.postman.i2p -timeout 1h
```

Persistent mode keeps answering PING after welcome until interruption or the
overall timeout. It does not join channels or send channel messages. Reconnecting
streams reuses the same destination; restarting `toyirc` creates a new transient
identity and does not restore its old tunnels.

Closing a SAM STREAM CONNECT attachment cancels its pending resolution and dial
without closing the root session. Pipelined bytes remain buffered for relay;
a full command buffer applies bounded backpressure until handoff or timeout.

Outbound streaming handshakes have a 45-second default budget, capped by the
caller deadline. A genuine unanswered handshake retires only its observed route
installation, allowing a subsequent dial to select another circuit or remote
lease. Caller cancellation does not penalize routes; later successful handshakes
and newer installations protect against stale failure feedback. Established
streams do not inherit the handshake timeout.

On bridges advertising `IVNP_PREPARE=1`, `toyirc` supplies its IRC target during
session creation. Remote preparation overlaps local LeaseSet confirmation using
destination-owned tunnels. Slow or failed preparation does not add a readiness
requirement. Bridges without this capability receive standard SAM commands.

The router saves bounded successful NetDB responder hints in `netdb.responders`
alongside `netdb.routers`. Hints expire after 24 hours and are reused only with
fresh verified floodfill RouterInfos; configured static seeds are not persisted
as observed successes. Selection rotates eligible hints rather than pinning every
lookup to one peer. Neither cache replaces signature checks or tunnel readiness.

Initial inbound builds prepare distinct first-hop and return-hop transports
concurrently, then send only after both succeed. Cancellation joins both
preparations without treating sibling cancellation as peer failure. The
configured hop count is unchanged; later carrier-based builds do not add this
direct preflight.

After the first inbound/outbound pair exists, maintenance can prepare up to two
builds per direction. `[tunnel] build_pending_capacity` bounds preparing and
reply-pending creators across the router, as well as each manager. Maintenance
owners wait in a fair queue; direct `Start*` calls return backpressure without
registering persistent waits. Failed preparation cancels obsolete waits before
releasing admission, avoiding self-triggered retry loops. Expected backpressure
does not poison lifecycle status, while independent real failures remain visible.

Logical target and renewal claims survive the late-reply grace period while
timeouts release active admission for retries. Retries retain retirement
identity but refresh the scheduling window; only one competing reply can satisfy
a claim. Circuit installation tokens protect renewed paths from stale replies.

RouterInfo seeding shares bounded encoding and per-transport-session caches
across destinations in one router. Snapshot changes, session replacement, and
expiry trigger reseeding; failed sends are not cached as successes. Router
shutdown releases cached session references. Compression reuses bounded scratch
state while returning independently owned deterministic gzip bytes.

Prepared senders allocate payload scratch backing on demand within fixed
admission slots. Writable spans are recorded before serialization or encryption
and wiped on release, including partial failures. First use and larger messages
may allocate; warmed storage is reused. Framed ciphertext remains independently
owned so network backpressure does not pin scratch storage. Tunnel encoding
combines IV and padding entropy into one cryptographic read.

Allocation counts, memory use, and throughput are benchmark measurements, not
unit-test pass/fail thresholds. Protocol bounds, cancellation, configured
deadlines, admission capacity, and sensitive-memory cleanup remain behavioral
test contracts.
