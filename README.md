# IVNP

Go 1.27 I2P router-protocol implementation.

- Zero-copy, bounds-checked I2P, I2NP, RouterInfo, LeaseSet, and LeaseSet2 parsers.
- Verified reseed ZIP/SU3 ingestion with explicitly injected pinned signers.
- Native NTCP2 and SSU2 transports, paired short-record tunnels, ECIES ratchets, Streaming, SAM, HTTP proxy, and SOCKS5.
- Public fixed-port operation and loopback-bound client-only operation; loopback transports never request NAT mappings.
- Caller-owned hot-path buffers, sensitive slab release, bounded queues, and allocation regression tests.

The root package is the stable facade. One IVNP import covers full-node
construction and the commonly used protocol parsers:

```go
import ivnp "gosuda.org/ivnp"

cfg, err := ivnp.LoadOrCreateConfig("ivnp.conf")
node, err := ivnp.New(cfg, ivnp.Options{})
routerInfo, err := ivnp.ParseRouterInfo(rawRouterInfo)
message, consumed, err := ivnp.ParseI2NP(wire)
```

Advanced callers may import the full-name subsystem roots: `foundation`,
`cryptography`, `networking`, `client`, `state`, `observability`, `node`, and
`contracts`. Concrete implementations below a subsystem's `internal` directory
are not public import paths.

```sh
go test ./...
```

Protocol layout and limits: [`docs/architecture.md`](docs/architecture.md). Current native-network compatibility and hot-path evidence: [`docs/static-audit.md`](docs/static-audit.md). Embedded operation and client-only binding: [`docs/embedded-router.md`](docs/embedded-router.md).
