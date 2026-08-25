# IVNP

Go 1.27 I2P router-protocol implementation.

- Zero-copy, bounds-checked I2P, I2NP, RouterInfo, LeaseSet, and LeaseSet2 parsers.
- Verified reseed ZIP/SU3 ingestion with explicitly injected pinned signers.
- Native NTCP2 and SSU2 transports, paired short-record tunnels, ECIES ratchets, Streaming, SAM, HTTP proxy, and SOCKS5.
- Public fixed-port operation and loopback-bound client-only operation; loopback transports never request NAT mappings.
- Caller-owned hot-path buffers, sensitive slab release, bounded queues, and allocation regression tests.

```sh
go test ./...
```

Protocol layout and limits: [`docs/architecture.md`](docs/architecture.md). Current native-network compatibility and hot-path evidence: [`docs/static-audit.md`](docs/static-audit.md). Embedded operation and client-only binding: [`docs/embedded-router.md`](docs/embedded-router.md).
