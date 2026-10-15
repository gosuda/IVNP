# IVNP

[![Go Reference](https://badge-api.gosuda.org/badge.svg?label=Go&message=Reference&style=old-school&size=200&letterSpacing=0&labelColor=292724&color=007d9c&labelTextColor=ffffff&textColor=ffffff)](https://pkg.go.dev/gosuda.org/ivnp)

IVNP is an I2P network router and application stack written in Go. It operates either as a standalone daemon (`ivnpd`) with built-in proxy and management services, or as an in-memory embedded Go library (`gosuda.org/ivnp`) that exposes standard `net.Conn`, `net.Listener`, and `net.PacketConn` primitives over destination-owned garlic circuits.

Requires **Go 1.27+**.

---

## Capabilities at a Glance

- **Dual Execution Model**: Run a persistent network router daemon via `ivnpd`, or embed a zero-disk-footprint router directly inside a Go process via `ivnp.NewRouter`.
- **Modern I2P Transport & Crypto Stack**: Full implementations of **NTCP2** (TCP with AES-256-CBC ephemeral key obfuscation and SipHash-2-4 frame length masking) and **SSU2** (UDP with ChaCha20 header protection, stateless retry tokens, 7-message peer testing, and introducer hole punching).
- **Post-Quantum & Ratchet End-to-End Sessions**: `ECIES-X25519-AEAD-Ratchet` (`Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256`) alongside FIPS-203 **ML-KEM-768** and **ML-KEM-1024** hybrid post-quantum LeaseSet2 encryption (`CryptoKeyType` 6 and 7).
- **Blinded & Authorized LeaseSets**: Full support for `LeaseSet2`, `MetaLeaseSet`, and two-layer ChaCha20 `EncryptedLeaseSet` with RedDSA (`Red25519`) daily key blinding and per-client Diffie-Hellman (`DH`) or Pre-Shared Key (`PSK`) access control.
- **Multi-Network Contexts & Happy Eyeballs**: Bind a single `ivnp.Destination` identity across the public I2P network (`netId=2`) and private overlay networks (`netId=1..255`) simultaneously. Unqualified stream dials race candidate networks using staggered Happy Eyeballs (`250ms` fallback delay), while `Listen` multiplexes accepted streams across all bound networks.
- **Compile-Time Datagram Authentication Separation**: `Destination.ListenPacket` serves only cryptographically authenticated protocols (`Datagram1` and target-bound `Datagram2`) and implements `net.PacketConn`. Unauthenticated protocols (`Raw` and `Datagram3`) require `Destination.ListenUnauthPacket`, preventing callers from mistaking a spoofable source hash for a verified `net.Addr`.
- **Complete Client Protocol Suite**: Built-in **SAM v3.3** bridge (`STREAM`, `DATAGRAM`, `DATAGRAM2`, `DATAGRAM3`, `RAW`, `PRIMARY` subsessions, and offline signatures), **HTTP/HTTPS-CONNECT** eepsite and outproxy gateway, **SOCKS5** proxy, and a lock-free **AddressBook** resolver with conditional ETag subscriptions.
- **Strict Layered Architecture & Zero-Allocation Wire Codecs**: Enforced 10-layer unidirectional dependency graph (`L0` through `L9`) backed by `wire.Cursor` zero-copy parsers, power-of-two slab pools, and deterministic `testing/synctest` network simulation (`internal/simnet`).

---

## Standalone Daemon (`ivnpd`)

### Install and Run

```sh
go install gosuda.org/ivnp/cmd/ivnpd@latest
ivnpd -config ivnp.conf
```

Or run directly from a source checkout:

```sh
go run ./cmd/ivnpd -config ivnp.conf
```

To run an ephemeral daemon in memory without writing configuration, keys, or NetDB state to disk:

```sh
ivnpd -memory
```

### Default Local Endpoints

| Service | Default Bind Address | Protocol / Purpose |
| :--- | :--- | :--- |
| **Web Console** | `http://127.0.0.1:7070` | Real-time dashboard, live SSE telemetry, NetDB inspector, and INI config editor |
| **HTTP Proxy** | `127.0.0.1:4444` | `.i2p` eepsite proxy and clearnet outproxy forwarding (`HTTP` and `CONNECT`) |
| **SOCKS5 Proxy** | `127.0.0.1:4447` | SOCKS5 `CONNECT` proxy for `.b32.i2p` and base64 destinations (enable with `-socks5`) |
| **SAM v3.3 Bridge** | `127.0.0.1:7656` (TCP) / `7655` (UDP) | Simple Anonymous Messaging v3.1-v3.3 control and datagram sockets |
| **Control API** | `127.0.0.1:7657` | Bearer-authenticated JSON status and readiness endpoints (`/readyz`, `/status`, `/destinations`) |
| **Metrics & Probes** | `127.0.0.1:9100` | Prometheus `/metrics`, `/varz`, `/healthz`, `/livez`, and `/readyz` |

### Daemon Configuration & Flags

On first start with the default `-config ivnp.conf` path, `ivnpd` generates a commented configuration file and stores AES-256-GCM encrypted router state (`router.state`), master keys (`router.keys`), and NetDB snapshots under `./data`.

```ini
[paths]
data_dir = /var/lib/ivnp

[router]
floodfill = false
max_participating_tunnels = 512

[http_proxy]
enabled = true
listen = 127.0.0.1:4444
outproxies = exit.stormycloud.i2p

[sam]
enabled = true
listen = 127.0.0.1:7656
udp_listen = 127.0.0.1:7655
```

Common CLI flags:
- `-config <path>`: Path to INI configuration file (default `ivnp.conf`).
- `-memory`: Run in-memory without reading or writing persistent state on disk.
- `-data-dir <dir>`: Override `[paths] data_dir`.
- `-webui=false` / `-webui-listen <addr:port>`: Disable or rebind the embedded WebUI server.
- `-webui-auth` / `-webui-token <secret>`: Require Bearer authentication on `/api/*` endpoints (or set `IVNPD_WEBUI_TOKEN`).
- `-http-proxy` / `-socks5`: Enable or disable proxy listeners from the command line.
- `-log-level <debug|info|warn|error>` / `-log-format <text|json>`: Configure structured logging (`SIGHUP` reloads `log.level` at runtime on Unix).
- `-test-config`: Validate configuration syntax and security invariants, then exit.

---

## Embedded Go Library (`gosuda.org/ivnp`)

```sh
go get gosuda.org/ivnp
```

`ivnp.NewRouter` starts local router infrastructure in memory by default (`cfg.Persistence == nil`). A `Router` owns transport listeners, NetDB state, and exploratory tunnels; it never creates an implicit application identity. Application traffic flows through explicit `ivnp.Destination` instances.

### Stream Listener and Client Dialing

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"gosuda.org/ivnp"
)

func runService(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cfg := ivnp.DefaultRouterConfig()
	router, err := ivnp.NewRouter(ctx, cfg)
	if err != nil {
		return err
	}
	defer router.Close()

	// NewDestination builds inbound/outbound client tunnels and confirms
	// LeaseSet2 publication before returning.
	dest, err := router.NewDestination(ctx, ivnp.DefaultDestinationConfig())
	if err != nil {
		return err
	}
	defer dest.Close()

	listener, err := dest.ListenContext(ctx, "i2p", ":8080")
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Println("Listening on:", net.JoinHostPort(dest.B32(), "8080"))

	// Dial a remote .b32.i2p address directly over I2P streaming:
	conn, err := dest.DialContext(ctx, "i2p", net.JoinHostPort(dest.B32(), "8080"))
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}
```

### Multi-Network Overlays and Happy Eyeballs

A single `Router` can host independent I2P network contexts (such as the public `netId=2` network alongside a private `netId=42` mesh). A `Destination` bound to multiple networks shares one cryptographic identity and `.b32.i2p` address across all of them:

```go
cfg := ivnp.DefaultRouterConfig()
cfg.Networks = []ivnp.NetworkConfig{
	ivnp.NewNetwork("private-mesh", 42,
		ivnp.WithListenAddress("0.0.0.0:19111"),
		ivnp.WithPeerSeeds(meshSeedRouterInfos...),
		ivnp.WithPeerAdmission(ivnp.AdmitPeers(allowedPeerHashes...)),
	),
	ivnp.NewNetwork("i2p", ivnp.NetworkIDPublicI2P),
}
cfg.DefaultNetwork = "private-mesh"

router, err := ivnp.NewRouter(ctx, cfg)
if err != nil {
	return err
}
defer router.Close()

destCfg := ivnp.DefaultDestinationConfig()
destCfg.Networks = []string{"private-mesh", "i2p"}
dest, err := router.NewDestination(ctx, destCfg)
```

When dialing with a generic network string (`"i2p"`, `"tcp"`, or `"stream"`), `Destination.DialContext` uses `DialHappyEyeballs` to start `"private-mesh"` immediately and stagger `"i2p"` by `250ms`. Calling `dest.ListenContext(ctx, "i2p", ":8080")` returns a merged listener that accepts connections arriving from either network.

### Authenticated vs. Unauthenticated Datagrams

IVNP separates authenticated datagrams from spoofable datagrams at the type level:

```go
// Authenticated Datagram2 (protocol 19, target-bound and replay-resistant):
// Implements standard net.PacketConn.
pktConn, err := dest.ListenPacketContext(ctx, "datagram2", ":9000")
if err != nil {
	return err
}
defer pktConn.Close()

// Unauthenticated Datagram3 (protocol 20) or Raw (protocol 18):
// Returns *ivnp.UnauthPacketConn so callers explicitly handle unverified sources.
rawConn, err := dest.ListenUnauthPacketContext(ctx, "datagram3", ":9001")
if err != nil {
	return err
}
defer rawConn.Close()
```

---

## Architecture & Subsystem Hierarchy

IVNP enforces a strict 10-layer unidirectional Directed Acyclic Graph (DAG). Every package belongs to one layer (`L0` through `L9`). Higher layers may import lower layers, but lower layers never import higher layers, and cross-subsystem imports must pass exclusively through each subsystem's root facade package.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ L9  CLI & Integration Tests   cmd/ivnpd, cmd/ivnp-reseed, tests/, sim_*    │
├────────────────────────────────────────────────────────────────────────────┤
│ L8  Root Module Facade        gosuda.org/ivnp (Router, Destination, Conn)  │
├────────────────────────────────────────────────────────────────────────────┤
│ L7  Node Lifecycle            node (Daemon, EmbeddedRouter, NetworkSpec)   │
├────────────────────────────────────────────────────────────────────────────┤
│ L6  Client Services           client (SAM v3.3, HTTP, SOCKS5, AddressBook) │
├────────────────────────────────────────────────────────────────────────────┤
│ L5  Control Plane             controlplane (NetDB, Tunnels, Reseed, NAT)   │
├────────────────────────────────────────────────────────────────────────────┤
│ L4  Data Plane                dataplane (NTCP2, SSU2, Garlic, Streaming)   │
├────────────────────────────────────────────────────────────────────────────┤
│ L3  Domain Interfaces & State interfaces/{destination,stream}, state       │
├────────────────────────────────────────────────────────────────────────────┤
│ L2  Foundation & Telemetry    foundation (Identity, I2NP, NetDB),          │
│                               observability (Registry, Prometheus, Health) │
├────────────────────────────────────────────────────────────────────────────┤
│ L1  Cryptography              cryptography (X25519, Elligator2, ML-KEM,    │
│                               ChaCha20-Poly1305, ElGamal, Streebog)        │
├────────────────────────────────────────────────────────────────────────────┤
│ L0  Internal Utilities        internal/{wire,pool,packet,ingress,          │
│                               parallelism,relay,simnet}                    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Documentation Suite

Detailed architectural guides, codebase maps, and wire-level protocol references live under [`docs/`](docs/README.md):

| Document | Contents |
| :--- | :--- |
| [**Documentation Index**](docs/README.md) | Reading guide and cross-reference map for the IVNP documentation suite |
| [**Architecture & Design Invariants**](docs/architecture.md) | L0-L9 layered DAG rules, plane separation, `CircuitToken` lifetime draining, zero-allocation wire parsing, slab pooling, and encrypted state persistence |
| [**Codebase & Subsystem Guide**](docs/codebase-guide.md) | Package-by-package and file-by-file directory reference across all 10 layers, key types, and subsystem facades |
| [**Protocols, Wire Formats & Cryptography**](docs/protocols-and-cryptography.md) | `cryptography` and `foundation`: Elligator2, X25519, Red25519 blinding, ML-KEM-768/1024 hybrids, `KeysAndCert` wire layout, `RouterInfo`, `LeaseSet2`, `EncryptedLeaseSet`, and I2NP headers |
| [**Transports & Tunnels**](docs/transports-and-tunnels.md) | NTCP2 and SSU2 handshakes, header protection, NAT hole punching, peer test, 1024-byte AES-256-CBC tunnel framing, gateway fragmentation, endpoint reassembly, and STBM/VTBM tunnel builds |
| [**Garlic, Streaming & Datagrams**](docs/garlic-streaming-and-datagrams.md) | `ECIES-X25519-AEAD-Ratchet` state machine, two-phase `NewSession` commit, I2P Streaming TCB, congestion control, and Datagram1/Raw/Datagram2/Datagram3 codecs |
| [**Control Plane & NetDB**](docs/controlplane-and-netdb.md) | Split Kademlia XOR NetDB, floodfill operations, iterative lookups, confirmed publication, paired tunnel pool maintenance, SU3 reseed verification, and UPnP/NAT-PMP port mapping |
| [**Client Services, Public API & Simulation**](docs/client-services-and-api.md) | Root Go API (`gosuda.org/ivnp`), SAM v3.3 server/client, HTTP & SOCKS5 proxies, AddressBook, `ivnpd` WebUI API, and deterministic simulation testing (`simnet` & `dstoverlay`) |
| [**Subsystem Reference: L0-L3 (Utilities, Crypto, Foundation & State)**](docs/subsystems-l0-l3-foundation-and-state.md) | Code-level reference for `internal/*`, `cryptography`, `foundation`, `observability`, `interfaces/*`, and `state` (`router.state` binary bundle layout) |
| [**Subsystem Reference: L4 (`dataplane`)**](docs/subsystems-l4-dataplane.md) | Code-level walkthrough of `DataPlane`, `Service`, 64-shard Bloom replay filter, `GarlicReceiver`, `NTCP2Manager`, `SSU2Manager` worker loops, and 64-shard `tunnel.Runtime` |
| [**Subsystem Reference: L5 (`controlplane`)**](docs/subsystems-l5-controlplane.md) | Code-level walkthrough of `Controller`, isolated `destinationRuntime`, `StreamingTunnelSender`, OBEP `replyRouterInfoSeeds`, NetDB, and STBM/VTBM tunnel builders |
| [**Subsystem Reference: L6-L9 (Services, Node, Root API & CLI)**](docs/subsystems-l6-l9-services-node-and-cli.md) | Code-level walkthrough of `client`, `node`, root `gosuda.org/ivnp` files, `cmd/ivnpd`, `cmd/ivnp-reseed`, and `tools/dstoverlay` |
| [**Reseed Server Manual (`ivnp-reseed`)**](cmd/ivnp-reseed/README.md) | Autonomous DHT crawler, TCP prober, Max-Min XOR peer selector, deterministic RSA-4096 SU3 packager, and HTTP server |

---

## Verification, Simulation & Tooling

Run the standard test suite, race detector, canonical import formatter, and static analyzer:

```sh
go test ./...
go test -race ./...
go run gosuda.org/ivnp/tools/importformatter -write
gojgp lint ./...
```

### Deterministic Simulation Testing (DST)

IVNP includes a deterministic multi-router simulation suite built on Go's `testing/synctest` virtual clock and `internal/simnet`. Build the runtime overlay first with `tools/dstoverlay`, then run the simulation tests:

```sh
overlay=$(mktemp /tmp/ivnp-dst-overlay.XXXXXX.json)
go run ./tools/dstoverlay -o "$overlay"
GODEBUG=asyncpreemptoff=1,cryptocustomrand=1 \
  go test -tags=dst -overlay="$overlay" -run '^TestSim|^TestDeterministic' .
rm -f "$overlay"
```

### Live Network Integration Tests

```sh
IVNP_EEPSITE_PROXY=http://127.0.0.1:4444 IVNP_SAM_ADDRESS=127.0.0.1:7656 \
  go test -tags=integration -run '^TestHTTPProxyCompletesI2PChallengeRoundTrip$' \
  -count=1 -timeout=12m ./tests/integration
```

---

## License

[MIT](LICENSE)
