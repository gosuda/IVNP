# Subsystem Code Reference: Layers L6 to L9 (Client Services, Node, Root API & CLI)

This document provides a code-level structural reference for Layers **L6** (`client`), **L7** (`node`), **L8** (root package `gosuda.org/ivnp`), and **L9** (`cmd/ivnpd`, `cmd/ivnp-reseed`, `architecture`, `tests/integration`, `tools/*`, and `sim_*.go`).

---

## 1. Layer L6: Client Services (`client/`)

`client/client_subsystem.go` re-exports four internal service packages:

### 1.1 `client/internal/addressbook`

| File | Primary Types & Functions | Code Mechanics & Invariants |
| :--- | :--- | :--- |
| `service.go` | `Service`, `Config`, `snapshot` | Implements `destination.DestinationResolver`; stores `merged map[string]string` in `atomic.Pointer[snapshot]` so `ResolveDestination` is lock-free |
| `bootstrap.go` | `defaultBootstrapHosts`, `ensureBootstrapHostsFile` | Seeds 6 built-in `.i2p` hosts (`reg.i2p`, `identiguy.i2p`, `stats.i2p`, `exit.stormycloud.i2p`, `i2p-projekt.i2p`, `zzz.i2p`) and writes initial `0600` `hosts.txt` if missing |
| `hosts.go` | `parseHosts`, `normalizeName`, `canonicalDestination` | Parses `name=dest` lines, strips `#` comments, rejects `#!` mutation commands (`ErrMutation`), normalizes `.i2p` / `.i2p.alt` labels (`<= 67` chars), and verifies canonical base32/base64 destinations |
| `subscription.go` | `refresh`, `subscriptionURL` | Fetches up to 32 remote subscriptions concurrently via `parallelism.Workers`, sends conditional `ETag` / `If-Modified-Since` headers, and blocks cross-origin redirects (`sameSubscriptionOrigin`) |
| `store.go` | `persistedState`, `loadState`, `saveState` | Persists `Version: 2` subscription snapshots via `state.FilesystemStoreWriteAtomic` (`0600`) and re-sanitizes all entries on load |

### 1.2 `client/internal/frontend`

| File | Primary Types & Functions | Code Mechanics & Invariants |
| :--- | :--- | :--- |
| `server.go` | `server`, `trackedListener`, `trackedConn` | Enforces loopback binding unless `AllowRemote` is set; bounds concurrent connections with `sem chan struct{}` and tracks active sockets for forced teardown on `Close()` |
| `control.go` | `Control`, `ControlConfig` | Loopback management HTTP server (`127.0.0.1:7650` in `DefaultOperating`, `127.0.0.1:7657` standalone fallback); requires constant-time SHA-256 `BearerToken` auth; serves `GET /readyz`, `GET /status`, and `GET /destinations` |
| `http_proxy.go` | `HTTPProxy`, `HTTPProxyConfig` | Loopback HTTP/CONNECT proxy (`127.0.0.1:4444`); strips hop-by-hop and `X-Forwarded-*` headers; routes `.i2p` hosts directly (`User-Agent: MYOB/6.66 (AN/ON)`) and clearnet hosts across round-robin `Outproxies` with 5-minute `warmOutproxyLoop` |
| `socks5.go` | `SOCKS5Proxy`, `SOCKS5Config` | Loopback SOCKS5 `CONNECT` proxy (`127.0.0.1:4447`); requires `ATYP = 0x03` (domain name); runs a background `reader.Peek(1)` goroutine during `DialI2P` to cancel aborted client dials |
| `target.go`, `relay.go` | `targetAddress`, `relayConnections` | Validates 52-char `.b32.i2p` and base64 targets; wraps `internal/relay.BidirectionalContained` with `BoundaryClientConnection` panic recovery |

### 1.3 `client/internal/sam`

| File | Primary Types & Functions | Code Mechanics & Invariants |
| :--- | :--- | :--- |
| `server.go`, `budget.go` | `Server`, `ServerConfig`, `byteBudget` | Manages TCP listener (`127.0.0.1:7656`), UDP socket (`127.0.0.1:7655`), session registry (`MaxSessions = 128`), and two-level `byteBudget` (`4 MiB` per session, `64 MiB` server-wide) |
| `command.go`, `protocol.go` | `command`, `parseCommand`, `dispatch` | Tokenizes SAM v3.3 lines (with `\"` and `\\` escapes), negotiates `HELLO VERSION` (`IVNP_PREPARE=1`), and dispatches `PING`, `DEST GENERATE`, `NAMING LOOKUP`, `SESSION`, `STREAM`, `DATAGRAM`, and `RAW` commands |
| `private_destination.go` | `parsePrivateDestination`, `parseLeaseSetPolicy` | Parses `TRANSIENT` or private base64 keys, SAM v3.3 offline signatures (when the 32B signing key slot is all zeros), and `i2cp.leaseSet*` options (`leaseSetType`, `leaseSetEncType`, `leaseSetAuthType`, `dh`/`psk` client keys) |
| `session.go` | `session`, `subsession` | Owns root `DestinationEndpoint` and demultiplexes `PRIMARY` subsessions (`SESSION ADD` / `SESSION REMOVE`) by `(LISTEN_PROTOCOL, LISTEN_PORT)` |
| `stream.go`, `accept.go` | `handleStreamConnect`, `acceptIncomingLoop`, `acceptLoop` | Two-stage FIFO `STREAM ACCEPT` matcher that immediately evicts canceled client sockets (`removeAcceptWaiter`), plus loopback-only `STREAM FORWARD` |
| `datagram.go`, `udp.go` | `handleDatagramSend`, `receiveLoop`, `udpReadLoop` | Marshals and verifies `Datagram1`, `Datagram2`, `Datagram3`, and `Raw` packets over TCP or UDP port `7655` (enforcing `sameSourceIP` between UDP sender and TCP control socket) |
| `network.go` | `Network` | External SAM v3.1-v3.3 client implementing `DialI2P` and `ListenI2P` with 1-minute `PING ivnp-keepalive` |

---

## 2. Layer L7: Node Lifecycle (`node/`)

- **`node/internal/runtime/node.go` (`Daemon`)**:
  - Embeds `*controlplane.Controller` and owns the ordered slice `services []nodeService` (`addressBook`, `sam`, `control`, `httpProxy`, `socks5`) plus `metricsServer`, exposing bound listener state via `ServiceListeners()`.
  - `newAddressBookTransport`: Custom `http.RoundTripper` that routes `.i2p` subscription URLs over `core.DialI2P` (after resolving the host via `AddressBook`) and clearnet `https://` URLs over `net.Dialer`.
  - `startProxyDestination`: When running in embedded/in-memory mode with `HTTPProxy` or `SOCKS5` enabled, automatically provisions the `"default"` client destination so proxy listeners can dial immediately.
- **`node/embedded.go` (`EmbeddedRouter`, `NetworkSpec`)**:
  - Hosts multiple isolated `*controlplane.Controller` instances keyed by network name (`contexts map[string]*controlplane.Controller`).
  - `NewDestinationOn(ctx, network, spec)` creates a destination on the named controller and blocks on `ready.WaitReady(ctx)` before returning.

---

## 3. Layer L8: Root Module Facade (`gosuda.org/ivnp`)

All root package files reside in `/Users/user/work/work3/IVNP`:

| File | Primary Types & Functions | Code Mechanics & Invariants |
| :--- | :--- | :--- |
| `facade.go` | `Router`, `Destination`, `NewRouter`, `NewDestination` | `Router` wraps `*node.EmbeddedRouter` and shared `packetBudget` (`64 MiB`). `NewDestination` generates one shared `foundation.LocalDestination` across all bound networks so every network shares the same `.b32.i2p` address |
| `config.go` | `RouterConfig`, `DestinationConfig`, `DedicatedDestinationConfig`, `DirectDestinationConfig`, `PersistenceConfig`, `DialPolicy` | Validates single-network vs. multi-network config; provides public, dedicated, and direct destination presets; isolates multi-network state files under `<DataDir>/<netName>/router.{state,keys}` |
| `networks.go` | `NetworkConfig`, `NetworkProfile`, `NewNetwork`, `NewDedicatedNetwork`, `NewDirectNetwork`, `NetDBConfig`, `TunnelPolicyConfig`, `PublicParticipation`, `PeerAdmissionFunc` | Functional options (`WithNetworkProfile`, `WithListenAddress`, `WithAdvertisedAddress`, `WithPeerSeeds`, `WithTrustedReseedCerts`, `WithNetDBConfig`, `WithTunnelTiming`, `WithIPRestriction`, `WithPeerAdmission`, `WithPublicParticipation`) and admission combinators (`AdmitPeers`, `RejectPeers`, `ChainAdmission`) |
| `addr.go`, `errors.go` | `Addr`, `ParseAddr`, `NameResolver` | Implements `net.Addr` (`"<52-char-b32>.b32.i2p:<port>"`) and defines sentinel errors (`ErrInvalidConfig`, `ErrIdentityInUse`, `ErrResourceLimit`, `ErrPeerDenied`) |
| `stream_facade.go` | `Dialer`, `ListenConfig`, `streamConn`, `mergedListener` | Implements `DialHappyEyeballs` (`250ms` leg stagger), `DialParallel`, `DialSequential`, `ConnectionNetwork(conn)`, and multi-network `mergedListener` |
| `packet.go`, `packet_io.go` | `PacketConn`, `UnauthPacketConn`, `UnauthPacket`, `packetSocket` | Segregates authenticated (`Datagram1`, `Datagram2`) and unauthenticated (`Raw`, `Datagram3`) sockets via `packetSourceClass`; allocates ephemeral ports in `49152..65535` |

---

## 4. Layer L9: CLI Binaries, Tooling & Simulation (`cmd/`, `tools/`, `sim_*`)

### 4.1 `cmd/ivnpd` (Standalone Daemon & WebUI)
- **`main.go`, `signal_unix.go`, `signal_windows.go`**: Parses CLI flags (`-config`, `-memory`, `-webui`, `-webui-listen`, `-webui-auth`, `-webui-token`, `-webui-remote-write`, `-webui-show-peers`, `-http-proxy`, `-socks5`, `-data-dir`, `-log-level`, `-log-format`, `-test-config`, `-pidfile`, `-version`), manages PID files, runs the in-process node restart supervisor, and reloads `log.level` on `SIGHUP`.
- **`webui_server.go`, `webui_api.go`, `webui_config.go`, `webui_config_schema.go`, `webui_history.go`**: Serves the embedded SvelteKit app (`cmd/ivnpd/webui/build`), computes startup SHA-256 CSP hashes for inline scripts (`inlineScriptCSPHashes`), enforces constant-time Bearer token, same-origin, write-policy, and peer-visibility checks, and implements `/api/status`, `/api/metrics`, `/api/history`, `/api/tunnels`, `/api/netdb`, `/api/peers`, `/api/destinations`, `/api/config` (`GET`, `PATCH`), `/api/config/rollback`, `/api/actions/{reseed,tunnel-probe,restart,log}`, and 1-second `/api/events` SSE streaming.

### 4.2 `cmd/ivnp-reseed` (Autonomous Indexer & SU3 Server)
- **`crawler.go`**: Runs an embedded floodfill `node.Subsystem`, harvests verified `RouterInfo`s every `4s`, records tunnel participation, and executes deficit-weighted prefix-tree exploration (`TreeExplore`).
- **`prober.go`**: Token-bucket rate-limited (`8.0/s`, burst `16`) TCP reachability prober (`1500ms` timeout, exponential failure backoff up to `2h`).
- **`store.go` & `selector.go`**: `PeerStore` (`MaxStorePeers = 2500`, persisted to `peers.gob`) with incremental `bySubnet16` (`/16` IPv4, `/48` IPv6) and `byFamily` contention group indices, plus 4-stage `SelectPeers` (relaxation gate -> subnet/family filter -> $O(K \cdot N)$ Max-Min XOR `farthestPointSample` -> 256-bucket stratification).
- **`packager.go` & `server.go`**: Derives deterministic RSA-4096 keys via `HKDF-SHA512` and `filippo.io/keygen.RSA`, builds a rotating pool of `16` distinct 75-peer SU3 archives every `10m`, and serves `/i2pseeds.su3`, `/reseed-rsa.crt`, `/stats`, `/health`, and the live HTML dashboard (`dashboard.go`).

### 4.3 `tools/` & Root Simulation Suite (`sim_*.go`)
- **`tools/importformatter/main.go`**: AST rewriter consolidating all imports into a single canonical `import (...)` block per file.
- **`tools/dstoverlay/main.go`**: Generates a Go compiler `-overlay` JSON patching `GOROOT/src` (`runtime/sema.go`, `internal/sync/mutex.go`, `sync/rwmutex.go`, `runtime/rand.go`, `runtime/proc.go`, `crypto/internal/randutil/randutil.go`) so contended mutex locks and runtime randomness behave deterministically inside `testing/synctest` bubbles.
- **`sim_main_test.go`, `sim_harness_test.go`, `sim_dst_test.go`**: Boots 2-node, 9-node, and 16-node `ivnp.Router` meshes over `internal/simnet` virtual links, testing end-to-end streaming, `Datagram2`, Gilbert-Elliott burst loss, duplicate/tampered UDP packets, asymmetric blackholes, and abrupt transit router crashes.
