# Client Services, Public API & Simulation

This document covers Layers L6 through L9 of IVNP: the root embedded Go library (`gosuda.org/ivnp`), node lifecycle (`node`), client protocols (`client`: SAM v3.3, HTTP/HTTPS-CONNECT proxy, SOCKS5 proxy, AddressBook, and Control API), the `ivnpd` daemon and WebUI, and the deterministic simulation testing (`DST`) harness.

---

## 1. Root Embedded Go API (`gosuda.org/ivnp`, L8)

### 1.1 Ownership Hierarchy: `Router` vs. `Destination` (`facade.go`)

`gosuda.org/ivnp` separates router infrastructure from application identities:

- **`ivnp.Router`**: Created via `NewRouter(ctx, cfg)`. Owns local NTCP2/SSU2 sockets, NetDB state, exploratory tunnel pools, and a shared packet memory budget (`Limits.PacketQueueBytes`, default `64 MiB`). `NewRouter` starts local workers immediately and does not create an application destination or block on network readiness.
- **`ivnp.Destination`**: Created via `router.NewDestination(ctx, destCfg)`. Owns a private `foundation.LocalDestination` keypair (cloned and wiped on `Close()`), dedicated inbound and outbound client tunnel pools, a private `RequestManager` for tunneled `LeaseSet` lookups, a `GarlicRatchetManager`, and all child `net.Conn`, `net.Listener`, and packet sockets. `NewDestination` returns only after observing an active inbound/outbound tunnel pair and confirmed `LeaseSet` publication on every bound network.

### 1.2 Multi-Network Contexts, Private Presets & Peer Admission (`networks.go`, `config.go`)

`RouterConfig.Networks` allows a single `Router` to run isolated I2P protocol contexts side by side (for example, the public `netId = 2` network alongside a private `netId = 42` overlay):

| `PublicParticipation` Mode | Router Capabilities | `MaxParticipating` | Floodfill | Intended Deployment |
| :--- | :--- | :--- | :--- | :--- |
| `ParticipationOnDemand` | `HK` | `0` | `false` | Client-only embedded processes |
| `ParticipationWarm` (Default) | `NOP` | `512` | `false` | Long-running nodes contributing transit bandwidth |
| `ParticipationContributor` | `NOPf` | `2048` | `true` | High-capacity public floodfill and transit routers |

| Network Profile Preset | Constructor (`networks.go`) | Destination Preset (`config.go`) | Default Hops / Count | Subnet Quota & IP Diversity | NetDB Readiness / Publication `K` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `NetworkProfilePublic` (`"public"`) | `NewNetwork(name, id, opts...)` | `DefaultDestinationConfig()` | `2` exploratory, `3` client (`3+1` tunnels) | `/16` K-bucket quota `2`; `/16` tunnel diversity | `MinRouters = 50`, `RouterInfoK = 5`, `LeaseSetK = 4` |
| `NetworkProfileSmallPrivate` (`"small_private"`) | `NewSmallPrivateNetwork(name, id, opts...)` | `SmallPrivateDestinationConfig()` | `1` exploratory, `2` client (`2+1` tunnels) | Subnet quota disabled; `IPRestriction = 0` | `MinRouters = 2`, `RouterInfoK = 2`, `LeaseSetK = 2` |
| `NetworkProfileOfficeLAN` (`"office_lan"`) | `NewOfficeLANNetwork(name, id, opts...)` | `OfficeLANDestinationConfig()` | `1` exploratory, `1` client (`2+0` tunnels) | Subnet quota disabled; `IPRestriction = 0`; NAT mapping off | `MinRouters = 1`, `RouterInfoK = 1`, `LeaseSetK = 1` |

Per-network behavior can be customized via `WithNetworkProfile`, `WithListenAddress`, `WithAdvertisedAddress`, `WithPeerSeeds`, `WithReseedServers`, `WithTrustedReseedCerts`, `WithNetDBConfig(NetDBConfig)`, `WithTunnelTiming(lifetime, renewBefore, healthProbe)`, `WithIPRestriction(mode)`, `WithExploratoryTunnels`, `WithPublicParticipation`, and `WithPeerAdmission(fn)` (using `AdmitPeers(hashes...)`, `RejectPeers(hashes...)`, and `ChainAdmission(checks...)`).

### 1.3 Stream Dialing, Happy Eyeballs & Merged Listeners (`stream_facade.go`)

When a `Destination` is bound to multiple networks (`DestinationConfig.Networks`), it uses the exact same cryptographic identity and `.b32.i2p` address on every network.

- **Network String Selection**:
  - Generic network strings (`""`, `"tcp"`, `"tcp4"`, `"tcp6"`, `"stream"`, `"ivnp"`, `"ivnp-stream"`) target all networks bound to the destination in preference order.
  - Network-specific strings (`"<netName>"` or `"<netName>-stream"`, such as `"i2p"` or `"private-mesh-stream"`) target that single network context.
- **Dialing Strategies (`DialStrategy`)**:
  - `DialHappyEyeballs` (default): Starts the primary bound network immediately and staggers each subsequent network leg by `FallbackDelay * i` (`DefaultHappyEyeballsDelay = 250ms`). The first leg to establish a stream cancels the remaining legs and closes any late-arriving connections via `drainDialResults`.
  - `DialParallel`: Dials all candidate networks simultaneously (`delay = 0`).
  - `DialSequential`: Attempts candidate networks one by one in preference order.
  - Callers can inspect which network context won the dial or accepted a stream via `ivnp.ConnectionNetwork(conn)`.
- **Merged Multi-Network Listeners (`mergedListener`)**:
  - Calling `dest.ListenContext(ctx, "ivnp", ":8080")` on a multi-network destination opens a sub-listener on each bound network and fans accepted connections into a unified channel. If one network context experiences a failure, healthy networks continue accepting streams; `Accept()` surfaces a terminal error only when all sub-listeners have exited.

### 1.4 Type-Safe Authenticated vs. Unauthenticated Packet Sockets (`packet.go`, `packet_io.go`)

IVNP enforces a compile-time boundary between authenticated and unauthenticated datagram protocols:

| Constructor & Return Type | Implements `net.PacketConn` | Accepted Network Strings | Wire Protocol |
| :--- | :--- | :--- | :--- |
| `dest.ListenPacketContext` -> `*PacketConn` | **Yes** | `"udp"`, `"packet"`, `"datagram"`, `"datagram2"`, `"<net>-datagram2"` | `Datagram2` (Protocol `19`, target-bound & replay-resistant) |
| `dest.ListenPacketContext` -> `*PacketConn` | **Yes** | `"packet1"`, `"datagram1"`, `"<net>-datagram1"` | `Datagram1` (Protocol `17`, legacy signed) |
| `dest.ListenUnauthPacketContext` -> `*UnauthPacketConn` | **No** | `"meta"`, `"packet3"`, `"datagram3"`, `"<net>-datagram3"` | `Datagram3` (Protocol `20`, 32B claimed source hash) |
| `dest.ListenUnauthPacketContext` -> `*UnauthPacketConn` | **No** | `"raw"`, `"udp-raw"`, `"<net>-raw"` | `Raw` (Protocol `18`, 0B header) |

Passing a raw or `datagram3` network string to `ListenPacket` fails with an explicit constructor error. `UnauthPacketConn.ReadPacket(p)` returns `UnauthPacket{ClaimedSource Hash, HasClaimedSource bool, FromPort uint16}`, making it impossible to pass an unverified sender hash to code expecting a verified `net.Addr`.

---

## 2. Node Lifecycle & Observability (`node` L7, `observability` L2)

### 2.1 Coordinated Startup & Reverse Shutdown (`node/internal/runtime/node.go`)

`node.Subsystem` (`Daemon`) composes `controlplane.Controller` with all enabled L6 client services:

1. **Startup Order (`Start(ctx)`)**:
   - Starts `controlplane.Controller` (transport listeners, NAT discovery, initial reseed, exploratory tunnels).
   - In embedded/memory mode with HTTP or SOCKS5 proxies enabled, initializes the `"default"` client destination (`startProxyDestination`).
   - Starts services sequentially: `addressBook` -> `sam` -> `control` -> `httpProxy` -> `socks5` -> `metricsServer`.
   - If any service fails to start, `closeResources` tears down already-started components in reverse order.
2. **Shutdown Order (`Close()`)**:
   - Stops `metricsServer`, closes `socks5` -> `httpProxy` -> `control` -> `sam` -> `addressBook` (forcibly closing any tracked active client connections via `trackedListener`), and finally closes `controlplane.Controller`.

### 2.2 Observability Endpoints (`observability/internal/registry/http.go`)

| Endpoint | Auth Required | Response Format & Semantics |
| :--- | :--- | :--- |
| `GET /metrics` | Bearer token (if configured) | Prometheus text format `0.0.4` (zero-reflection pooled formatter across 13 metric domains + Go runtime stats) |
| `GET /varz` | Public on allowed listener | Indented JSON snapshot of all atomic counters, gauges, and process memory metrics |
| `GET /healthz`, `GET /livez` | Public on allowed listener | HTTP `200` (`HealthOK` / `HealthDegraded`) or `503` (`HealthUnavailable`) |
| `GET /readyz` | Public on allowed listener | HTTP `200` when `ManagementStatus.Ready == true`, else `503 Service Unavailable` |

---

## 3. Client Services (`client`, L6)

### 3.1 SAM v3.3 Bridge (`client/internal/sam`)

`sam.Server` binds loopback TCP (`127.0.0.1:7656`) and UDP (`127.0.0.1:7655`) listeners and implements SAM v3.1 through v3.3:

- **Handshake & Extensions**: `HELLO VERSION MIN=3.1 MAX=3.3` replies `HELLO REPLY RESULT=OK VERSION=3.3 IVNP_PREPARE=1`. When `IVNP_PREPARE=<target>` is passed to `SESSION CREATE`, the server runs `PrepareDestination` concurrently with tunnel readiness.
- **Session Styles**: `STREAM`, `DATAGRAM` (proto 17), `DATAGRAM2` (proto 19), `DATAGRAM3` (proto 20), `RAW` (proto 18 or custom `PROTOCOL=0..255` excluding `0, 6, 17, 19, 20`), and `PRIMARY` (multiplexing subsessions via `SESSION ADD` and `SESSION REMOVE` keyed by `(LISTEN_PROTOCOL, LISTEN_PORT)`).
- **Offline Signatures & LeaseSet Policy**: Parses SAM v3.3 offline signature blocks when the 32-byte private signing key slot is all zeros, and supports `i2cp.leaseSetType=3|5`, `i2cp.leaseSetEncType=4,6,7`, `i2cp.leaseSetAuthType=0|1|2`, `i2cp.leaseSetClient.dh.<n>`, and `i2cp.leaseSetClient.psk.<n>`.
- **FIFO `STREAM ACCEPT` & Loopback UDP Verification**:
  - `acceptIncomingLoop` and `acceptLoop` match inbound I2P streams to waiting `STREAM ACCEPT` sockets in strict FIFO order while evicting canceled client sockets immediately.
  - UDP datagrams arriving on `127.0.0.1:7655` must originate from the exact same loopback IP address as the session's TCP control socket (`sameSourceIP`) and are accounted against per-session (`4 MiB`) and server-wide (`64 MiB`) byte budgets.

### 3.2 HTTP / HTTPS-CONNECT Proxy (`client/internal/frontend/http_proxy.go`)

`HTTPProxy` (`127.0.0.1:4444`) handles both `.i2p` eepsite requests and clearnet outproxy forwarding:

- **Direct `.i2p` Requests**: Resolves `.b32.i2p`, raw base64, or named `.i2p` hosts (via `AddressBook`), strips hop-by-hop and `X-Forwarded-*` headers, normalizes `User-Agent` to `"MYOB/6.66 (AN/ON)"`, and relays HTTP or `CONNECT` streams over `Network.DialI2P`.
- **Clearnet Outproxy Forwarding**: Non-`.i2p` hosts passing `validClearnetHost` round-robin across configured `Outproxies` (default `exit.stormycloud.i2p`), normalize `User-Agent` to `"Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"`, and tunnel HTTP or `CONNECT` requests through port `80` of the outproxy. A background loop (`warmOutproxyLoop`) warms outproxy LeaseSets and tunnels every `5m`.

### 3.3 SOCKS5 Proxy & Lock-Free AddressBook

- **`SOCKS5Proxy` (`127.0.0.1:4447`, `socks5.go`)**: Accepts SOCKS5 `CONNECT` (`0x01`) requests with domain addressing (`ATYP = 0x03`), monitoring the client socket with `reader.Peek(1)` during `DialI2P` so client disconnects cancel in-flight I2P dials immediately.
- **`AddressBookService` (`client/internal/addressbook`)**: Stores merged hostname maps in an `atomic.Pointer[snapshot]` so `ResolveDestination` is lock-free. Precedence runs from highest to lowest: `PrivateHostsPath` -> `UserHostsPath` -> `HostsPath` -> `defaultBootstrapHosts` (`reg.i2p`, `identiguy.i2p`, `stats.i2p`, `exit.stormycloud.i2p`, `i2p-projekt.i2p`, `zzz.i2p`) -> remote subscriptions (`RefreshInterval = 12h`, conditional `If-None-Match` / `If-Modified-Since`, same-origin redirect enforcement).

---

## 4. `ivnpd` Web Console & REST/SSE API (`cmd/ivnpd`)

`ivnpd` embeds a compiled SvelteKit application (`cmd/ivnpd/webui/build`) served on `127.0.0.1:7070` (`webui_server.go`, `webui_api.go`, `webui_config.go`, `webui_config_schema.go`, `webui_history.go`). At startup, `inlineScriptCSPHashes` computes SHA-256 Content-Security-Policy hashes for every embedded inline script. The frontend exposes URL-addressable operational views (`/`, `/tunnels/`, `/tunnels/[id]/`, `/peers/[b32]/`, `/destinations/`, `/destinations/[name]/`, `/network/`, `/settings/`) with a global `⌘K` / `/` command palette.

| Method & Path | Purpose |
| :--- | :--- |
| `GET /api/status` | Router state, readiness breakdown, `unmet_conditions`, client `capabilities`, router hash, uptime, reachability, transports, reseed counters, and per-service `listening` state |
| `GET /api/metrics` | Structured bandwidth, tunnel, NetDB, transport, proxy, and Go runtime counters |
| `GET /api/history` | 60-minute ring buffer (`720` samples at `5s` intervals) of bandwidth, tunnel, NetDB, and heap telemetry retained across node restarts |
| `GET /api/tunnels` | Active exploratory and client tunnels with 10-minute build window deltas (`recent_build_successes`, `recent_build_failures`) and policy-gated hop/gateway `.b32.i2p` identities |
| `GET /api/netdb?limit=N&q=...` | Searchable `RouterInfo` entries in the local NetDB with total `matched` count |
| `GET /api/peers?b32=...` | Batch lookup of up to `64` comma-separated `.b32.i2p` router identities with `PeerProfileSnapshot` tunnel build latency and outcome histories (requires loopback listener or `-webui-show-peers`) |
| `GET /api/destinations` | Active local destinations, `.b32.i2p` addresses, and token-bucket bandwidth snapshots |
| `GET /api/config`, `PATCH /api/config` | Read the schema-driven configuration descriptor (`fields`, SHA-256 `revision`, `running` vs. on-disk `value`, `pending` restart flags) or atomically patch modified INI keys with `<config>.bak` backup (`0600`) and live `log.level` application |
| `POST /api/config/rollback` | Atomically swap `<config>.bak` and `ivnp.conf` after revision and parser validation |
| `POST /api/actions/reseed` | Trigger an immediate SU3 reseed pass |
| `POST /api/actions/tunnel-probe` | Trigger an immediate tunnel health probe pass |
| `POST /api/actions/restart` | Schedule an in-process router restart supervised by `main.go` while keeping the WebUI listener online |
| `GET /api/actions/log` | Most recent `50` administrative actions (`reseed`, `probe`, `restart`, `config`, `rollback`), newest first |
| `GET /api/events` | 1-second Server-Sent Events (`text/event-stream`) telemetry stream |

---

## 5. Deterministic Simulation Testing (`internal/simnet`, `tools/dstoverlay`, `sim_*.go`)

IVNP includes a full-stack deterministic simulation suite (`//go:build dst || synctest`) that boots multi-router meshes inside Go's `testing/synctest` virtual-time bubble:

1. **Compiler Runtime Overlay (`tools/dstoverlay/main.go`)**:
   - Generates a Go build `-overlay` JSON file patching `GOROOT/src`:
     - Routes contended `sync.Mutex` and `sync.RWMutex` waits inside a `synctest` bubble through `runtime_SemacquireWaitGroup(addr, true)` (`waitReasonSynctestWaitGroupWait`) and disables wall-clock mutex spinning (`runtime_canSpin(0)`) so mutex contention is recognized as durably blocked by the virtual clock.
     - Pins `runtime/rand.go` (`"ivnp-dst-replay-v1"`) for deterministic `select` case ordering and `map` iteration.
     - Disables `sysmon` wall-clock preemption in `runtime/proc.go` and makes `randutil.MaybeReadByte` a no-op.
     - Defines `sync.DurableMutexOverlay = true` so `sim_main_test.go` refuses to compile if `-overlay` was omitted.
2. **Entropy & Virtual Link Scheduling (`internal/simnet`)**:
   - `PinSessionEntropy(seed)` replaces `crypto/rand.Reader` with a deterministic `ChaCha8` stream, while `foundation.SetDeterministicRandomSource` and `dataplane.SetDeterministicSeeds` seed router identities, tunnel build records, and streaming ISSNs.
   - `simnet.Network` schedules every virtual TCP segment and UDP datagram on a deterministic min-heap (`(dueTime, seq)`), supporting configurable per-link latency, jitter, packet drop rates, Gilbert-Elliott 2-state Markov burst loss (`BurstLossConfig`), packet duplication, network partitions, and mid-flight router crashes (`TestDeterministicRouterMesh`, `TestDeterministicRouterMesh16`, `TestSimChaosFailureModels`).
