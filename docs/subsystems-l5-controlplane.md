# Subsystem Code Reference: Layer L5 (`controlplane`)

This document provides a code-level walkthrough of Layer **L5 (`controlplane`)**, detailing the runtime `Controller`, per-destination isolation (`destinationRuntime`), control-plane `Router`, route preparation (`StreamingTunnelSender`), session-scoped OBEP seeding (`replyRouterInfoSeeds`), NetDB internals (`controlplane/internal/netdb`), tunnel pool builders (`controlplane/internal/tunnel`), SU3 reseed (`controlplane/internal/reseed`), and NAT port mapping (`controlplane/internal/nat`).

---

## 1. Top-Level Control Plane Runtime (`controlplane/internal/runtime`)

### 1.1 `Controller` Object Graph (`controller.go`)

`runtime.Controller` (re-exported as `controlplane.Controller`) is the root owner of a single I2P network context (`netId`):

```
Controller
 ├── stateStore: *state.SecureStateStore      (AES-256-GCM router.state + .ivnp.lock)
 ├── database: *netdb.Database                (Split Table + KBucketSet + LeaseSet store)
 ├── routerStore: *netdb.RouterInfoStore      (Atomic netdb.routers disk snapshot)
 ├── responderStore: *netdb.ResponderProfileStore (Atomic netdb.responders snapshot)
 ├── core: *router.Router                     (NTCP2/SSU2 sockets, ControlDispatcher, TransportMux)
 ├── profiles: *tunnel.PeerProfiles           (Rolling 32-sample peer build/delivery profiler)
 ├── buildStats: *tunnel.BuildStatistics      (Lock-free packed atomic success/failure ratio)
 ├── creatorBudget: *tunnel.CreatorBudget     (Global pending build concurrency limiter)
 ├── exploratoryPool: *tunnel.Pool            (Router-owned exploratory inbound/outbound circuits)
 ├── exploratoryBuild: *tunnel.BuildManager   (ECIES STBM builder for exploratory tunnels)
 ├── exploratoryMaintainer: *tunnel.PairedPoolMaintainer
 ├── exploratoryHealth: *tunnel.Health        (Bit-31 DeliveryStatus probe runner)
 ├── requests: *netdb.RequestManager          (Iterative Kademlia lookup engine)
 ├── explorer: *netdb.Explorer                (256-bucket deficit explorer)
 ├── lookupResponder: *netdb.LookupResponder  (Floodfill DatabaseLookup worker pool)
 ├── storeFlooder: *netdb.StoreFlooder        (Floodfill DatabaseStore flooder + midnight rollover)
 ├── routerPublisher: *netdb.RouterInfoPublisher
 ├── nat: *natMappingPublisher                (NAT-PMP + UPnP IGD port mapper)
 └── destinations: map[string]*destinationRuntime (Isolated per-destination control/data runtimes)
```

- **Readiness & Peer Telemetry (`management_types.go`, `controller.go`)**: `UnmetReadinessConditions(readiness ReadinessDetails)` evaluates the 8 ordered data-plane readiness requirements (`netdb_routers >= 50`, `router_info_publication`, `lease_set2_publication`, exploratory/client tunnel pools, and `floodfill_advertisement`) as the single source of truth shared by `dataPlaneReady` and the WebUI status API. `Controller.PeerProfileSnapshots(peers)` exports rolling tunnel build outcome and latency profiles per peer hash.

### 1.2 Isolated Client Destination Runtime (`destination_runtime.go`, `client_destination.go`)

Every client destination created via `CreateDestination` or `EnsureDestination` runs inside its own self-contained `destinationRuntime`. Client destinations never share tunnels, lookup paths, or ratchet tables with the router or with sibling destinations:

```go
type destinationRuntime struct {
	name        string
	local       *foundation.LocalDestination
	session     *dataplane.RouterDestinationSession
	ratchet     *dataplane.GarlicRatchetManager
	limiter     *dataplane.RouterDestinationBandwidthLimiter
	pool        *tunnel.Pool
	build       *tunnel.BuildManager
	maintainer  *tunnel.PairedPoolMaintainer
	health      *tunnel.Health
	requests    *netdb.RequestManager
	publisher   *destinationPublisher
	sender      *router.StreamingTunnelSender
}
```

- **Tunneled Private Lookups (`muxRequestSender{private: true}`)**: A destination's `requests` (`*netdb.RequestManager`) never sends direct transport lookups. Every `DatabaseLookup` is sent through one of the destination's own outbound circuits (`destinationRequestPath`), specifies one of the destination's own inbound gateways as the reply path, and attaches a single-use 8-byte ECIES reply tag (`ReplyKeyRegistry`) so floodfill responses return garlic-encrypted.
- **Deterministic Teardown Ordering (`destinationRuntime.release`)**:
  1. Cancels the destination context and waits for `maintainer`, `health`, `requests`, `build`, and `publisher` goroutines to exit.
  2. Unregisters tunnel build and publication reply handlers from the router.
  3. Calls `sender.ReleaseSensitive()`, `pool.Clear()`, `tunnels.RemoveOwner(local.Hash())`, `ratchet.ReleaseSensitive()`, and `local.ReleaseSensitive()`.

---

## 2. Control Plane Router & Route Preparation (`controlplane/internal/router`)

### 2.1 `StreamingTunnelSender` & Coalesced Route Preparation (`route_control.go`, `reply_control.go`)

`StreamingTunnelSender` bridges `dataplane.StreamingTunnelNetwork` to L5 route resolution for a single destination:

1. **Fast Path (Installed `PreparedRoute`)**: If `DestinationSession.PreparedRoutes()` already holds an unexpired `PreparedRoute` for `target` whose outbound `CircuitToken` is still active in `pool`, `Send` delegates directly to `dataplane.RouterPreparedRouteSender` without consulting NetDB.
2. **Coalesced Route Preparation (`prepareRoute`)**:
   - Bounded by `PreparationCapacity = 16` concurrent preparations, `RouteCapacity = 64` cached routes, and `WaiterCapacity = 256` waiting callers (`PreparationTimeout = 30s`).
   - Looks up the target's `LeaseSet` via the destination's private `RequestManager` (or resolves and decrypts the daily `EncryptedLeaseSet` if a `RemoteELSContext` is installed for `target`).
   - Selects the best usable encryption key (`CryptoMLKEM1024X25519` -> `CryptoMLKEM768X25519` -> `CryptoX25519`) and a non-excluded `Lease2`.
   - Seeds the local outbound tunnel endpoint (OBEP) with the remote inbound gateway's `RouterInfo` (`seedLeaseGateway`).
   - Installs the resulting `PreparedRoute` snapshot into `DestinationSession`.
3. **Silent Handshake Lease Exclusion (`ObserveSilentHandshake`)**:
   - When an outbound streaming `SYN` or ECIES `NewSession` goes unanswered, `ObserveSilentHandshake` marks `(remote, outboundCircuit, leaseGateway, leaseTunnelID)` failed for `10s`.
   - Once `silentLeaseCircuitThreshold = 2` distinct local outbound circuits fail against the same remote `(leaseGateway, leaseTunnelID)` pair, that remote lease is excluded across all local circuits.
   - If every `(circuit, lease)` combination has failed, `refreshRemoteLeaseSet` triggers one forced fresh DHT lookup (`LookupLeaseSetFresh`) and clears failure marks if a newer `LeaseSet` arrives.

### 2.2 Session-Scoped Reply `RouterInfo` Seeding (`runtime/router_info_seeder.go`)

When a local outbound tunnel endpoint (OBEP) is asked to forward a message to a remote inbound gateway (`DeliveryTunnel` or `DeliveryRouter`), the OBEP may not yet have that gateway's `RouterInfo` in its own NetDB.

`replyRouterInfoSeeds` solves this without redundant bandwidth overhead:
- Before sending a tunnel-replied `DatabaseLookup`, `DatabaseStore`, paired inbound `ShortTunnelBuild`, or initial streaming packet, the caller invokes `replyRouterInfoSeeds.EnsureSeeded(ctx, endpoint, targetRouterInfo)`.
- `replyRouterInfoSeeds` caches up to `128` compressed `DatabaseStore(RouterInfo)` wire payloads and tracks `(endpointHash, routerInfoSnapshotHash, transportSessionID)` tuples for `replyRouterInfoSeedLifetime = 5m` (up to `1024` entries), coalescing concurrent callers via `entry.done`. If the transport session to the first hop reconnects, the changed `transportSessionID` automatically triggers a fresh seed.

---

## 3. NetDB Engine Internals (`controlplane/internal/netdb`)

| File | Primary Types | Responsibility |
| :--- | :--- | :--- |
| `kbucket.go` | `kBucketSet`, `kBucket` | Kademlia $b=4$ routing tree over ranges `[0, 2047]`; splits through bucket 0 and rejects overflow via Java `RejectTrimmer` semantics |
| `dht.go` | `Table`, `RoutingKey`, `routerSelectionBuffer` | Split `routers` map + `kBucketSet`; per-bucket `/16` IPv4 and `/48` IPv6 routing subnet quota (`DefaultBucketSubnetQuota = 2`); UTC daily routing key (`SHA256(key \|\| YYYYMMDD)`); CPU-pooled zero-allocation XOR partial sort |
| `database.go`, `store.go` | `Database`, `leaseEntry` | Pooled gzip inflation (`<= 4096 B`), version monotonicity, min-heap `leaseExpiries` eviction (`maxLeases = 4096`), and `published` flag isolation |
| `local_router.go`, `local_ls2.go` | `LocalRouterInfo`, `LocalLeaseSet2` | Signs and caches local `RouterInfo` and multi-key `LeaseSet2` (capping lease `EndDate` at `Offline.Expires` when offline-signed) |
| `local_encrypted_ls2.go`, `encrypted_resolution.go` | `LocalEncryptedLeaseSet`, `DecryptEncryptedLeaseSet` | Daily `Red25519` key blinding, two-layer ChaCha20 encryption (`ELS2_L1K`, `ELS2_L2K`), and per-client DH (`ELS2_XCA`) / PSK (`ELS2PSKA`) authorization |
| `requests.go`, `explorer.go` | `RequestManager`, `Explorer` | Coalesced iterative Kademlia lookups (`20s` budget, `3s` step) and 256-bucket deficit exploration |
| `lookup_responder.go`, `store_flooder.go` | `LookupResponder`, `StoreFlooder` | Bounded 64-slot floodfill query responder (with coalesced enqueue copies and pooled `searchReply` referral generation) and 3-target `DatabaseStore` flooder with UTC midnight rollover |
| `confirmation.go`, `publication.go`, `router_publication.go` | `PublicationTokenRegistry`, `LeaseSetPublisher`, `RouterInfoPublisher` | 31-bit `DeliveryStatus` token correlation and multi-wave floodfill publication (`K=4` for LeaseSets, `K=5` for RouterInfo) |
| `persistence.go`, `responder_persistence.go` | `RouterInfoStore`, `ResponderProfileStore` | Atomic `0600` disk snapshots (`netdb.routers` magic `"IVNPNDB\x00"`, `netdb.responders` magic `"IVNPRSP\x00"`) with SHA-256 digests |

---

## 4. Tunnel Pool Builder & Maintenance (`controlplane/internal/tunnel`)

| File | Primary Types | Responsibility |
| :--- | :--- | :--- |
| `build_record.go` | `ShortBuildRequest`, `ShortBuildKeys`, `TransformShortBuildRecord` | 218-byte ECIES `ShortTunnelBuild` (`Noise_N_25519_ChaChaPoly_SHA256`) record sealing/opening and ChaCha20 slot layering |
| `legacy_build.go`, `legacy_build_manager.go` | `VariableBuildRecord`, `LegacyBuildManager` | 528-byte `VariableTunnelBuild` supporting ElGamal-2048 and long ECIES-X25519 records with AES-256-CBC slot layering |
| `build_manager.go` | `BuildManager`, `pendingBuild` | Manages outbound and inbound STBM flights, inbound fake-record SHA-256 tamper verification, `5s` request timeouts, and the `60s` `recent` grace window |
| `creator_budget.go`, `creator_claim.go`, `stats.go` | `CreatorBudget`, `creatorClaim`, `BuildStatistics` | Bounds concurrent pending builds across pools and scales parallelism inversely with Bayesian build success rate (`3/10` prior, decay at `256` samples) |
| `profile.go`, `netdb_source.go` | `PeerProfiles`, `NetDBHopSource` | Rolling 32-sample peer scoring, SipHash-2-4 sub-tier hop ordering, and 3-pass `/16` + `family` diversity selection |
| `pool.go`, `rotation.go`, `paired_maintenance.go`, `health.go` | `Pool`, `PairedPoolMaintainer`, `Health` | Sticky active outbound set, 4-phase bootstrap ordering (Bootstrap Inbound -> Outbound -> Paired Inbound -> Backups), and bit-31 `DeliveryStatus` liveness probing |

---

## 5. Reseed & NAT Discovery (`controlplane/internal/reseed`, `controlplane/internal/nat`)

- **`controlplane/internal/reseed/`**:
  - `su3.go` & `certificates.go`: Verifies 40-byte `I2Psu3\x00` headers and raw PKCS#1 v1.5 RSA-4096 SHA-512 signatures against 18 embedded X.509 certificates (`certs/*.crt`).
  - `reseed.go`: Executes parallel fetches (prioritizing `*.hotseed.gosuda.org`), retains `best` and `fallback` candidates per hash in `dedupSlot`, orders each local K-bucket via Max-Min XOR farthest-point sampling (`fpsOrderBucket`), enforces `/16` and `/48` per-bucket subnet quotas, and returns 16 floodfill anchors for active transport probing.
- **`controlplane/internal/nat/`**:
  - `natpmp/natpmp.go`: Mutex-serialized UDP client (`port 5351`) for public IP discovery and TCP/UDP port mapping with exponential retry (`250ms` to `64s`).
  - `upnp/ssdp.go`, `description.go`, `soap.go`: Strict SSDP `M-SEARCH` parser, XML `WANIPConnection`/`WANPPPConnection` service locator, and SOAP `AddPortMapping` / `DeletePortMapping` / `GetExternalIPAddress` client.
