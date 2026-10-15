# Codebase & Subsystem Guide

This document maps every directory, package, and source file across IVNP's 10 architectural layers (`L0` through `L9`). Use it as a structural blueprint when navigating or modifying the repository.

---

## High-Level Directory Map

```
IVNP/
├── internal/               # [L0] Zero-allocation wire cursors, slab pools, packet buffers, ingress recovery, simnet
├── cryptography/           # [L1] X25519, Elligator2, ChaCha20-Poly1305, ML-KEM-768/1024, ElGamal, Streebog
├── foundation/             # [L2] Identities, Certificates, Mapping, OfflineSignature, I2NP, NetDB wire structures
├── observability/          # [L2] Lock-free atomic metrics registry, Prometheus /metrics, /healthz, structured slog
├── interfaces/             # [L3] Domain contracts for DestinationEndpoint and StreamNetwork
├── state/                  # [L3] Zero-dep INI config parser, symlink-safe atomic FS store, AES-256-GCM state store
├── dataplane/              # [L4] Noise, NTCP2, SSU2, 1024B Tunnels, ECIES Ratchet, Streaming, Datagrams, Data Router
├── controlplane/           # [L5] Kademlia NetDB, Floodfill, STBM/VTBM Tunnel Pools, Reseed SU3, NAT-PMP/UPnP, Runtime
├── client/                 # [L6] SAM v3.3 server/client, HTTP eepsite/outproxy, SOCKS5, Control API, AddressBook
├── node/                   # [L7] Coordinated Daemon lifecycle and multi-network EmbeddedRouter controller
├── *.go (root package)     # [L8] Public Go API (Router, Destination, Dialer, ListenConfig, PacketConn, UnauthPacketConn)
├── cmd/
│   ├── ivnpd/              # [L9] Standalone router daemon and embedded SvelteKit WebUI
│   └── ivnp-reseed/        # [L9] Autonomous DHT crawler, TCP prober, Max-Min XOR selector, and SU3 reseed server
├── architecture/           # [L9] Automated DAG layer and canonical import enforcement tests
├── tests/integration/      # [L9] Live I2P eepsite and end-to-end round-trip integration tests
└── tools/                  # Build tooling: canonical importformatter and synctest dstoverlay generator
```

---

## Layer L0: Internal Utilities (`internal/`)

L0 packages have zero internal dependencies and rely only on the Go standard library.

### `internal/wire`
- **`cursor.go`**:
  - `Cursor`: Zero-allocation sequential binary reader over a caller-owned `[]byte` (`ReadU8`, `ReadU16`, `ReadU32`, `ReadU64`, `ReadBytes`, `Skip`). Returned byte slices borrow directly from the underlying buffer.
  - `Writer`: Fixed-capacity binary serializer (`PutU8`, `PutU16`, `PutU32`, `PutU64`, `Put`, `Reserve`). Writes directly into caller-supplied storage without heap growth.

### `internal/pool`
- **`slab.go`**:
  - `Lease`: Pooled byte-slice wrapper across 9 power-of-two size classes (`256 B` to `64 KiB`, `minClass = 8`, `maxClass = 16`). Pools `*Lease` pointers (`leaseSlabs`) to avoid slice-header boxing allocations on `sync.Pool.Put`.
  - `AcquireLease(n)`, `Lease.Bytes(n)`, `Lease.Release()`, `Lease.ReleaseSensitive()` (wipes full backing capacity before returning to pool).
  - `Acquire(n)`, `Release(buf)`, `ReleaseSensitive(buf)`: Direct slice pooling helpers.

### `internal/packet`
- **`buffer.go`**:
  - `Buffer`: Single-owner packet buffer backed by `bufferPool` and a `pool.Lease`. Pre-allocates `reserved` header headroom and `payloadCapacity` tail room so protocols can prepend headers via `Push(n)`, append payloads via `Append(n)`, and advance read cursors via `Consume(n)` without copying.

### `internal/ingress`
- **`recover.go`**:
  - `Boundary` (`BoundaryNTCP2Handshake` through `BoundarySAMWorker`), `Panic`, `Reporter`, `Recover`, `Report`. Isolates panics at socket and worker boundaries, captures stack traces, and converts panics into `ErrRecoveredPanic`.

### `internal/parallelism`
- **`parallelism.go`**:
  - `CPUs()`: Returns `max(runtime.GOMAXPROCS(0), 1)`.
  - `Workers(work)`: Bounds worker pool counts to `min(CPUs(), work)`.

### `internal/relay`
- **`relay.go`**:
  - `Bidirectional` and `BidirectionalContained`: Copies data in both directions between two `net.Conn` endpoints using pooled 32 KiB buffers (`clear()`ed on release), propagating `CloseWrite()` half-close on clean EOF and joining errors on failure.

### `internal/simnet` (`//go:build dst || synctest`)
- **`entropy_dst.go`**: `PinSessionEntropy(seed)` replaces `crypto/rand.Reader` with a mutex-serialized `ChaCha8` stream so OS entropy syscalls cannot perturb `synctest` goroutine scheduling.
- **`simnet.go`**: `Network` min-heap discrete-event packet scheduler (`eventHeap`), per-directed-edge `LinkConfig` (latency, jitter, drop rate, deterministic Nth-packet drop, Gilbert-Elliott 2-state Markov `BurstLossConfig`, duplication, bandwidth rate limiting), and per-link PCG PRNG seeded from `SHA256(seed || from || to)`.
- **`tcp.go`**: In-memory `TCPListener` and `TCPConn` modeling SYN handshakes, 200ms SYN retries, 64 KiB segmentation, receive window flow control (`256 KiB`), and reorder buffers (`256` segments).
- **`udp.go`**: In-memory `UDPConn` implementing `net.PacketConn` and `AddrPort` batch methods.

---

## Layer L1: Cryptography (`cryptography/`)

- **`cryptography_subsystem.go`**: Package doc and L1 boundary marker.
- **`sensitive.go`**: `Sensitive` interface (`ReleaseSensitive()`) and `ErrSensitiveReleased`.
- **`chacha.go`**: `ChaCha20Poly1305` stateful AEAD wrapper (`SealTo`, `OpenTo`, `ReleaseSensitive`), stateless zero-allocation `SealChaCha20Poly1305To` / `OpenChaCha20Poly1305To`, and `NewChaCha20Stream` (initializing block counter to `1`).
- **`x25519.go`**: `X25519PrivateKey` holding a raw `[32]byte` scalar and precomputed `[32]byte` public key, executing zero-allocation `PublicKey` and `ECDH` via `x25519ScalarMult` and wiping both arrays on `ReleaseSensitive()`.
- **`field25519.go`**: Constant-time 4-limb (`[4]uint64`) arithmetic in $\mathbb{F}_{2^{255}-19}$ (`add`, `sub`, `mul`, `square`, `mulA24`, `invert`, `pow22523`, `fieldSqrtRatio`) and RFC 7748 Montgomery ladder (`x25519ScalarMult`) using unrolled `math/bits.Mul64` and branchless bitmask selection.
- **`elligator.go`**: Constant-time `EncodeElligator2`, `DecodeElligator2`, and `GenerateElligator2X25519` for indistinguishable 256-bit X25519 ephemeral public keys in NTCP2, SSU2, and ECIES NewSession messages.
- **`elgamal.go`**: Legacy I2P 2048-bit MODP Group 14 `EncryptElGamal` and `DecryptElGamal` (514-byte wire ciphertext with `0xFF || SHA256(222B plaintext) || plaintext` framing).
- **`mlkem.go`**: Post-quantum FIPS-203 `MLKEMPublicKey` and `MLKEMPrivateKey` (64-byte seed retention) for `MLKEM768X25519` (type 6, 1184B pubkey, 1088B ciphertext) and `MLKEM1024X25519` (type 7, 1568B pubkey, 1568B ciphertext).
- **`streebog.go` & `streebog_tables.go`**: GOST R 34.11-2012 256-bit (`Sum256`) and 512-bit (`Sum512`) hash functions using 8 precomputed 64-bit lookup tables.
- **`curve.go`**: GOST R 34.10-2012 256-bit (`Verify256`) and 512-bit (`Verify512`) elliptic curve signature verification.

---

## Layer L2: Foundation & Observability (`foundation/`, `observability/`)

### `foundation/`
- **`foundation_subsystem.go`, `identity.go`, `network_wire.go`, `random_dst.go`**: Subsystem facade re-exporting all identity, I2NP, and NetDB wire primitives.
- **`foundation/internal/identity/`**:
  - `types.go`: `Hash` (`[32]byte`), `Certificate`, `SigningKeyType` (0..11), `CryptoKeyType` (0..7), 384-byte base `Identity` (`KeysAndCert` with left-aligned crypto key and right-aligned signing key), and canonical `Mapping` / `MappingIterator`.
  - `signature.go`: `VerifySignature` and `VerifySignaturePrefixed` supporting DSA-SHA1, ECDSA (P256/P384/P521), RSA (2048/3072/4096), Ed25519, Ed25519ph, RedDSA (`Red25519`), and GOST R 34.10 (256/512).
  - `encrypted_signing.go`: `GenerateRed25519Key`, `Red25519Sign`, `EncryptedLeaseSetAlpha` (`HKDF-SHA256` with `"I2PGenerateAlpha"` and `"i2pblinding1"`), `BlindEncryptedLeaseSetPublic`, `BlindEncryptedLeaseSetPrivate`, and `EncryptedLeaseSetSubcredential`.
  - `offline_signature.go`: `OfflineSignature` parser, serializer, and transient key verifier.
  - `address_generator.go`: I2P Base64 (`-~`) and `.b32.i2p` codecs, `LocalDestination` (managing Ed25519/Red25519/X25519/ElGamal/offline keys and capability mask `0x07`), `LocalAddress`, and `LocalRouterAddress`.
- **`foundation/internal/i2np/`**:
  - `i2np.go`: Standard 16-byte header (`Parse`, `ParseWire`, `ParseUnchecked`, `MarshalTo`), 9-byte transport header (`ParseTransport`, `MarshalTransportTo`), 5-byte legacy short header, and wire codecs for `DatabaseStore` (1), `DatabaseLookup` (2), `DatabaseSearchReply` (3), `DeliveryStatus` (10), `Garlic` (11), `TunnelData` (18), `TunnelGateway` (19), `Data` (20), `TunnelBuild` (21/22), `VariableTunnelBuild` (23/24), `ShortTunnelBuild` (25/26), and `TunnelTest` (231).
- **`foundation/internal/netdb/`**:
  - `structures.go`: Zero-copy parsers and serializers for `RouterAddress`, `RouterInfo` (`MaxRouterInfoBytes = 4096`), `Lease`, `LeaseSet` (type 1), `Lease2`, `LeaseSet2Header`, and `LeaseSet2` (type 3, including `SelectUsableEncryptionKey`).
  - `extended.go`: `MetaLease`, `MetaLeaseSet` (type 7, prefix `0x07`), and `EncryptedLeaseSet` (type 5, prefix `0x05`, blinded key hash `SHA256(sigType[2] || blindedPubKey)`).
  - `store.go`: `MarshalDatabaseStore` and deterministic `CompressRouterInfo` (`gzip.BestCompression` with zeroed header metadata).

### `observability/`
- **`observability_subsystem.go`**: Public facade for metrics, health probes, and structured logging.
- **`observability/internal/registry/`**:
  - `registry.go`: Lock-free `atomic.Uint64` `Registry` covering 13 metric domains (`Lifecycle`, `Reseed`, `Transport`, `NetDB`, `Tunnel`, `Admission`, `Proxy`, `Control`, `Bootstrap`, `Publication`, `SAM`, `Garlic`, `SSU2`) plus Go runtime memory/goroutine snapshots.
  - `http.go`: Zero-reflection Prometheus `/metrics` formatter, `/healthz`, `/livez`, `/readyz`, `/varz` JSON handler, and constant-time `RequireBearer` middleware.
  - `log.go`: `slog.Logger` builder (`text`/`json`) and redaction helpers (`Secret`, `SecretBytes`, `SafeError`).

---

## Layer L3: Domain Interfaces & Persistent State (`interfaces/`, `state/`)

### `interfaces/destination` & `interfaces/stream`
- **`interfaces/destination/destination_interface.go`**: Defines `DestinationResolver`, `LeaseSetPolicy`, `DestinationSpec`, `DestinationEndpoint` (and capability extensions `ModernDatagramEndpoint`, `DatagramPayloadEndpoint`, `StreamDestinationEndpoint`, `BoundedDestinationEndpoint`, `ReadyDestinationEndpoint`, `PreparingDestinationEndpoint`), `ReceivedMessage`, `ByteBudget`, and `DestinationController`.
- **`interfaces/stream/stream_interface.go`**: Defines `StreamNetwork`, `Dialer`, `ListenerConfig`, and stream sentinel errors.

### `state/`
- **`state_subsystem.go`**: Public facade for configuration and encrypted state storage.
- **`state/internal/configuration/`**:
  - `config.go`: Zero-dependency INI parser (`maxConfigBytes = 1 MiB`, `maxConfigEntries = 4096`) rejecting duplicate keys and unknown sections.
  - `operating.go`: `Operating` config schema, `DefaultOperating()`, loopback/bearer-token security enforcement, and `DefaultConfigTemplate()`.
- **`state/internal/filesystem_store/`**:
  - `atomic.go`, `secure_unix.go`, `secure_windows.go`: Symlink/reparse-point rejection, hard-link rejection (`Nlink == 1`), `0600`/`0700` and Windows DACL validation, `WriteAtomic` temp-file-and-rename persistence, and `Flock`/`LockFileEx` advisory locking.
- **`state/internal/secure_store/`**:
  - `lock.go`: Exclusive `.ivnp.lock` acquisition (`AcquireLock`).
  - `state.go`: `Store` managing `router.keys` (32-byte master key) and `router.state` (`"IVNP\x02"` AES-256-GCM encrypted `Bundle` of router/transport/destination private keys and ELS2 policies) with full cryptographic round-trip validation on load and save.

---

## Layer L4: Data Plane (`dataplane/`)

- **`dataplane_subsystem.go` & `dst_seed.go`**: Sole public gateway for L4.
- **`dataplane/internal/transport/noise/`**:
  - `state.go`: `SymmetricState` (`Initialize`, `MixHash`, `MixKey`, `EncryptAndHash`, `DecryptAndHash`, `Split`, `ReleaseSensitive`).
- **`dataplane/internal/transport/ntcp2/`**:
  - `handshake.go`: `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256` `Initiator` and `Responder`, AES-256-CBC ephemeral key obfuscation, and SipHash-2-4 key derivation (`askMaster` / `"siphash"`).
  - `frame.go`: `SipState` length obfuscation and zero-allocation `BlockIterator` (`DateTime`, `Options`, `RouterInfo`, `I2NP`, `Termination`, `Padding`).
  - `io.go` & `session.go`: `Direction` and `Session` wrapping `net.Conn` with RWMutex-guarded key lifecycle.
- **`dataplane/internal/transport/ssu2/`**:
  - `packet.go` & `token.go`: `ShortHeader` (16B), `LongHeader` (32B), dual-ChaCha20 `ProtectHeader`, and stateless HMAC-SHA256 retry tokens.
  - `handshake.go`: `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256` `Initiator`/`Responder`, `ConfirmedReassembler` (up to 15 fragments), and `DataCipher`.
  - `block.go` & `ack.go`: TLV block codecs (types 0..20, 254) and `ACKTracker` (up to 64 ACK ranges).
  - `introduction.go`, `peertest.go`, `path.go`: Signed `RelayRequest`/`RelayIntro`/`RelayResponse`, 7-message `PeerTestBlock`, and `PathValidator` migration challenges.
  - `batch.go`, `batch_linux_vector.go`, `batch_linux_amd64.go`, `batch_linux_arm64.go`, `batch_stub.go`, `batch_portable.go`, `dispatch.go`: Linux 64-bit (`amd64` and `arm64`) `recvmmsg`/`sendmmsg` + `SO_RXQ_OVFL` drop counter, portable UDP batching, and bounded `Dispatcher`.
- **`dataplane/internal/tunnel/`**:
  - `crypto.go`: Double-IV AES-256-CBC `LayerCipher` (`EncryptInPlace`, `DecryptInPlace`) with pooled CBC block modes.
  - `blocks.go`, `gateway.go`, `reassembly.go`: `DeliveryBlock` codec, 1028-byte `Gateway` encoder/fragmenter (up to 64 fragments), `Endpoint` checksum verifier, and slab-backed out-of-order `Reassembler` (`maxEntries = 128`, `45s` TTL).
  - `circuits.go` & `runtime.go`: 64-shard circuit table, generation-scoped `CircuitToken`, reference-counted `circuitLifetime` draining, and self-delivery fast paths.
- **`dataplane/internal/garlic/` & `dataplane/internal/garlic/ecies/`**:
  - `ecies/handshake.go` & `ecies/hybrid.go`: `Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256` and post-quantum hybrid `Noise_IKhfselg2+hs2_25519+MLKEM768/1024_ChaChaPoly_SHA256` `Initiator`/`Responder`, bound/unbound `NewSession`, and `NewSessionReply`.
  - `ecies/ratchet.go` & `ecies/ratchet_window.go`: Two-phase `NewSessionCandidate` commit, DH ratchet (`NextKey` block `0x07`, auto-rotate at 4096 messages), symmetric tag/key ratchets, and circular `receiveTags` window (`lookahead = 512`).
  - `ecies/one_time_reply.go` & `ecies/router_message.go`: Single-use 8-byte tag AEAD wrapper for lookup/build replies and `Noise_N` router-to-router garlic encryption.
  - `garlic/ratchet.go`, `reply_keys.go`, `lookup_reply.go`: Sharded `RatchetManager` with global `tagRoutes` index, `ReserveInboundReply` ordering gate, and `ReplyKeyRegistry`.
  - `garlic/clove.go`, `serialize.go`, `newsession.go`, `send.go`, `receive.go`, `session.go`, `manager.go`, `tags.go`: Legacy ElGamal/AES+SessionTag compatibility stack and clove codecs.
- **`dataplane/internal/streaming/` & `dataplane/internal/streaming/tunnel/`**:
  - `packet.go`, `encode.go`, `reliability.go`, `state.go`, `conn.go`: 22-byte streaming header codec, Jacobson/Karels `RTOEstimator`, slow-start/congestion-avoidance `CongestionWindow` (with distinct `FastRecovery()` and `Loss()` transitions), and TCB state machine.
  - `tunnel/tunnel.go` & `deadline.go`: `TunnelNetwork` and `tunnelConn` implementing `net.Conn` and `net.Listener`, SYN target-hash replay protection, offline signature verification, selective NACK fast retransmit, and min-heap send pacing (`250µs..10ms`).
- **`dataplane/internal/datagram/`**:
  - `datagram.go` & `modern.go`: `Raw` (18), `V1` (17), replay-resistant target-bound `V2` (19), and `V3` (20) codecs and verifiers.
- **`dataplane/internal/router/`**:
  - `router.go`, `network.go`, `control_queue.go`: I2NP expiration check, 64-shard time-bucketed Bloom `replayFilter`, `SocketRuntime` (`NativeSocketRuntime`), and two-tier bounded `ControlQueue`.
  - `data_plane.go`, `destination.go`, `destination_bandwidth.go`, `prepared_routes.go`, `prepared_sender.go`: `DataPlane` coordinator, `GarlicReceiver` (including I2CP 10-byte gzip payload framing, zero-allocation stored-block fast path, and pooled `flate.Resetter` fallback), `DestinationSession`, token-bucket bandwidth limiter, and `PreparedRouteSender`.
  - `ntcp2_manager.go` & `ssu2_manager.go` (+ `ssu2_introduction.go`, `ssu2_setup_queue.go`, `ssu2_send_mutex.go`): Full transport connection managers, crossed-connection tie-breaking, SSU2 `setupQueue` vs. `authQueue` isolation, sub-second RTO deadline timer (`retransmitAndNextDue`), introducer relay management, and Fisher-Yates relay packet shuffling.
  - `session_sender.go`, `established_sender.go`, `delivery_forwarder.go`: Control-capable vs. established-only packet senders.

---

## Layer L5: Control Plane (`controlplane/`)

- **`controlplane_subsystem.go`**: Sole public gateway for L5.
- **`controlplane/internal/netdb/`**:
  - `dht.go` & `kbucket.go`: Split `Table` (`routers` map + Kademlia $b=4$ `kBucketSet` over 2048 ranges with Java `RejectTrimmer` flood resistance and per-bucket `/16` IPv4 and `/48` IPv6 subnet diversity quotas), `RoutingKey` (`SHA256(key || YYYYMMDD)`), and pooled zero-allocation XOR selection buffers.
  - `database.go` & `store.go`: `Database` store admission, gzip bomb protection (`<= 4096 B`), version monotonicity, and `published` vs. private lookup-derived LeaseSet separation.
  - `local_router.go`, `local.go`, `local_ls2.go`, `local_encrypted_ls2.go`, `encrypted_resolution.go`: Local `RouterInfo`, `LeaseSet`, `LeaseSet2`, and two-layer ChaCha20 + HKDF `EncryptedLeaseSet` construction and decryption (`ELS2_L1K`, `ELS2_L2K`, `ELS2_XCA` DH auth, `ELS2PSKA` PSK auth).
  - `requests.go`, `explorer.go`, `lookup_responder.go`, `store_flooder.go`, `confirmation.go`, `publication.go`, `router_publication.go`, `responder_profiles.go`, `persistence.go`, `responder_persistence.go`: Iterative DHT lookups, K-bucket exploration, floodfill responder/flooder (with UTC midnight rollover), `DeliveryStatus`-confirmed publication, and atomic `netdb.routers` / `netdb.responders` persistence.
- **`controlplane/internal/tunnel/`**:
  - `build_record.go` & `build_manager.go`: 218-byte ECIES `ShortTunnelBuild` (`Noise_N_25519_ChaChaPoly_SHA256`), ChaCha20 slot layering, inbound fake-record tamper verification, and 60s expired-build grace window (`recent` map).
  - `legacy_build.go` & `legacy_build_manager.go`: 528-byte `VariableTunnelBuild` (ElGamal-2048 and long ECIES-X25519).
  - `profile.go`, `netdb_source.go`, `stats.go`, `creator_budget.go`, `creator_claim.go`: Rolling peer profiling, SipHash-2-4 sub-tier hop ordering, 3-pass `/16` and family diversity selection, and Bayesian build statistics.
  - `pool.go`, `rotation.go`, `paired_maintenance.go`, `health.go`: Sticky outbound selection, `PairedPoolMaintainer` bootstrap ordering (Bootstrap Inbound -> Outbound -> Paired Inbound -> Backups), and bit-31 `DeliveryStatus` health probing.
- **`controlplane/internal/reseed/`**:
  - `su3.go`, `certificates.go`, `reseed.go`, `certs/*.crt`: SU3 container parser, raw PKCS#1 v1.5 RSA-4096 SHA-512 verifier, 18 embedded X.509 certificates, and two-phase eclipse-resistant candidate ingestion (`dedupSlot` fallback + K-bucket farthest-point sampling + `/16` subnet quotas).
- **`controlplane/internal/nat/`**:
  - `natpmp/natpmp.go`: RFC 6886 NAT-PMP UDP client (`port 5351`).
  - `upnp/ssdp.go`, `description.go`, `soap.go`: UPnP IGD multicast SSDP discovery, XML service parsing (`WANIPConnection`/`WANPPPConnection`), and SOAP `AddPortMapping` / `GetExternalIPAddress`.
- **`controlplane/internal/router/` & `controlplane/internal/runtime/`**:
  - `router/runtime.go`, `control_dispatch.go`, `route_control.go`, `reply_control.go`, `transport_mux.go`: Control-plane router state machine, synchronous lookup privacy tagging, coalesced `StreamingTunnelSender` route preparation, `ReserveRatchetReply` gate, silent-handshake lease exclusion, and `TransportMux`.
  - `runtime/controller.go`, `destination_runtime.go`, `client_destination.go`, `destination_publication.go`, `nat_mapping.go`, `router_info_seeder.go`: Top-level `Controller`, isolated per-destination control/data-plane runtime (`destinationRuntime`), tainted-copy master promotion, adaptive NAT renewal, and session-scoped OBEP `RouterInfo` seeding (`replyRouterInfoSeeds`).

---

## Layer L6: Client Services (`client/`)

- **`client_subsystem.go`**: Public facade for L6.
- **`client/internal/addressbook/`**:
  - `service.go`, `bootstrap.go`, `hosts.go`, `subscription.go`, `store.go`: Lock-free `atomic.Pointer[snapshot]` hostname resolver (`PrivateHosts` -> `UserHosts` -> `Hosts` -> `defaultBootstrapHosts` -> remote ETag subscriptions) and atomic state persistence.
- **`client/internal/registration/`**:
  - `regi2p.go`: `reg.i2p` `#!sig=` authentication string generator.
- **`client/internal/frontend/`**:
  - `server.go`, `control.go`, `http_proxy.go`, `socks5.go`, `relay.go`, `target.go`: Connection-limited listeners (`trackedListener`), Bearer-authenticated management `Control` server (`127.0.0.1:7657`), `HTTPProxy` (`127.0.0.1:4444` eepsite and clearnet outproxy gateway with background outproxy warmup), and `SOCKS5Proxy` (`127.0.0.1:4447`).
- **`client/internal/sam/`**:
  - `server.go`, `protocol.go`, `command.go`, `session.go`, `stream.go`, `accept.go`, `datagram.go`, `udp.go`, `private_destination.go`, `budget.go`: Full SAM v3.3 server (`127.0.0.1:7656` TCP / `7655` UDP) supporting `STREAM`, `DATAGRAM`, `DATAGRAM2`, `DATAGRAM3`, `RAW`, `PRIMARY` subsessions, offline signatures, FIFO `STREAM ACCEPT` matching, and bounded byte accounting.
  - `network.go`: External SAM v3.1-v3.3 client adapter.

---

## Layer L7: Node Lifecycle (`node/`)

- **`node_subsystem.go`**: Public facade for L7.
- **`node/internal/runtime/node.go`**: `Daemon` composing `controlplane.Controller`, `AddressBookService`, `SAM`, `Control`, `HTTPProxy`, `SOCKS5Proxy`, and `observability` HTTP server with strict forward startup and reverse teardown ordering.
- **`node/embedded.go`**: `EmbeddedRouter` managing one or more named `controlplane.Controller` network contexts (`NetworkSpec`) inside a single Go process.

---

## Layer L8: Root Module Facade (`gosuda.org/ivnp`)

- **`facade.go`**: `Router` and `Destination` lifecycle, multi-network destination binding with shared `LocalDestination` identity, `WaitReady`, and `ResolveAddr`.
- **`config.go` & `networks.go`**: `RouterConfig`, `DestinationConfig`, `PersistenceConfig`, `NetworkConfig`, `PublicParticipation` modes (`OnDemand`, `Warm`, `Contributor`), and `PeerAdmissionFunc` combinators.
- **`addr.go` & `errors.go`**: `Addr` (`<b32>:<port>`), `NameResolver`, and public sentinel errors (`ErrInvalidConfig`, `ErrIdentityInUse`, `ErrResourceLimit`, `ErrPeerDenied`, etc.).
- **`stream_facade.go`**: `Dialer`, `ListenConfig`, multi-network `DialHappyEyeballs` (`250ms` stagger) / `DialParallel` / `DialSequential`, `ConnectionNetwork(conn)`, and `mergedListener`.
- **`packet.go` & `packet_io.go`**: Compile-time separated `PacketConn` (`Datagram1` and `Datagram2`, implementing `net.PacketConn`) and `UnauthPacketConn` (`Raw` and `Datagram3`), ephemeral port allocation (`49152..65535`), and pooled datagram serialization.

---

## Layer L9: Binaries, Integration Tests & Simulation (`cmd/`, `tests/`, `tools/`, `sim_*`)

- **`cmd/ivnpd/`**:
  - `main.go`, `signal_unix.go`, `signal_windows.go`: Daemon CLI entrypoint, `-memory` mode, PID file management, and `SIGHUP` live log-level reload.
  - `webui_server.go`, `webui_api.go`, `webui_config.go`, `webui/`: Embedded SvelteKit web console (`127.0.0.1:7070`), CSP script-hash calculation, Bearer/Origin validation, `/api/*` REST handlers, and `/api/events` 1-second SSE stream.
- **`cmd/ivnp-reseed/`**:
  - `main.go`, `crawler.go`, `prober.go`, `selector.go`, `store.go`, `packager.go`, `server.go`, `dashboard.go`: Standalone floodfill DHT crawler, token-bucket TCP prober, 4-stage Max-Min XOR peer selector, deterministic HKDF/RSA-4096 SU3 packager, and HTTP server.
- **`tests/integration/`**: Live network eepsite proxy and two-router round-trip tests (`//go:build integration`).
- **`sim_main_test.go`, `sim_harness_test.go`, `sim_dst_test.go`**: Deterministic multi-router simulation suite running inside `testing/synctest` bubbles over `internal/simnet`.
- **`tools/dstoverlay/main.go`**: Generates a Go runtime `-overlay` JSON patching `sync.Mutex`, `runtime/rand.go`, `sysmon`, and `randutil` for 100% deterministic `synctest` replay.
- **`tools/importformatter/main.go`**: AST-based canonical single-block Go import formatter.
