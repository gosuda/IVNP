# IVNP Technical Documentation

This directory contains the architectural specifications, subsystem maps, and wire-level protocol documentation for **IVNP** (`gosuda.org/ivnp`). Every document maps directly to packages, types, and state machines in the repository source tree.

---

## Document Catalog

### 1. System Architecture & Codebase Organization

- **[Architecture & Design Invariants](architecture.md)**
  Explains the 10-layer unidirectional DAG (`L0` through `L9`), automated import boundary enforcement (`architecture/architecture_test.go`), subsystem root facades, strict separation between `controlplane` and `dataplane`, reference-counted `CircuitToken` lifetimes, zero-allocation wire cursors, slab pooling, panic containment, and AES-256-GCM persistent state storage.
- **[Codebase & Subsystem Guide](codebase-guide.md)**
  Provides a complete directory-by-directory and file-by-file reference across every package in the repository. Use this guide to locate where specific protocols, state machines, wire parsers, or lifecycle controllers live.

### 2. Core I2P Protocol Stack & Cryptography

- **[Protocols, Wire Formats & Cryptography](protocols-and-cryptography.md)**
  Covers Layer L1 (`cryptography`) and Layer L2 (`foundation`): constant-time $\mathbb{F}_{2^{255}-19}$ field arithmetic, Elligator2 point encoding, X25519, ChaCha20-Poly1305, FIPS-203 ML-KEM-768/1024 post-quantum hybrids, RedDSA (`Red25519`) key blinding, ElGamal-2048, GOST R 34.10/34.11 Streebog, 384-byte `KeysAndCert` identity alignment, `RouterInfo`, `LeaseSet2`, `EncryptedLeaseSet`, `MetaLeaseSet`, and I2NP header formats.
- **[Transports & Tunnels](transports-and-tunnels.md)**
  Details point-to-point transport protocols and multi-hop tunnel execution in `dataplane` and `controlplane`:
  - **NTCP2**: `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`, AES-256-CBC ephemeral key obfuscation, and SipHash-2-4 frame length masking.
  - **SSU2**: `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`, dual ChaCha20 header protection, fragmented `SessionConfirmed`, stateless retry tokens, 7-message `PeerTest`, and `RelayRequest`/`RelayIntro`/`RelayResponse`/`HolePunch` NAT traversal.
  - **Tunnels**: 1024-byte `TunnelData` framing, double-IV AES-256-CBC layer encryption, gateway fragmentation, endpoint out-of-order reassembly, Short Tunnel Build (`STBM`, 218-byte records), and Variable Tunnel Build (`VTBM`, 528-byte records).
- **[Garlic, Streaming & Datagrams](garlic-streaming-and-datagrams.md)**
  Covers end-to-end destination encryption and transport protocols in `dataplane`:
  - **Garlic & ECIES Ratchet**: `Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256` and post-quantum hybrid `Noise_IKhfselg2+hs2`, two-phase `NewSessionCandidate` commit with bundled `LeaseSet2` verification, `ReserveInboundReply` ordering gates, DH and symmetric session-tag ratchets, and single-use `ReplyKeyRegistry` lookup/build tags.
  - **I2P Streaming**: 22-byte streaming packet headers, SYN target-hash replay prevention, offline transient signatures, Jacobson/Karels RTO estimation, congestion control, selective NACK fast retransmit, and min-heap pacing.
  - **Datagrams**: `Datagram1` (protocol 17), `Raw` (protocol 18), target-bound `Datagram2` (protocol 19), and low-overhead `Datagram3` (protocol 20).

### 3. Control Plane, Client Services & Operations

- **[Control Plane & NetDB](controlplane-and-netdb.md)**
  Explains Layer L5 (`controlplane`): split NetDB storage (`Table` + Kademlia $b=4$ `kBucketSet`), daily UTC routing keys, iterative `RequestManager` lookups, `LookupResponder` private-vs-published LeaseSet isolation, `StoreFlooder` with UTC midnight rollover, confirmed `DeliveryStatus` publication, two-layer ChaCha20 `EncryptedLeaseSet` client authorization (`DH` and `PSK`), `PairedPoolMaintainer` tunnel bootstrap ordering, SipHash-2-4 hop tiering, eclipse-resistant SU3 reseed ingestion, and NAT-PMP/UPnP port mapping.
- **[Client Services & Public API](client-services-and-api.md)**
  Covers Layers L6 through L9 (`client`, `node`, root `gosuda.org/ivnp`, and `cmd/ivnpd`):
  - Root Go API (`Router`, `Destination`, multi-network Happy Eyeballs dialing, merged listeners, and `PacketConn` vs. `UnauthPacketConn`).
  - SAM v3.3 server and external client, HTTP/HTTPS-CONNECT eepsite and outproxy gateway, SOCKS5 proxy, and lock-free AddressBook service.
  - `ivnpd` daemon CLI, INI configuration schema, and WebUI REST/SSE endpoints.
- **[Verification, Simulation & Tooling](testing-and-simulation.md)**
  Documents standard verification commands (`go test`, `importformatter`, `gojgp lint`, `architecture_test.go`), deterministic multi-router simulation testing (`internal/simnet`, `tools/dstoverlay`, `sim_*.go`), and live network integration tests (`tests/integration`).
- **[Standalone Reseed Server (`ivnp-reseed`)](../cmd/ivnp-reseed/README.md)**
  Documents the standalone network crawler, token-bucket TCP reachability prober, 4-stage Max-Min XOR peer selector, deterministic RSA-4096 SU3 packager, and HTTP server.

### 4. Layer-by-Layer Subsystem Code References

- **[Subsystem Code Reference: Layers L0 to L3](subsystems-l0-l3-foundation-and-state.md)**
  Struct layouts, method contracts, slab class tables, nil-safe observability counters, and the AES-256-GCM `router.state` binary bundle specification across `internal/*`, `cryptography`, `foundation`, `observability`, `interfaces/*`, and `state`.
- **[Subsystem Code Reference: Layer L4 (`dataplane`)](subsystems-l4-dataplane.md)**
  Internal call graphs, 64-shard Bloom replay filter, `GarlicReceiver` dispatch priority, `PreparedRouteSender` execution, `NTCP2Manager`, `SSU2Manager` 7-loop worker pipeline, 64-shard `tunnel.Runtime`, and sharded `garlic.RatchetManager`.
- **[Subsystem Code Reference: Layer L5 (`controlplane`)](subsystems-l5-controlplane.md)**
  `runtime.Controller` object graph, per-destination `destinationRuntime` isolation, `StreamingTunnelSender` coalesced route preparation, silent-handshake lease exclusion, session-scoped `replyRouterInfoSeeds`, NetDB internals, and STBM/VTBM tunnel builders.
- **[Subsystem Code Reference: Layers L6 to L9](subsystems-l6-l9-services-node-and-cli.md)**
  File-by-file breakdown of `client` (`addressbook`, `frontend`, `sam`), `node` (`Daemon`, `EmbeddedRouter`), root `gosuda.org/ivnp` facade files, `cmd/ivnpd`, `cmd/ivnp-reseed`, and `tools/dstoverlay`.

---

## Protocol Stack to Subsystem Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Application / Client Layer                                                  │
│   Go API (ivnp.Destination)  │  SAM v3.3  │  HTTP Proxy  │  SOCKS5 Proxy    │
│   [L8: root package]         │  [L6: client/internal/{sam,frontend}]        │
├──────────────────────────────┴────────────┴──────────────┴──────────────────┤
│ End-to-End Transport Layer                                                  │
│   I2P Streaming (Proto 6)    │  Datagram1/Raw/Datagram2/Datagram3 (17..20)  │
│   [L4: dataplane/internal/streaming]  [L4: dataplane/internal/datagram]     │
├─────────────────────────────────────────────────────────────────────────────┤
│ End-to-End & Router Session Layer                                           │
│   ECIES-X25519-AEAD-Ratchet (+ ML-KEM-768/1024) │ Legacy ElGamal/AES+Tags   │
│   [L4: dataplane/internal/garlic/ecies]         │ [L4: .../garlic]          │
├─────────────────────────────────────────────────────────────────────────────┤
│ I2NP & Multi-Hop Tunnel Layer                                               │
│   I2NP Framing [L2: foundation/internal/i2np]                               │
│   STBM/VTBM Building & Pool Policy [L5: controlplane/internal/tunnel]       │
│   1024B AES-256-CBC Layer Crypto, Gateway & Reassembly [L4: .../tunnel]     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Network Database & Routing Layer                                            │
│   RouterInfo, LeaseSet1/2, EncryptedLS2, MetaLS [L2: foundation, L5: netdb] │
│   Kademlia XOR Routing, Floodfill, Reseed SU3, NAT-PMP/UPnP [L5]            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Point-to-Point Link Layer                                                   │
│   NTCP2 (TCP + Noise XK + SipHash)  │  SSU2 (UDP + Noise XK + ChaCha20)     │
│   [L4: dataplane/internal/transport/ntcp2]  [L4: .../transport/ssu2]        │
└─────────────────────────────────────────────────────────────────────────────┘
```
