# Subsystem Code Reference: Layer L4 (`dataplane`)

This document provides a code-level walkthrough of Layer **L4 (`dataplane`)**, tracing its public gateway (`dataplane/dataplane_subsystem.go`), central data-plane coordinator (`dataplane/internal/router`), transport managers (`NTCP2Manager`, `SSU2Manager`), sharded circuit runtime (`dataplane/internal/tunnel`), sharded ECIES ratchet manager (`dataplane/internal/garlic`), and tunnel-backed streaming engine (`dataplane/internal/streaming/tunnel`).

---

## 1. Data-Plane Coordinator (`dataplane/internal/router`)

### 1.1 `DataPlane` & `Service` Composition (`data_plane.go`, `router.go`)

`DataPlane` (`dataplane/internal/router/data_plane.go`) wires the core execution components of L4 together without any dependency on L5 (`controlplane`):

```
DataPlane
 ├── service: *Service                   (I2NP expiration check + 64-shard Bloom replay filter)
 ├── tunnels: *tunnel.Runtime            (64-shard circuit table + AES-256-CBC layer execution)
 ├── destinations: *DestinationManager   (Local DestinationSession registry + route tables)
 ├── replyKeys: *garlic.ReplyKeyRegistry (4096-entry single-use 8B tag store for lookup/build replies)
 ├── garlic: *GarlicReceiver             (Dispatches ReplyKey, Router Noise-N, and Destination ECIES)
 └── streaming: *streamingtunnel.TunnelNetwork (I2P Streaming TCBs over destination tunnels)
```

### 1.2 I2NP Ingress & Time-Bucketed Bloom Replay Filter (`router.go`)

When an I2NP message arrives from NTCP2, SSU2, a tunnel endpoint, or a decrypted garlic clove, `Service.HandleFrom(ctx, msg, src)` executes three steps:

1. **Clock Skew Validation**: Rejects messages whose `Header.Expiration` falls outside `[now - 60s, now + 180s]` (`pastSkew = 60s`, `futureSkew = 180s`).
2. **64-Shard Bloom Replay Filter (`replayFilter`)**:
   - Partitioned across 64 mutex-guarded shards (`replayShardCount = 64`) to eliminate cross-core lock contention.
   - Each shard maintains `replayBucketCount = 5` rotating 60-second bitset buckets (`replayFilterBits = 1 << 18` bits per bucket, 4 hash probes per check).
   - Keyed by `(replayScope, MessageID, Expiration, len(Payload), SHA256(Payload))` across three scopes: `replayI2NP`, `replayGarlicSet`, and `replayGarlicClove`.
3. **Sink Dispatch with Provenance (`InboundSource`)**:
   - Preserves `InboundSource{Peer: foundation.Hash, Authenticated: bool, FromGarlic: bool}` and `DatabaseLookupSource` across delivery to `Sinks.Database`, `Sinks.Garlic`, `Sinks.TunnelBuild`, `Sinks.TunnelData`, and `Sinks.DeliveryStatus`.

### 1.3 `GarlicReceiver` Dispatch Pipeline (`data_plane.go`)

When `Service` routes an `I2NPGarlic` (type 11) message to `GarlicReceiver.HandleFrom`, decryption proceeds in strict priority order:

```
Inbound I2NPGarlic Payload
       │
       ├─ 1. First 8 bytes in ReplyKeyRegistry?
       │     └──► OpenOneTimeReplyExistingSession (Lookup / TunnelBuild replies)
       │
       ├─ 2. Router-Targeted Garlic?
       │     └──► garlicecies.OpenRouterMessage (Noise_N_25519_ChaChaPoly_SHA256)
       │
       └─ 3. Destination-Targeted Garlic (DestinationSession.Receive):
             ├─ a) Matches 8B tag in RatchetManager? -> Open ExistingSession
             ├─ b) Valid Elligator2 NewSessionCandidate?
             │     ├─ Extract bundled DatabaseStore(LeaseSet2) from cloves
             │     ├─ Verify leaseSetMatchesRatchetStatic(LS2, candidate.StaticPublic)
             │     ├─ ReserveInboundReply (holds follow-up app traffic until NSR sends)
             │     └─ CommitNew(candidate) (or RetainNew if LS2 arrives separately)
             └─ c) Legacy ElGamal/AES fallback (ReceiveNew / DecryptExisting)
```

---

## 2. Destination Sessions & Prepared Route Execution (`dataplane/internal/router`)

### 2.1 `DestinationSession` & `PreparedRouteSender` (`destination.go`, `prepared_routes.go`, `prepared_sender.go`)

Each active local destination in L4 is represented by a `DestinationSession`:

- **Cryptographic State**: Holds the destination's `foundation.LocalDestination`, its sharded `*garlic.RatchetManager` (configured with ML-KEM-768 and ML-KEM-1024 private keys when post-quantum hybrid capabilities are enabled), and legacy ElGamal `SessionManager`/`TagStore`.
- **Installed Circuits**: Tracks the set of owned inbound and outbound `tunnel.CircuitToken` installations.
- **`PreparedRouteSender`**: Stores reference-counted `PreparedRoute` snapshots (`preparedRouteEntry`) installed by L5 (`InstallRoute`):

```go
type PreparedRoute struct {
	Owner          foundation.Hash
	Remote         foundation.Hash
	Generation     uint64
	KeyType        foundation.CryptoKeyType
	KeyData        []byte
	LegacyKey      cryptography.ElGamalPublicKey
	Legacy         bool
	Gateway        foundation.Hash
	TunnelID       uint32
	Circuit        dataplanetunnel.CircuitToken
	Expires        uint64
	LocalLeaseSet  []byte
	LocalLeaseSet2 bool
}
```

When an application sends a streaming packet or datagram to a remote destination hash, `PreparedRouteSender` (`SendTunnel` / `SendRatchetReply`) acquires `routesMu.RLock()` via `acquireRoute`, updates `route.used.Store(s.routeClock.Add(1))`, increments `route.active.Add(1)`, releases `routesMu.RUnlock()`, encrypts the I2CP-gzipped `I2NPData` message (bundling `LocalLeaseSet` as a second garlic clove when initiating a `NewSession` or before session confirmation), and injects the resulting `I2NPGarlic` block directly into `tunnels.SendBlockPrepared(ctx, route.Circuit, block)`.

### 2.2 Bounded Subscriptions & Bandwidth Limiting (`destination.go`, `destination_bandwidth.go`)

- **Demultiplexing by `(Protocol, ToPort)`**: Inbound destination payloads are parsed by `parseDestinationData` (`data_plane.go`), which validates the 10-byte I2CP gzip header (magic `1f 8b`, method `08`, and zero flags), checks the trailer CRC-32 and ISIZE, takes a zero-allocation slice fast path on single uncompressed DEFLATE stored blocks (`0x01 || LE16(len) || LE16(^len)`), and falls back to a pooled `flate.Resetter` reader (`destinationDataFlatePool`) for compressed blocks before dispatching to `SubscribeBounded(DestinationRoute{Protocol, ToPort}, maxPackets, maxBytes, budget)`. Exact `(Protocol, ToPort)` subscriptions take precedence over wildcard port (`ToPort = 0`) or wildcard protocol (`Protocol = 0`) subscriptions.
- **`DestinationBandwidthLimiter`**: Enforces token-bucket rate limits (`bytesPerSecond`, `burstBytes`) on both destination ingress and egress before queueing.

---

## 3. Transport Managers (`NTCP2Manager` & `SSU2Manager`)

### 3.1 `NTCP2Manager` (`ntcp2_manager.go`)

- **Outbound Dial Coalescing (`dialing map[foundation.Hash]*ntcp2DialAttempt`)**: Multiple callers requesting a session to the same peer hash wait on a single in-flight `ntcp2DialAttempt.done` channel rather than opening parallel TCP connections.
- **Ephemeral Key Replay Cache**: Tracks a 4096-entry circular buffer and hash map (`ntcp2ReplayEntries = 4096`) of observed 32-byte AES-obfuscated `X` values within the `±120s` clock skew window.
- **Crossed-Connection Resolution (`preferInboundSession`)**: If an inbound handshake completes for a peer that already has an active outbound session (or vice versa), both routers compare `bytes.Compare(local[:], peer[:])` so both sides keep the connection initiated by the lower router hash.
- **Idle Tracking Without Syscall Churn (`ntcp2IdleConn`)**: Wraps the underlying `net.Conn` and updates an `atomic.Int64` last-activity timestamp on reads and writes rather than calling `SetDeadline` on every frame.

### 3.2 `SSU2Manager` (`ssu2_manager.go`, `ssu2_setup_queue.go`, `ssu2_introduction.go`, `ssu2_send_mutex.go`)

`SSU2Manager` manages all UDP sessions over a single `UDPBatchConn` (`recvmmsg`/`sendmmsg` on `linux/amd64` and `linux/arm64`) using seven specialized worker loops:

| Worker Loop | Queue / Trigger | Responsibility |
| :--- | :--- | :--- |
| `readLoop` | `UDPBatchConn.ReadBatch` | Reads 4 batches of 32 datagrams; classifies each packet via `establishedPacket` into `authQueue` or `setupQueue` |
| `setupLoop` | `setupQueue` (bounded) | Handles `TokenRequest`, `Retry`, `SessionRequest`, `SessionCreated`, `SessionConfirmed`, `PeerTest`, `Relay*`, and `HolePunch` |
| `authLoop` | `authQueue` | Decrypts established `Data` packets in place, updates `ACKTracker`, processes control blocks, and groups I2NP messages into per-peer `ssu2DispatchBatch`es |
| `dispatchLoop` | `dispatchQueues` | Delivers authenticated I2NP messages to `Service.HandleFrom` (`ssu2DispatchStall = 4s` timeout guard) |
| `ackLoop` | `1ms` coalesce timer | Batches pending ACK ranges (`ACKTracker`) into outbound `Data` packets |
| `egressLoop` | `egressQueue` (`32` slots) | Shuffles consecutive relay/peer-test packets via CSPRNG Fisher-Yates (`shuffleRelaySlots`) and flushes vector batches via `WriteBatchPrefix` |
| `retransmitLoop` | `1s` ticker + sub-second `dueTimer` | Schedules exact `sentAt + rto` wakeup deadlines (`retransmitAndNextDue`) for RFC 6298 RTO retransmission (`max 5` retries, `maxRTO = 1m`), 3-NACK fast retransmit, congestion window + MTU probing (`1280..1500`), and fragment/challenge expiry |

---

## 4. Sharded Circuit Runtime (`dataplane/internal/tunnel`)

### 4.1 64-Shard Table & Lock-Free Transform Execution (`circuits.go`, `runtime.go`)

`tunnel.Runtime` stores installed circuits across `circuitShards = 64` shards indexed by `tunnelID & 63`:

```go
type circuitShard struct {
	mu           sync.RWMutex
	outbound     map[uint32]*outboundCircuit
	inbound      map[uint32]*inboundCircuit
	participants map[uint32]*participantCircuit
}
```

- **Minimal Lock Hold Time**: Every hot-path method (`Send`, `SendRouter`, `SendTunnel`, `SendTunnelToken`, `HandleContext`) acquires `shard.mu.RLock()`, looks up the circuit, verifies `circuit.lifetime == token.generation` (when token-addressed), increments `circuit.lifetime.refs`, and **immediately releases `shard.mu.RUnlock()`**.
- **In-Place Layer Encryption**: All double-IV AES-256-CBC transforms (`LayerCipher.EncryptInPlace` / `DecryptInPlace`), gateway block encoding, endpoint reassembly, and `EstablishedSender` network writes execute with zero locks held on the circuit shard.
- **Reference-Counted Key Wiping**: When the control plane removes or replaces a circuit, `retireCircuitLocked` drops the table's base reference (`refs.Add(-1)`). The last worker goroutine to finish using the circuit (`refs == 0`) zeroes all `LayerCipher` key schedules (`ReleaseSensitive()`) and releases any pending `Reassembler` slab leases.

---

## 5. Sharded ECIES Ratchet & Tunnel Streaming (`dataplane/internal/garlic`, `dataplane/internal/streaming`)

### 5.1 Sharded `garlic.RatchetManager` (`dataplane/internal/garlic/ratchet.go`)

To prevent lock contention when a destination communicates with many concurrent peers, `garlic.RatchetManager` partitions `garlicecies.RatchetManager` instances across `parallelism.Workers(maxSessions)` shards:

- Outbound encryption (`Seal`, `HasSession`, `NeedsBundledLeaseSet`) hashes the target peer's first byte (`peer[0] % len(shards)`) and locks only that shard.
- Inbound `ExistingSession` decryption (`Open`) must look up the 8-byte session tag before the sender's identity is known. Each shard notifies the parent `garlic.RatchetManager` of newly derived and retired tags through the `garlicecies.TagObserver` interface (`TagAdded`, `TagRemoved`), maintaining a 64-way sharded `tagShards [64]ratchetTagShard` (`map[[8]byte]uint16`, indexed by `tag[0] & 63`) that routes 8-byte tags directly to their owning shard.

### 5.2 Tunnel-Backed Streaming Engine (`dataplane/internal/streaming/tunnel/tunnel.go`)

`TunnelNetwork` bridges `DestinationSession` garlic delivery to standard `net.Conn` and `net.Listener` interfaces:

- **Connection Table**: Demultiplexes inbound `ProtocolStreaming (6)` packets by `(localPort, remotePort, ReceiveStreamID, SendStreamID)`.
- **Per-Connection Event Loop (`tunnelConn.maintain`)**: Each active `tunnelConn` runs a single event loop coordinating application `Write` buffers, `sendSchedule` (pacing min-heap), `retrySchedule` (RTO retransmission min-heap), `ackHoldInterval` (`50ms` delayed ACK timer), and `Close` / `Reset` transitions.
