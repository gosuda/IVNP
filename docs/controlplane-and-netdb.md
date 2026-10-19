# Control Plane & NetDB

Layer L5 (`controlplane`) owns network discovery, Kademlia XOR routing, floodfill storage and publication, `EncryptedLeaseSet` blinding and per-client authorization, tunnel pool policy, SU3 reseed verification, and NAT port mapping. All external packages access L5 exclusively through `controlplane/controlplane_subsystem.go`.

---

## 1. Split NetDB & Kademlia XOR Routing (`controlplane/internal/netdb`)

### 1.1 Split `DataStore` + `KBucketSet` (`dht.go`, `kbucket.go`)

`netdb.Table` separates full `RouterInfo` storage from Kademlia routing buckets, matching Java I2P's split `DataStore` + `KBucketSet` design:

- **Full `RouterInfo` Store (`routers map[foundation.Hash]routerEntry`, `floodfills map[foundation.Hash]struct{}`)**: Holds all verified `RouterInfo` records (`MaxRouterInfoBytes = 4096`) and maintains an incremental `floodfills` index across admissions, updates, expirations, and evictions so `Counts() (routers, floodfills int)` and floodfill queries avoid scanning the entire `routers` map. In embedded mode, `routerLimit` bounds total stored routers (`256 * BucketCapacity`), evicting the oldest `lastSeen` entry with deterministic XOR tie-breaking.
- **Kademlia $b=4$ `kBucketSet` (`kbucket.go`)**:
  - Uses `BucketCount = 256`, `KademliaB = 4`, `kademliaBFactor = 8` ($2^{b-1}$), and `kademliaRangeCount = 2048` ($256 \times 8$), with `DefaultBucketCapacity = 24` ($K = 24$).
  - `kademliaRange(local, peer)` computes the leading zero bits of `local ^ peer`, sets `highBit = 255 - leading`, shifts `rangeNumber = highBit << 3`, and ORs in the next 3 bits below `highBit` to map every peer into `[0, 2047]`.
  - **Flood Resistance (`RejectTrimmer`) & Subnet Diversity (`DefaultBucketSubnetQuota = 2`)**: When a leaf bucket (`bucket.begin == bucket.end`) is full (`len(members) >= 24`), `add()` rejects newly arriving peers rather than evicting verified routing entries. Before admitting or updating a peer in `kBucketSet`, `routingAllowsSubnetsLocked` enforces at most `DefaultBucketSubnetQuota = 2` peers (configurable via `SetBucketSubnetQuota`) per IPv4 `/16` or IPv6 `/48` subnet within the same `distanceBucket(local, hash)` band. Rejected peers remain available in the `t.routers` data store.
- **Zero-Allocation XOR Selection (`selectionPool`, `borrowSelectionFloodfills`)**: Closest-peer queries (`ClosestInto`, `ClosestFloodfillsInto`, `ClosestFloodfillsExcludingInto`) borrow pre-allocated `routerSelectionBuffer` structs from a CPU-sized channel pool to run partial selection sorts by XOR distance without heap allocations, with floodfill queries iterating only the indexed `floodfills` set via `borrowSelectionFloodfills()`.

### 1.2 Daily UTC Routing Key (`RoutingKey`)

Floodfill selection never uses the raw 32-byte `RouterInfo` or `LeaseSet` hash directly. Instead, `RoutingKey(key, nowMillis)` computes a daily rotating key at UTC midnight:

$$\text{RoutingKey}(K, t) = \text{SHA-256}\bigl(K_{[0..32)} \parallel \text{ASCII}(\text{"YYYYMMDD"})_{[0..8)}\bigr)$$

This rotation prevents a fixed set of floodfill routers from permanently sitting closest to a target identity hash.

### 1.3 Store Validation, Freshness Windows & LeaseSet Privacy (`database.go`, `store.go`)

`Database.HandleDatabaseStoreAsPublished(store, seenAtMillis, published)` enforces strict structural, version, and clock-skew bounds before admitting any record:

| Record Type | Store Code | Freshness & Admission Rules |
| :--- | :--- | :--- |
| `RouterInfo` | `0` | Decompressed via pooled `gzip.Reader` capped at `4096` bytes (`ErrRouterInfoTooLarge` on overflow); `Hash() == store.Key`; matching `netId`; valid signature; `Published` within `[-90m, +2m]` of `seenAt` (`24h` during reseed); strictly newer `Published > old.Published`. |
| `LeaseSet` (Legacy) | `1` | `Hash() == store.Key`; valid signature; earliest lease `> seenAt - 10m`, latest lease in `(seenAt - 1m, seenAt + 16m]`; strictly newer earliest-lease timestamp. |
| `LeaseSet2` | `3` | `Hash() == store.Key`; if offline-signed, `Offline.Expires >= seenAt` and no lease `EndDate > Offline.Expires`; valid signature over `0x03 \|\| Unsigned`; lease range in `[-10m, +16m]`; strictly newer `Header.Published`. |
| `EncryptedLeaseSet` | `5` | `store.Key == SHA256(sigType[2, BE] \|\| blindedPubKey[32])`; valid `Red25519` signature over `0x05 \|\| Unsigned`; valid expiration range; strictly newer `Published`. |
| `MetaLeaseSet` | `7` | `Hash() == store.Key`; valid signature over `0x07 \|\| Unsigned`; expiration up to `MetaLeaseSetMaxFutureMillis` (`65,535s`). |

#### Private vs. Published LeaseSet Isolation

Every stored `leaseEntry` carries a `published bool` flag:
- LeaseSets received as replies to local `DatabaseLookup` queries are stored with `published = false` (tagged synchronously at `ControlDispatcher.Enqueue` before queueing).
- `Database.StoredLeaseSet(key)` returns any stored entry so local destinations can build outbound routes.
- `Database.StoredPublishedLeaseSet(key, now)` returns **only** unexpired entries with `published == true`. Floodfill `LookupResponder` calls `StoredPublishedLeaseSet`, ensuring that LeaseSets learned through private client lookups are never re-served to third-party peers.

### 1.4 Iterative Lookups, K-Bucket Exploration & Floodfill Operations

- **Iterative `RequestManager` (`requests.go`)**: Coalesces concurrent lookups for the same key (`20s` envelope timeout, `3s` per-attempt step timeout, up to `5` iterative hops). Seeds candidates from `ResponderProfiles` and the closest floodfills to `RoutingKey(key, now)`. When an already-queried peer returns a `DatabaseSearchReply`, `RequestManager` queues background `RouterInfo` lookups for unknown referred hashes and steps to the next closest floodfill.
- **`Explorer` (`explorer.go`)**: Round-robins through all 256 K-buckets. When a bucket holds fewer than `8` peers (`12` during aggressive bootstrap), `Explorer` synthesizes a random 32-byte key in that bucket (flipping bit `255 - bucket` of the local router hash and randomizing lower bits) and launches an exploratory lookup.
- **Floodfill `LookupResponder` & `StoreFlooder` (`lookup_responder.go`, `store_flooder.go`)**:
  - `LookupResponder` processes inbound `DatabaseLookup` queries on a bounded 64-slot queue, coalescing copied `Excluded` and reply-tag slices into a single backing allocation in `Enqueue`, pooling `searchReplyExcludedPool` maps and stack-allocated `[3]RouterRef` referral buffers in `searchReply`, and honoring ECIES one-time reply encryption (`ValidateDatabaseLookupReply`) without ever downgrading encrypted requests to plaintext.
  - When a floodfill receives a `DatabaseStore` with `ReplyToken != 0`, it sends a `DeliveryStatus` confirmation and hands the record to `StoreFlooder`, which clears the reply fields and forwards the store to the `3` closest floodfills (enforcing a 4096-entry deduplication cache and a 3-floods-per-90s per-key rate limit).
  - **UTC Midnight Rollover**: Within `45m` of UTC midnight for `RouterInfo` (or `10m` for `LeaseSet`), `StoreFlooder` also floods to the `2` closest floodfills under *tomorrow's* `RoutingKey` so lookups remain continuous across midnight.
- **Confirmed Publication (`confirmation.go`, `publication.go`, `router_publication.go`)**:
  - `PublicationTokenRegistry` allocates 31-bit non-zero tokens (`(rand | 1) & 0x7fffffff`, keeping bit 31 clear for tunnel health probes).
  - `LeaseSetPublisher` and `RouterInfoPublisher` send `DatabaseStore` waves (`30s` wave timeout) across the 12 closest floodfills until `K = 4` (LeaseSet) or `K = 5` (RouterInfo) floodfills return matching `DeliveryStatus` confirmations.

---

## 2. Two-Layer `EncryptedLeaseSet` & Client Authorization (`local_encrypted_ls2.go`, `encrypted_resolution.go`)

When a destination is configured with `DestinationEncryptedNone`, `DestinationEncryptedDH`, or `DestinationEncryptedPSK`, `LocalEncryptedLeaseSet` wraps the signed inner `LeaseSet2` in two layers of ChaCha20 encryption signed by the daily blinded `Red25519` key:

```
Outer EncryptedLeaseSet (StoreType 5, Signed with Blinded Red25519 Key over 0x05 || Unsigned):
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ Outer Header: sigType(11)[2B] || blindedPubKey[32B] || published[4B] || expires[2B]      │
│               || flags[2B] || encryptedLen[2B]                                           │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ Outer Salt (32B)                                                                         │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ Layer 1 Ciphertext: ChaCha20(key, nonce, counter=1)                                      │
│   Derived via HKDF-SHA256(salt=OuterSalt[32], ikm=subcredential[32]||published[4],       │
│                           info="ELS2_L1K") -> key[32] || nonce[12]                       │
│   ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│   │ Auth Mode (1B): 0x00 (None) | 0x01 (DH: dhPub[32] + N*40B) | 0x03 (PSK: salt+N*40│   │
│   ├──────────────────────────────────────────────────────────────────────────────────┤   │
│   │ Inner Salt (32B)                                                                 │   │
│   ├──────────────────────────────────────────────────────────────────────────────────┤   │
│   │ Layer 2 Ciphertext: ChaCha20(key, nonce, counter=1)                              │   │
│   │   Derived via HKDF-SHA256(salt=InnerSalt[32],                                    │   │
│   │                           ikm=[authCookie[32]]||subcredential[32]||published[4], │   │
│   │                           info="ELS2_L2K") -> key[32] || nonce[12]               │   │
│   │   Plaintext: 0x03 (StoreType LeaseSet2) || Signed Inner LeaseSet2                │   │
│   └──────────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Per-Client DH Authorization (`elsAuthDH = 1`)**: The publisher generates an ephemeral X25519 keypair `(privateDH, dhPublic)` and a 32-byte random `authCookie`. For each authorized client public key `clientPub[32]`, it computes `shared = X25519(privateDH, clientPub)` and runs `HKDF-SHA256(salt=dhPublic, ikm=shared || clientPub || subcredential || published, info="ELS2_XCA")` to derive `clientKey[32] || clientNonce[12] || clientID[8]`. Each 40-byte entry stores `clientID[8] || ChaCha20(authCookie[32])`, sorted by `clientID`.
- **Per-Client PSK Authorization (`elsAuthPSK = 3`)**: Uses a 32-byte random `pskSalt` and `HKDF-SHA256(salt=pskSalt, ikm=psk[32] || subcredential || published, info="ELS2PSKA")` to encrypt `authCookie[32]` under each client's pre-shared key.
- **No-Fallback Invariant**: When a remote destination has a `RemoteELSContext` installed in `StreamingTunnelSender`, `resolveEncryptedLeaseSet` queries only the blinded `EncryptedLeaseSet` DHT key and caps route lifetime at UTC midnight. Plaintext `LeaseSet2` fallback is strictly prohibited.

---

## 3. Tunnel Pool Policy, Hop Selection & Maintenance (`controlplane/internal/tunnel`)

### 3.1 Paired Pool Bootstrap Ordering (`paired_maintenance.go`)

Building tunnels in I2P has a circular dependency: an outbound tunnel build requires an inbound tunnel to receive the `OutboundTunnelBuildReply`, while a private inbound tunnel build should be sent through an outbound tunnel so the Inbound Gateway (IBGW) does not see the creator's direct transport connection. `PairedPoolMaintainer` resolves this in four deterministic phases:

1. **Bootstrap Inbound (`OutboundTunnelID == 0`)**: When no inbound tunnel exists, the maintainer builds an initial inbound tunnel directly over an established transport session to the IBGW.
2. **Primary Outbound**: Once at least one inbound tunnel is active, outbound builds route their `OutboundTunnelBuildReply` through an active inbound `(Gateway, GatewayTunnelID)` pair.
3. **Paired Inbound (`OutboundTunnelID != 0`)**: Subsequent inbound tunnel builds are sent through an active outbound tunnel, garlic-wrapping the `ShortTunnelBuild` message to the IBGW with `SealRouterMessage` (`Noise_N`) and seeding the OBEP with the IBGW's compressed `RouterInfo`.
4. **Backup Tunnels**: Built only after primary inbound and outbound targets are satisfied outside the `renewBefore` rotation window.

### 3.2 Peer Profiling & SipHash-2-4 Hop Tiering (`profile.go`, `netdb_source.go`)

- **`PeerProfiles`**: Tracks a rolling window (`32` samples across up to `512` peers) of build and delivery observations, computing `Score = Successes * 10000 - Failures * 20000 - min(MeanLatency, 10000)` and applying a 2-minute build cooldown after repeated failures.
- **SipHash-2-4 Keyed Hop Ordering (`javaPeerSelectionKeys`)**: Each pool holds a 32-byte random `SelectionKey` used to compute `subTier(peer) = sipHash24(k0, k1, peer) & 0x03` and `order(peer) = sipHash24(orderK0, orderK1, peer)`.
  - For 2-hop client tunnels, hop 0 is drawn from `subTier 2..3` and hop 1 from `subTier 0..1`.
  - For 3-hop client tunnels, hop 0 is drawn from `subTier 1`, the endpoint from `subTier 0`, and middle hops from `subTier 2..3`.
  - This deterministic partitioning prevents predecessor/successor correlation attacks across tunnel rotations.
- **3-Pass Subnet & Family Diversity**: Pass 0 enforces unique IPv4 `/16` prefixes, unique IPv6 `/32` prefixes, unique ports, and unique `family` declarations across all hops in a tunnel; Pass 1 relaxes IP prefix uniqueness under scarcity; Pass 2 relaxes family uniqueness.

### 3.3 60-Second Build Grace Window & Bit-31 Health Probing (`build_manager.go`, `health.go`)

- **5s Request Timeout vs. 60s Grace Window**: If a build attempt does not complete within `normalBuildRequestTimeout = 5s` (`10s` on low-core ARM/Android), `Expire` releases the active `CreatorBudget` slot immediately so the maintainer can start a replacement build, but moves the pending build into `m.recent[replyID]` and retains its `GarlicReplyKey` for the full `buildReplyGracePeriod = 60s`. If the slow reply arrives within 60 seconds and the replacement claim has not yet completed, the tunnel is still installed.
- **Bit-31 `DeliveryStatus` Health Probes**: `Health` sends 12-byte `DeliveryStatus` messages (`msgID = nextID | (1 << 31)`) through `OutboundID -> InboundGateway:InboundID`. Setting bit 31 distinguishes tunnel health probes from 31-bit NetDB publication tokens.

---

## 4. Eclipse-Resistant Reseed & Adaptive NAT Mapping

### 4.1 Two-Phase SU3 Reseed Ingestion (`controlplane/internal/reseed`)

- **Raw PKCS#1 v1.5 RSA-4096 Verification (`su3.go`, `certificates.go`)**: Parses the `I2Psu3\x00` header (`SigningRSASHA512_4096 = 6`), locates the signer's X.509 certificate among the 18 embedded `.crt` files in `controlplane/internal/reseed/certs/`, computes `SHA-512` over the header and ZIP payload, and calls `rsa.VerifyPKCS1v15(pub, crypto.Hash(0), digest[:], sig)` (verifying raw block-type-1 padding without an ASN.1 `DigestInfo` prefix, per the I2P SU3 specification).
- **Two-Phase Admission (`reseed.go`)**:
  1. `fetchCandidates` queries up to 3 reseed servers in parallel (prioritizing `*.hotseed.gosuda.org` within a 5s merge window), validates `netId` and 24-hour freshness before signature verification, and retains both the newest (`best`) and second-newest (`fallback`) `RouterInfo` per router hash (`dedupSlot`) so a corrupt or forged newer record from one server cannot shadow a valid record from another.
  2. `ingestCandidates` groups candidates by local K-bucket, orders each bucket via Max-Min XOR farthest-point sampling (`fpsOrderBucket`), lazily verifies signatures (falling back to `slot.fallback` on failure), enforces per-bucket subnet quotas (`<= 2` routers per IPv4 `/16` or IPv6 `/48`, `<= 20` total per bucket), and returns up to `16` floodfill anchors for active live transport probing (`probeReseedAnchors`).

### 4.2 NAT-PMP & UPnP IGD Port Mapping (`controlplane/internal/nat`, `runtime/nat_mapping.go`)

`natMappingPublisher` discovers external addresses and maps NTCP2 (TCP) and SSU2 (UDP) ports automatically:
1. Probes candidate local gateways via RFC 6886 **NAT-PMP** (`UDP port 5351`, `500ms` probe timeout).
2. Falls back to **UPnP IGD** (`M-SEARCH` multicast to `239.255.255.250:1900`, XML service discovery for `WANIPConnection` / `WANPPPConnection`, and SOAP `AddPortMapping` / `GetExternalIPAddress`).
3. Renews mappings at `2/3` of the granted lease lifetime, updates `LocalRouterInfo` reachability (`Reachable` vs. `Firewalled`), and unmaps ports cleanly on `Close()`.
