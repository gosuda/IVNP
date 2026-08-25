# Java I2P / go-i2p / IVNP Interoperability Audit

## Reference baseline

Java I2P is authoritative for compatibility decisions. The reviewed source was
Java I2P commit `a60f10ba3bb728b79c507bb66e2eef1d8931a4d2`
(Core 2.13.0, API 0.9.70). go-i2p commit
`f84788ee12a4aba1df0cab674e203d3f6dfd9f5c` was used as an independent
cross-check, including its pinned go-noise ratchet implementation.

| Boundary | Java I2P | go-i2p | IVNP decision |
| --- | --- | --- | --- |
| RouterInfo | 4,096-byte uncompressed maximum | parsed through `go-i2p/common` | 4,096-byte post-inflation cap; compressed input remains bounded by its `uint16` field and I2NP payload |
| LeaseSet2 encryption keys | at most 8 | supports multiple LS2 keys and prefers X25519 | at most 8 |
| Streaming maximum-size option | payload MSS; default 1,730, ECIES default 1,812, minimum 512; zero I2CP ports are unspecified | Streaming remains less mature than its transport/ratchet layers | advertise 3,050 payload bytes, enforce the peer MSS, acknowledge SYNACK before returning `Dial`, and accept authenticated zero-port replies |
| Floodfill search | daily routing key, Kademlia `K=24`, `B=4`, five queried peers selected with peer profiles | full XOR ordering plus 256 leading-bit exploration buckets | Java-compatible daily routing key, `K=24`, `B=4`, five successfully dispatched queries; one preferred responder-profile entry seeds the search, referrals retain capacity, and referred RouterInfos are refreshed |
| Ratchet Garlic | type-11 compact cloves in Noise-N/New Session and Existing Session | delegated to pinned `go-noise/ratchet` | Java-compatible KDF, block IDs, DateTime-first ordering, and compact type-11 cloves |
| Legacy destination crypto | ElGamal/AES and ECIES destinations | top-level primitives exist, but destination Garlic documents ECIES-only support | both legacy ElGamal/AES and ECIES destination delivery |
| SSU2 header protection | raw ChaCha20 starts at block counter 1 | current implementation leaves `x/crypto/chacha20` at counter 0 | explicit counter 1 for TokenRequest, Retry, handshake, and data header masks |

The cross-check is not treated as a second authority. In particular, current
go-noise mixes the Elligator2 wire representation for the IK `e` transcript,
while Java decodes the key and feeds the decoded X25519 public key to its Noise
state. IVNP follows Java. Current go-noise also hashes the responder static
pre-message for `hs2`, while Java 2.13.0 demonstrably mixes raw `rs`; IVNP
therefore retains Java's raw-key transcript in both directions.

Raw ChaCha20 is another case where go-i2p is a cross-check rather than an
authority. Java `ChaCha20.encrypt` and i2pd `Crypto.cpp` both start header
protection at block counter 1. The reviewed go-i2p metrics implementation uses
the `x/crypto/chacha20` default counter 0. IVNP follows Java and i2pd; an
RFC-vector test and an i2pd TokenRequest/Retry exchange defend that boundary.


IVNP still uses its own bounded packet ceilings where Java permits larger
application messages:

- RouterInfo: 4,096 bytes after decompression;
- LeaseSet variants: 4,096 bytes;
- Streaming packet: 3,072 bytes total, therefore 3,050-byte payload MSS;
- Datagram: 32,768 bytes.

Streaming NACK handling begins at byte 17, followed by resend delay, flags,
option size, options, and payload. ACK processing retains NACKed in-flight
sequences and uses wrap-safe sequence comparison.

## Ownership and retention

Parser outputs alias caller input. NetDB admission copies only verified retained entries. Router buckets are bounded by 256 buckets times configured capacity. Lease entries are bounded to 4,096, evict the earliest-expiring entry at capacity, and are removed by `ExpireLeases` after protocol expiry.

`internal/pool` is a 256-byte through 64-KiB `sync.Pool` slab cache. It is not a retention limit; DHT/lease caps and expiry control retained live memory. Sensitive slice and opaque `Lease` releases clear the entire backing capacity before reuse.

## Packet buffer ownership

`internal/packet.Buffer` adapts the useful gVisor PacketBuffer layout to IVNP:

- pooled contiguous slab plus a pooled opaque handle;
- fixed reserved prefix, pushed header cursor, consumed input cursor, and strict logical payload capacity;
- zero-copy header/payload/wire views;
- single-owner non-concurrent contract;
- idempotent release and rejected use after release.

NTCP2 framed I/O uses the packet buffer's reserved two-byte header and appended authenticated ciphertext. The warmed path remains zero allocation.

## Measured hot paths

Focused sustained benchmarks on linux/amd64, 70,000 iterations:

| Path | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| ECIES Existing Session with caller scratch and periodic DH transition | 6,920 | 0 | 0 |
| SSU2 manager data send framing and bounded egress handoff | 1,526 | 0 | 0 |

## Verification boundary

Source-derived Java I2P and i2pd AES/ChaCha vectors and parser fixtures pass.
Native-network verification now covers:

- simultaneous TCP and UDP binds on one public port;
- authenticated outbound NTCP2 sessions and established SSU2 sessions with
  native routers;
- confirmed RouterInfo and LeaseSet2 publications plus authenticated
  inbound/outbound short-tunnel build replies;
- iterative LeaseSet2 resolution through current native floodfills;
- a production-routed HTTP proxy request through public I2P tunnels to an
  i2pd-hosted eepsite. The site returned HTTP 403 in 5.238 seconds because the
  i2pd web console rejected the tunneled Host header; i2pd's own proxy returned
  the same class of response, so the status proves end-to-end stream delivery
  rather than application success.

Direct comparison with Java I2P and i2pd changed these protocol boundaries:

- tunnel creators apply per-hop decryption transforms to outbound data while
  transit participants apply encryption;
- NetDB target selection uses the UTC daily routing key
  `SHA256(destination-hash || YYYYMMDD)`;
- local transport failures do not consume Java's five-query budget; the
  initial set reserves referral capacity, a bounded shared responder profile
  supplies one preferred seed query, strict XOR ordering resumes after that query,
  and LeaseSet searches refresh referred RouterInfos before using them;
- LeaseSet lookups travel through an outbound tunnel as anonymous router
  Noise-N Garlic and request a one-time ECIES reply key/tag;
- ECIES destination payloads use compact type-11 cloves, and a SYN may place a
  local LeaseSet2 DatabaseStore before its destination Data block;
- Streaming sends a pure ACK after accepting SYNACK and treats zero I2CP
  source/destination ports as unspecified. i2pd emitted both SYNACK ports as
  zero; requiring the locally selected ephemeral/remote ports discarded an
  otherwise authenticated SYNACK.

The controlled native eepsite is the positive compatibility proof. Five
independent 30-second requests to public hostbook sites still did not return an
HTTP response (one failed lookup returned 502); direct b32 requests to
`i2p-projekt.i2p` and `stats.i2p` also timed out. An i2pd proxy fetched those
same two sites with HTTP 200 in 3.821 and 3.258 seconds. These observations are
retained as network-path availability failures, not reported as successful
public-site loads and not hidden behind a same-router shortcut.
