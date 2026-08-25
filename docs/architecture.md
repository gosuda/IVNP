# Architecture

## Subsystems and import direction

IVNP exposes one package root per subsystem. Every subsystem root contains a
`<name>_subsystem.go` facade; concrete implementations live below that
subsystem's `internal` directory. Cross-subsystem code imports only the facade.

```text
gosuda.org/ivnp              Stable public facade
node                         Complete node composition and durable ownership
client                       SAM, proxies, address book, and client services
networking                   Router, tunnels, network database, transports
state                        Configuration and durable encrypted state
observability                Metrics and logging contracts
contracts/destination        Destination-facing shared contracts
contracts/stream             Stream dialing and listening contract
foundation                   Identities, mappings, hashes, and signatures
cryptography                 Cryptographic primitives and key types
internal                     Allocation, wire, relay, and recovery helpers
```

`architecture_test.go` loads production and test imports with `go list`,
rejects upward edges, rejects cross-subsystem `internal` imports, and verifies
every subsystem facade file. Only subsystem roots and `gosuda.org/ivnp` are
stable public import paths.

`foundation` owns common wire structures: certificates, key certificates,
identities, mappings, hashes, local Destinations, and signatures.
`internal/wire` is the only byte cursor/writer implementation. It returns
aliases into caller input and never grows a destination.

## Ownership and GC policy

- Parsers return views into the supplied packet. No map, string, or per-field object is created in parse hot paths.
- A retained RouterInfo or LeaseSet is copied exactly once at netdb admission. Its fields all alias that one byte slice.
- `internal/pool` pools 256-byte through 64-KiB power-of-two slabs. `Lease.ReleaseSensitive` and slice `ReleaseSensitive` clear the complete backing slab before reuse.
- `ClosestInto`, `ClosestFloodfillsInto`, block iterators, and message parsers require caller-provided result storage or return a zero-copy iterator.
- Tests assert zero allocations for identity, I2NP standard-frame, RouterInfo, Kademlia selection, sustained ECIES Existing Session traffic, and SSU2 send framing.

## Wire limits

Every variable-length parser validates its declared length before slicing or multiplication.

| Structure | Bound | Derivation |
| --- | ---: | --- |
| Standard I2NP payload, wire maximum | 65,535 | Unsigned 16-bit header size |
| Standard I2NP frame, wire maximum | 65,551 | `16 + 65,535` |
| i2pd-compatible I2NP payload | 62,690 | `62,708` i2pd buffer `- 2` transport prefix `- 16` header |
| i2pd-compatible standard frame | 62,706 | `16 + 62,690` |
| TunnelData payload | 1,028 | 4-byte tunnel ID + fixed 1,024-byte block |
| TunnelGateway embedded frame | 62,684 | `62,690 - 4` tunnel ID `- 2` length |
| DatabaseLookup payload | 17,512 | `32 + 32 + 1 + 4 + 2 + 512×32 + 32 + 1 + 32×32` |
| RouterInfo decompression | 4,096 | Java I2P 2.13.0 `RouterInfo.MAX_UNCOMPRESSED_SIZE`; one sentinel byte detects exact overflow |
| NTCP2 encrypted frame | 16–65,535 | ChaCha20-Poly1305 tag through uint16 obfuscated length |
| NTCP2 plaintext frame | 0–65,519 | 65,535 encrypted maximum `- 16` tag |
| SSU2 UDP packet | 40–1,472 | Specification minimum and IPv4 MTU-safe maximum |

Mappings reject key/value strings longer than 255 bytes and total encoded content over 65,535 bytes. Certificate encoders reject payloads over 65,535 bytes. Lease counts are capped at 16 and DatabaseLookup exclusions at 512 before byte-count calculations.

Streaming's optional maximum-size field is a payload MSS, not a total packet
size. IVNP therefore advertises `3,050` (`3,072 - 22`) and limits outbound
payload chunks to the peer's advertised MSS. Missing and undersized values use
Java I2P's 1,730-byte default and 512-byte minimum respectively.

## Admission flow

1. Transport authenticates a frame or packet before exposing blocks.
2. I2NP validates its fixed header, declared payload length, and checksum where applicable.
3. DatabaseStore validates its type, reply fields, and compressed RouterInfo size prefix.
4. Netdb parses the contained signed structure, checks that its real hash equals the store key, and verifies the signature.
5. The database derives floodfill eligibility from the stored RouterInfo `caps` option (`f`), retains one exact raw copy, and updates a bounded Kademlia bucket. Floodfill selection writes ordered peers into caller-owned storage.

Reseed follows the same final admission path. Source-pinned HTTPS endpoints require the exact `netid=2` query and the standard I2P reseed User-Agent. The daemon injects the pinned SU3 signer set explicitly at construction. SU3 containers require an active embedded RSA-SHA512-4096 signing certificate and Java `NONEwithRSA` verification of the raw SHA-512 digest in a strict PKCS#1 v1.5 block before their ZIP content is opened. Archive bytes, entry count, total uncompressed bytes, individual RouterInfo size, and the 24-hour reseed publication window are independently bounded. Inbound identity binding and live admission retain the 90-minute freshness rule; cold outbound transport may dial a verified reseed RouterInfo for up to 24 hours so it can fetch a fresh replacement without bootstrap deadlock.

## Cryptography

The standard library provides hashing, AES, X25519, DSA, ECDSA, RSA, Ed25519, and HKDF-adjacent primitives. `golang.org/x/crypto` is deliberately used for maintained ChaCha20 and ChaCha20-Poly1305 implementations. No local ChaCha implementation exists.

Raw ChaCha20 streams used for I2P header protection begin at block counter 1;
the `x/crypto/chacha20` default counter 0 is never used on that wire boundary.
SSU2 applies the explicit counter to both header masks.
Authenticated NTCP2 framing or block syntax failures close the affected
transport session. A valid I2NP block rejected by routing, replay, rate, or
application policy is dropped without tearing down the authenticated session.

NetDB request managers share a bounded recent-responder profile. One preferred
profile entry seeds each iterative lookup, after which daily-routing-key XOR order
controls the remaining Java-compatible five-query budget. Initial local
candidates leave capacity for referrals, local transport failures promote
bounded fallbacks without consuming the wire-query budget, and LeaseSet
referrals refresh RouterInfos before use.
Sparse-bucket exploration starts with daemon maintenance and then drains and
refills its bounded four-lookup window every five seconds. Per-bucket backoff
still begins at 30 seconds, preventing a sparse or hostile region from creating
an unbounded discovery loop.

Streaming completes the three-way open before `Dial` returns: SYNACK closes the
establishment channel, `Dial` sends its pure ACK after the original SYN send has
left the paced worker, then application writes may proceed. Authenticated
packets with I2CP source or destination port zero use the protocol's
unspecified-port semantics; nonzero ports must still match the connection.
