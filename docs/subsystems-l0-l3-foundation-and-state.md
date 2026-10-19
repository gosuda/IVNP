# Subsystem Code Reference: Layers L0 to L3 (Utilities, Crypto, Foundation & State)

This document provides a code-level structural reference for Layers **L0** (`internal/*`), **L1** (`cryptography`), **L2** (`foundation`, `observability`), and **L3** (`interfaces/*`, `state`). It details the concrete Go structs, method signatures, memory layouts, and concurrency invariants implemented in each package.

---

## 1. Layer L0: Internal Utilities (`internal/`)

### 1.1 `internal/wire` (`cursor.go`)

`wire` provides the zero-allocation binary reading and writing primitives used by every wire parser in IVNP.

```go
type Cursor struct {
	buf []byte
	off int
}

type Writer struct {
	buf []byte
	off int
}
```

- **Reader Contract (`Cursor`)**:
  - `NewCursor(buf []byte) Cursor` initializes `off = 0`.
  - `ReadU8()`, `ReadU16()`, `ReadU32()`, and `ReadU64()` decode big-endian integers via `binary.BigEndian` and advance `off`. If `len(buf) - off` is smaller than the integer width, they return `(0, ErrShortBuffer)` without advancing `off`.
  - `ReadBytes(n int) ([]byte, error)` returns `(nil, ErrLargeField)` if `n < 0` and `(nil, ErrShortBuffer)` if `n > len(buf) - off`. Otherwise it advances `off += n` and returns the subslice `c.buf[start:c.off]`. Callers treat the returned slice as an immutable view into `buf` unless they explicitly copy it.
- **Writer Contract (`Writer`)**:
  - `NewWriter(dst []byte) Writer` wraps a pre-sized destination slice `dst`.
  - `Reserve(n int) ([]byte, error)` validates `0 <= n <= len(w.buf) - w.off`, advances `w.off += n`, and returns `w.buf[start:w.off]` for in-place serialization (for example, AEAD sealing or cryptographic signing directly into the output buffer).
  - `Put(src []byte)` calls `Reserve(len(src))` and copies `src`.

### 1.2 `internal/pool` (`slab.go`)

`pool` eliminates heap allocations on hot packet and decompression paths using power-of-two slab classes:

| Class Index (`i`) | Exponent (`8 + i`) | Slab Capacity (`1 << exp`) | Typical Protocol Consumers |
| :--- | :--- | :--- | :--- |
| `0` | `8` | `256 B` | Short Tunnel Build records (`218 B`), small I2NP control messages |
| `1` | `9` | `512 B` | `Identity` (`391 B`), `LeaseSet2` headers |
| `2` | `10` | `1,024 B` | Variable Tunnel Build records (`528 B`), `LeaseSet2` payloads |
| `3` | `11` | `2,048 B` | `TunnelData` (`1028 B`), SSU2 UDP datagrams (`1280..1500 B`) |
| `4` | `12` | `4,096 B` | `RouterInfo` (`<= 4096 B`), I2P Streaming packets (`<= 3072 B`) |
| `5`..`8` | `13`..`16` | `8 KiB`..`64 KiB` | NTCP2 frames (`<= 65,535 B`), multi-record tunnel builds, datagrams |

- **Pointer-Pooled `Lease` (`leaseSlabs [9]sync.Pool`)**:
  - Putting a value-type `[]byte` into `sync.Pool` allocates a 24-byte slice header on the heap to satisfy the `any` interface conversion. `pool.AcquireLease(n)` avoids this by pooling `*Lease` struct pointers (`struct { buf []byte; class int; released bool }`).
  - For requests with `n > 65536`, `AcquireLease` returns an unpooled `&Lease{buf: make([]byte, n), class: -1}` that is garbage-collected after `Release()`.
  - `Lease.ReleaseSensitive()` calls `clear(l.buf[:cap(l.buf)])` before returning `l` to `leaseSlabs[l.class]`.

### 1.3 `internal/packet` (`buffer.go`)

`packet.Buffer` wraps a `pool.Lease` with explicit head and tail cursors so protocol layers can prepend headers without shifting payload bytes:

```
Slab Backing Array: b.buf[0 : b.limit]
┌───────────────────────────┬───────────────────────────┬───────────────────────────┐
│ Unused Headroom           │ Prepended Header          │ Appended Payload          │
│ b.buf[0 : b.start]        │ b.buf[b.start : b.reserved│ b.buf[b.reserved : b.end] │
└───────────────────────────┴───────────────────────────┴───────────────────────────┘
                            ▲                           ▲                           ▲
                         b.start                   b.reserved                     b.end
```

- `Acquire(reserved, payloadCapacity int) (*Buffer, bool)` initializes `b.start = reserved` and `b.end = reserved`.
- `Push(n int)` decrements `b.start -= n` into the reserved prefix and returns `b.buf[b.start : b.start+n]`.
- `Append(n int)` increments `b.end += n` into the payload region and returns `b.buf[oldEnd : b.end]`.
- `Consume(n int)` advances `b.start += n` toward `b.end` for sequential reading.

### 1.4 `internal/ingress`, `internal/parallelism`, `internal/relay`, `internal/simnet`

- **`internal/ingress/recover.go`**: `Recover(errp *error, reporter Reporter, boundary Boundary, peer net.Addr)` catches panics inside `defer`, formats `ErrRecoveredPanic`, captures `debug.Stack()`, and invokes `reporter.ReportRecoveredPanic(Panic{...})` inside a secondary panic guard.
- **`internal/parallelism/parallelism.go`**: `CPUs()` returns `max(runtime.GOMAXPROCS(0), 1)`; `Workers(work)` returns `min(CPUs(), work)` for `work > 0`.
- **`internal/relay/relay.go`**: `BidirectionalContained` spawns two goroutines copying `leftReader -> right` and `right -> left` using pooled `[32768]byte` arrays (`clear()`ed on return), propagating half-close via `CloseWrite()` when one direction hits `io.EOF`.
- **`internal/simnet/` (`//go:build dst || synctest`)**: Implements `Network`, `Host`, `UDPConn`, `TCPConn`, and `TCPListener` over a deterministic min-heap event queue (`eventHeap` ordered by `(due, seq)`). Each directed link `(from, to)` owns a private PCG PRNG seeded with `SHA256(seed || from.As16() || to.As16())`.

---

## 2. Layer L1: Cryptography (`cryptography/`)

All L1 files reside directly in `/Users/user/work/work3/IVNP/cryptography`:

| File | Primary Types & Functions | Key Implementation Details |
| :--- | :--- | :--- |
| `sensitive.go` | `Sensitive`, `ErrSensitiveReleased` | Common interface (`ReleaseSensitive()`) implemented by all stateful key/cipher structs |
| `chacha.go` | `ChaCha20Poly1305`, `SealChaCha20Poly1305To`, `OpenChaCha20Poly1305To`, `NewChaCha20Stream` | Zero-allocation AEAD sealing/opening into `dst[:0]`; stateless RFC 8439 Poly1305 authenticator with stack-buffer wiping |
| `x25519.go` | `X25519PrivateKey`, `GenerateX25519PrivateKey` | Stores `[32]byte` `scalar` and precomputed `[32]byte` `public`; executes zero-allocation `PublicKey` and `ECDH` via `x25519ScalarMult` and zeroes both arrays on `ReleaseSensitive()` |
| `field25519.go` | `field25519 [4]uint64`, `fieldSqrtRatio`, `x25519ScalarMult` | Unrolled constant-time $\mathbb{F}_{2^{255}-19}$ limb arithmetic (`add`, `sub`, `mul`, `square`, `mulA24`, `invert`, `pow22523`) and RFC 7748 Montgomery ladder |
| `elligator.go` | `EncodeElligator2`, `DecodeElligator2`, `GenerateElligator2X25519` | Checks quadratic residue eligibility before drawing entropy; masks top 2 bits (`0xc0`) of byte 31 |
| `elgamal.go` | `ElGamalPublicKey`, `ElGamalPrivateKey`, `EncryptElGamal`, `DecryptElGamal` | 2048-bit MODP Group 14; 222B plaintext -> 514B ciphertext (`0x00 \|\| a[256] \|\| 0x00 \|\| b[256]`) |
| `mlkem.go` | `MLKEMPublicKey`, `MLKEMPrivateKey`, `GenerateMLKEM`, `Encapsulate` | FIPS-203 ML-KEM-768 (type 6) and ML-KEM-1024 (type 7); stores 64-byte seed in `MLKEMPrivateKey` |
| `streebog.go`, `curve.go` | `Sum256`, `Sum512`, `Verify256`, `Verify512` | Table-driven GOST R 34.11-2012 hash and GOST R 34.10-2012 Weierstrass curve verification |

---

## 3. Layer L2: Foundation & Observability (`foundation/`, `observability/`)

### 3.1 `foundation` Facade & Internal Packages

`foundation` re-exports three internal packages through `foundation/identity.go` and `foundation/network_wire.go`:

1. **`foundation/internal/identity`**:
   - `Identity` (`types.go`): Zero-copy view (`raw []byte`, `cert Certificate`) over a 384+ byte `KeysAndCert` structure.
   - `Mapping` & `MappingIterator` (`types.go`): Zero-copy view and iterator over I2P `key=value;` mappings; `ValidateCanonical()` enforces strict ascending byte order of keys.
   - `LocalDestination` (`address_generator.go`): Thread-safe (`sync.RWMutex`) key container supporting Ed25519, Red25519, X25519, ElGamal, and `OfflineSignature` transient signing keys, advertising capability bitmask `0x07` (`CryptoMLKEM1024X25519`, `CryptoMLKEM768X25519`, `CryptoX25519`).
2. **`foundation/internal/i2np`**:
   - `Header` and `Message` (`i2np.go`): Parsers and serializers for 16-byte standard headers (`Parse`, `ParseWire`, `ParseUnchecked`), 9-byte transport headers (`ParseTransport`), and typed message structs (`DatabaseStore`, `DatabaseLookup`, `DatabaseSearchReply`, `DeliveryStatus`, `TunnelData`, `TunnelGateway`, `VariableTunnelBuild`, `ShortTunnelBuild`).
3. **`foundation/internal/netdb`**:
   - `RouterInfo`, `RouterAddress` (`structures.go`): Zero-copy parsers (`ParseRouterInfo`) separated from `Verify()`.
   - `LeaseSet`, `LeaseSet2`, `EncryptedLeaseSet`, `MetaLeaseSet` (`structures.go`, `extended.go`): Zero-copy parsers and prefixed signature verifiers (`0x03`, `0x05`, `0x07`).
   - `CompressRouterInfo` (`store.go`): Deterministic `gzip.BestCompression` serializer using pooled writers (`ModTime = Unix(0,0)`, `OS = 255`).

### 3.2 `observability` (`observability/internal/registry`)

`observability.Registry` (`registry.go`) stores all telemetry counters and gauges as lock-free `atomic.Uint64` fields organized into 13 domain structs (`Lifecycle`, `Reseed`, `Transport`, `NetDB`, `Tunnel`, `Admission`, `Proxy`, `Control`, `Bootstrap`, `Publication`, `SAM`, `Garlic`, `SSU2`).

- **Nil-Receiver Safety**: Every metric accessor on `*Registry` checks `if r == nil` and falls back to a package-private `zeroRegistryState`, allowing subsystems in unit tests to record metrics with a `nil` registry without branching or panicking.
- **Zero-Reflection Exposition (`http.go`)**: `NewMetricsHandler` writes Prometheus text format `0.0.4` into a pooled `*bytes.Buffer` (`metricsBufferPool`, 8 KiB initial capacity, 64 KiB pooling cap) using `strconv.AppendUint` and `strconv.AppendFloat`.

---

## 4. Layer L3: Domain Interfaces & State (`interfaces/`, `state/`)

### 4.1 `interfaces/destination` & `interfaces/stream`

`interfaces/destination/destination_interface.go` defines the capability-segregated endpoint hierarchy used between `dataplane`, `controlplane`, `client`, and root `ivnp`:

- **Base Interface**: `DestinationEndpoint` (`Hash`, `B32`, `Destination`, `DialI2P`, `ListenI2P`, `SendMessage`, `MarshalDatagramV1To`, `Subscribe`, `Close`).
- **Extension Interfaces**:
  - `ModernDatagramEndpoint`: `MarshalDatagramV2To`, `MarshalDatagramV3To`.
  - `DatagramPayloadEndpoint`: `DatagramMaxPayload(protocol uint8) (int, error)`.
  - `StreamDestinationEndpoint`: `DialStream(ctx, address, localPort)`, `ListenStream(ctx, address)`.
  - `BoundedDestinationEndpoint`: `SubscribeBounded(route, maxPackets, maxBytes, budget)`.
  - `ReadyDestinationEndpoint`: `WaitReady(ctx)`.
  - `PreparingDestinationEndpoint`: `PrepareDestination(ctx, target Hash)`.

### 4.2 `state` Subsystem (`state/internal/*`)

#### INI Configuration Parser (`state/internal/configuration/config.go`, `operating.go`)
- `Parse(text)` enforces `maxConfigBytes = 1 MiB` and `maxConfigEntries = 4096`, strips `#` and `;` comments outside double-quoted strings, and rejects duplicate `(section, key)` pairs.
- `DefaultOperatingForProfile(profile)` and `[network] profile` (`public`, `small_private`, `office_lan`) initialize baseline topology defaults before applying explicit INI key overrides across `[netdb]` (`bucket_subnet_quota`, `min_routers`, `router_info_floodfill_k`, `lease_set_floodfill_k`, `exploration_bootstrap_delay`, `exploration_steady_delay`), `[tunnels]` (`ip_restriction`), `[reseed]` (`trusted_cert_files`, `disable_subnet_quota`, `router_info_files` up to `64` files, and `netid=<network.id>` URL query validation), and `[destinations]` (`<name>.ip_restriction`).
- `ParseOperating` and `LoadOperating` enforce loopback-only binding on `http_proxy`, `socks5`, and `sam` UDP (`udp_host`), require a `16..4096` byte `bearer_token` on `control` and any non-loopback `sam` or `metrics` listener, and require `0600` file permissions whenever any `bearer_token` is present in `ivnp.conf`.

#### Encrypted State Bundle Wire Format (`state/internal/secure_store/state.go`)

`router.state` encrypts the serialized `Bundle` with **AES-256-GCM** using the 32-byte key from `router.keys` and the 5-byte header `"IVNP\x02"` as Additional Authenticated Data (AAD):

```
Outer File (router.state):
┌───────────────────┬───────────────┬───────────────────────────┬──────────────────────────────────────┐
│ Magic "IVNP" (4B) │ Version 0x02  │ GCM Nonce (12B)           │ AES-256-GCM Ciphertext + 16B Tag     │
└───────────────────┴───────────────┴───────────────────────────┴──────────────────────────────────────┘
◄─────────── AAD (5B) ─────────────►

Inner Plaintext Bundle Layout:
1. Router Keys:
   identityLen[2, BE] || routerIdentity[N] || ed25519Private[64] || x25519Private[32]
2. Transport Static Keys:
   ntcp2StaticPriv[32] || ntcp2StaticIV[16] || ssu2StaticPriv[32] || ssu2IntroKey[32]
3. Legacy Named Destinations (Sorted by Name):
   count[2, BE] || (nameLen[1] || name || b64Len[2, BE] || b64 || ed25519Priv[64] || elgamalPriv[256])*
4. Optional Extension 1 - EncryptedLeaseSet Policies:
   count[2, BE] || (nameLen[1] || name || secretLen[2] || secret || mode[1] || clientCount[2] || keys[32*K])*
5. Optional Extension 2 - Modern LocalDestination Private Material:
   count[2, BE] || (nameLen[1] || name || privLen[2, BE] || localDestinationPrivateBytes[privLen])*
6. Optional Extension 3 - Remote EncryptedLeaseSet Access Policies:
   count[2, BE] || (nameLen[1] || name || count[2] || (identLen[2] || ident || secret || kind[1] || dh/psk)*)*
```
