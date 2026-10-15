# Protocols, Wire Formats & Cryptography

This document specifies the cryptographic primitives in Layer L1 (`cryptography`) and the binary wire structures in Layer L2 (`foundation`). All parsers operate on caller-owned buffers via `internal/wire.Cursor` without heap allocation, and all stateful cryptographic objects implement `cryptography.Sensitive` for deterministic memory wiping.

---

## 1. Cryptographic Primitives (`cryptography`, L1)

### 1.1 Constant-Time $\mathbb{F}_{2^{255}-19}$ Field Arithmetic & Elligator2

I2P's modern handshake protocols (NTCP2, SSU2, and `ECIES-X25519-AEAD-Ratchet`) obfuscate ephemeral X25519 public keys on the wire so passive middleboxes cannot distinguish handshake packets from uniform random bytes by testing whether a 32-byte prefix lies on Curve25519.

`cryptography/field25519.go` implements constant-time arithmetic over $p = 2^{255}-19$ using four 64-bit little-endian limbs (`type field25519 [4]uint64`) with unrolled `math/bits.Mul64` schoolbook multiplication (`mul`), symmetrical squaring (`square`), scalar multiplication by $a_{24} = 121665$ (`mulA24`), single-pass $2^{256} \equiv 38 \pmod p$ folding (`fieldFold`), 11-multiplication addition chains for `invert` and `pow22523`, and a stack-allocated RFC 7748 Montgomery ladder (`x25519ScalarMult`).

`cryptography/elligator.go` implements Elligator2 for the Montgomery curve $y^2 = x^3 + 486662 x^2 + x$:

1. **Encoding (`EncodeElligator2(dst, public []byte, random io.Reader) (bool, error)`)**:
   - Given a canonical 32-byte X25519 public coordinate $x \in (0, p)$ with $x \ne -A$, a representative exists if and only if $-2 x (x + A)$ is a quadratic residue modulo $p$.
   - `EncodeElligator2` evaluates `fieldSqrtRatio(x, 2 * (x + A))` ($r_0 = \sqrt{\frac{x}{-2(x+A)}} \bmod p$) **before** consuming any random bytes. Roughly half of generated X25519 public keys are ineligible and return `(false, nil)` immediately.
   - For eligible points, it reads 1 random byte (`entropy`). Bit 0 selects in constant time between $r_0$ and $r_1 = \sqrt{\frac{-x - A}{2x}} = (2 r_0)^{-1}$, normalized into $[0, (p-1)/2]$.
   - Because $(p-1)/2 = 2^{254} - 10$, bits 254 and 255 of the canonical representative are always zero. `EncodeElligator2` masks the top two bits of the 31st byte with random bits (`encoded[31] |= entropy & 0xc0`) so the 256-bit wire value is uniformly distributed.
2. **Decoding (`DecodeElligator2(dst, encoded []byte) error`)**:
   - Clears the two high padding bits (`representative[31] &= 0x3f`) and checks $r \le (p-1)/2$.
   - Computes $d = 1 + 2r^2$, $v = -A \cdot d^{-1} \bmod p$, and $t = v^3 + A v^2 + v$.
   - If $t$ is a nonzero square in $\mathbb{F}_p$, selects $x = v$; otherwise selects $x = -v - A \bmod p$, storing the 32-byte canonical X25519 public key into `dst`.

### 1.2 X25519 Scalar Isolation (`cryptography/x25519.go`)

Standard library `*ecdh.PrivateKey` structs allocate unwiped copies of key material on the Go heap. `cryptography.X25519PrivateKey` stores only the raw `[32]byte` secret scalar (`scalar`) and the precomputed `[32]byte` public key (`public`) in value storage. `NewX25519PrivateKey` and `GenerateX25519PrivateKey` derive `public` once with `x25519ScalarMult(&key.public, &key.scalar, &fieldBasepoint)`, so `PublicKey(dst *[32]byte)` is a fixed-size copy (`0 B/op, 0 allocs/op`). `ECDH(dst *[32]byte, peer []byte)` copies the peer coordinate into a stack array, runs the clamped Montgomery ladder on stack-allocated `field25519` values (`0 B/op, 0 allocs/op`), and rejects the all-zero output produced by small-order peer points with `subtle.ConstantTimeCompare`, clearing `dst` and returning `ErrLowOrderPoint`. Peer encodings with bit 255 set or u-coordinates in `[p, 2^255)` are accepted and reduced as RFC 7748 requires. `TestX25519RFC7748Vectors` pins the RFC 7748 section 5.2 and 6.1 vectors, and `TestX25519MatchesStandardLibrary` cross-checks 2,000 random and non-canonical inputs against `crypto/ecdh`. `ReleaseSensitive()` zeroes both `scalar[:]` and `public[:]`; every later call returns `ErrSensitiveReleased`.

### 1.3 ChaCha20 & ChaCha20-Poly1305 (`cryptography/chacha.go`)

- **`ChaCha20Poly1305`**: Stateful AEAD wrapper around RFC 8439 ChaCha20-Poly1305 (`ChaChaKeySize = 32`, `ChaChaNonceSize = 12`, `ChaChaTagSize = 16`). `SealTo` and `OpenTo` write directly into `dst[:0]` without heap allocation when `cap(dst)` is sufficient.
- **Stateless `SealChaCha20Poly1305To` / `OpenChaCha20Poly1305To`**: Executes RFC 8439 AEAD in zero heap allocations by initializing a stack-bound `chacha20.Cipher` at counter `0` to derive the 32-byte Poly1305 one-time key, advancing to counter `1` for payload encryption, verifying tags in constant time (`subtle.ConstantTimeCompare`), and wiping stack key/tag buffers before returning.
- **`NewChaCha20Stream(key, nonce []byte)`**: Returns an unauthenticated `*chacha20.Cipher` with the initial block counter set to `1` (used for SSU2 header protection, `EncryptedLeaseSet` layers, and `ShortTunnelBuild` slot transformation).

### 1.4 Post-Quantum ML-KEM Hybrids (`cryptography/mlkem.go`)

IVNP implements I2P's post-quantum hybrid LeaseSet2 encryption types using FIPS-203 `crypto/mlkem`:

| `CryptoKeyType` | Constant | Encapsulation Key Size | Ciphertext Size | Noise Protocol Identifier |
| :--- | :--- | :--- | :--- | :--- |
| `6` | `MLKEM768X25519` | `1184` bytes | `1088` bytes | `Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256` |
| `7` | `MLKEM1024X25519` | `1568` bytes | `1568` bytes | `Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256` |

`MLKEMPrivateKey` stores only the 64-byte FIPS-203 seed (`[mlkem.SeedSize]byte`), reconstructing the decapsulation key during `Decapsulate(ciphertext)` and wiping intermediate buffers before returning the 32-byte shared secret.

### 1.5 Legacy ElGamal-2048 & GOST R 34.10 / Streebog

- **ElGamal-2048 (`cryptography/elgamal.go`)**: Uses the 2048-bit MODP Group 14 prime $p$ and generator $g = 2$. `EncryptElGamal` formats a 222-byte plaintext into a 255-byte block (`0xFF || SHA256(plaintext)[32] || plaintext[222]`) and outputs a 514-byte wire ciphertext (`0x00 || a[256] || 0x00 || b[256]`).
- **GOST R 34.11-2012 Streebog & GOST R 34.10-2012 (`streebog.go`, `curve.go`)**: Implements 256-bit (`Sum256`) and 512-bit (`Sum512`) Streebog hashing and Weierstrass curve signature verification (`Verify256`, `Verify512`) so the router can verify all valid network `RouterInfo` and `Destination` identities.

---

## 2. Foundation Identities & Signatures (`foundation`, L2)

### 2.1 Signing and Encryption Key Type Registries (`foundation/internal/identity/types.go`)

#### Signing Key Types (`SigningKeyType`)

| Code | Constant | Public Key Bytes | Signature Bytes | Algorithm |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `SigningDSASHA1` | `128` | `40` | 1024-bit DSA with SHA-1 |
| `1` | `SigningECDSASHA256P256` | `64` | `64` | ECDSA P-256 with SHA-256 |
| `2` | `SigningECDSASHA384P384` | `96` | `96` | ECDSA P-384 with SHA-384 |
| `3` | `SigningECDSASHA512P521` | `132` | `132` | ECDSA P-521 with SHA-512 |
| `4` | `SigningRSASHA256_2048` | `256` | `256` | RSA-2048 (`E=65537`) PKCS#1 v1.5 with SHA-256 |
| `5` | `SigningRSASHA384_3072` | `384` | `384` | RSA-3072 (`E=65537`) PKCS#1 v1.5 with SHA-384 |
| `6` | `SigningRSASHA512_4096` | `512` | `512` | RSA-4096 (`E=65537`) PKCS#1 v1.5 with SHA-512 |
| `7` | `SigningEdDSASHA512Ed25519` | `32` | `64` | Ed25519 (RFC 8032 / SHA-512) |
| `8` | `SigningEdDSASHA512Ed25519ph` | `32` | `64` | Ed25519ph (pre-hashed SHA-512) |
| `9` | `SigningGOSTR3410_256` | `64` | `64` | GOST R 34.10-2012 (256-bit) with Streebog-256 |
| `10` | `SigningGOSTR3410_512` | `128` | `128` | GOST R 34.10-2012 (512-bit) with Streebog-512 |
| `11` | `SigningRedDSASHA512Ed25519` | `32` | `64` | RedDSA (`Red25519`) over Ed25519 curve |

#### Encryption Key Types (`CryptoKeyType`)

| Code | Constant | Identity Wire Bytes | LeaseSet2 Key Bytes | Algorithm |
| :--- | :--- | :--- | :--- | :--- |
| `0` | `CryptoElGamal` | `256` | `256` | ElGamal-2048 |
| `1` | `CryptoP256` | `64` | `64` | ECDH P-256 |
| `2` | `CryptoP384` | `96` | `96` | ECDH P-384 |
| `3` | `CryptoP521` | `132` | `132` | ECDH P-521 |
| `4` | `CryptoX25519` | `32` | `32` | X25519 |
| `6` | `CryptoMLKEM768X25519` | `32` | `1216` (`32 + 1184`) | X25519 + ML-KEM-768 hybrid |
| `7` | `CryptoMLKEM1024X25519` | `32` | `1600` (`32 + 1568`) | X25519 + ML-KEM-1024 hybrid |

### 2.2 `Identity` (`KeysAndCert`) 384-Byte Inline Alignment

An I2P `Identity` (`RouterIdentity` or `Destination`) consists of a fixed 384-byte inline base (`IdentityBaseLength = 384`) followed by a variable-length `Certificate` (`type[1] || length[2, BE] || payload[length]`):

```
Offset   0                               256                     384     387
         ┌───────────────────┬───────────┬───────────┬───────────┬───────┬──────────────────┐
         │ CryptoKey (First) │  Random   │  Random   │SigningKey │ Cert  │ Cert Payload     │
         │ (Left-Aligned)    │  Padding  │  Padding  │ (Right-   │Header │ sigType[2]       │
         │ min(cryptoLen,256)│           │           │ Aligned)  │ (3B)  │ cryptoType[2]    │
         │                   │           │           │min(sig,128│Type=5 │ sigExcess ||     │
         │                   │           │           │           │       │ cryptoExcess     │
         └───────────────────┴───────────┴───────────┴───────────┴───────┴──────────────────┘
         ◄────────── 256 bytes ─────────►◄────── 128 bytes ─────►
```

- **Left-Aligned Crypto Key**: `CryptoKeyParts()` reads the first `min(cryptoLen, 256)` bytes starting at offset `0`.
- **Right-Aligned Signing Key**: `SigningKeyParts()` reads the first `min(signingLen, 128)` bytes ending at offset `384` (i.e., `src[384-inlineSigning : 384]`).
- **Excess Key Material**: When `signingLen > 128` (such as ECDSA P-521 or RSA) or `cryptoLen > 256`, the remaining bytes follow the 4-byte `(signingType, cryptoType)` prefix inside the `CertificateKey` (type 5) payload.
- For a standard modern router (`X25519` + `Ed25519` or `Red25519`), the `CertificateKey` payload is 4 bytes (`[0x00, 0x07, 0x00, 0x04]`), yielding a 391-byte `Identity` whose SHA-256 digest (`Identity.Hash()`) is the 32-byte router or destination hash.

### 2.3 Red25519 & Encrypted LeaseSet Key Blinding (`encrypted_signing.go`)

Destinations that publish an `EncryptedLeaseSet` (store type 5) blind their public signing key daily at UTC midnight so floodfill routers cannot link the published DHT entry back to the underlying `Destination` without knowing the public identity (and optional `secret`):

1. **Daily Blinding Factor $\alpha$ (`EncryptedLeaseSetAlpha`)**:
   - Constructs 36-byte `keydata = publicSigningKey[32] || uint16BE(signingType) || uint16BE(11)`.
   - Computes `salt = SHA256("I2PGenerateAlpha" || keydata)`.
   - Computes `ikm = ASCII(date.UTC().Format("20060102")) || secret`.
   - Expands 64 bytes via `HKDF-SHA256(ikm, salt, info="i2pblinding1")` and reduces modulo the Ed25519 group order $\ell$ (`edwards25519.NewScalar().SetUniformBytes`) to produce scalar $\alpha$.
2. **Blinded Public Key $A'$ (`BlindEncryptedLeaseSetPublic`)**:
   - Decodes the destination's Ed25519 (`7`) or Red25519 (`11`) public point $A$ and computes $A' = A + [\alpha]B$.
3. **Blinded Private Scalar $a'$ (`BlindEncryptedLeaseSetPrivate`)**:
   - Computes $a' = (a + \alpha) \bmod \ell$, where $a$ is the destination's clamped Ed25519 scalar or canonical Red25519 scalar.
4. **RedDSA Signature (`Red25519Sign`)**:
   - Draws 80 random bytes `rand80`.
   - $r = \text{SHA-512}(\text{rand80} \parallel A' \parallel M) \bmod \ell$, $R = [r]B$.
   - $k = \text{SHA-512}(R \parallel A' \parallel M) \bmod \ell$, $S = (r + k \cdot a') \bmod \ell$.
5. **Subcredential Derivation (`EncryptedLeaseSetSubcredential`)**:
   - `credential = SHA256("credential" || keydata)`
   - `subcredential = SHA256("subcredential" || credential || blindedPublicKey[32])`.

---

## 3. Canonical `Mapping` & NetDB Wire Structures (`foundation/internal/netdb`)

### 3.1 Canonical `Mapping` (`foundation/internal/identity/types.go`)

I2P option tables (`RouterInfo` options, `RouterAddress` options, and `LeaseSet2` options) use the `Mapping` wire format:

```
size[2, BE] || (keyLen[1] || key[keyLen] || '=' (0x3d) || valLen[1] || val[valLen] || ';' (0x3b))*
```

`Mapping.ValidateCanonical()` enforces that keys are strictly sorted in ascending raw UTF-8 byte order (`bytes.Compare(previous, key) < 0`). Unsorted or duplicate keys fail with `ErrUnsortedMapping` before signature verification, preventing signature malleability across implementations.

### 3.2 NetDB Store Structures (`structures.go`, `extended.go`)

| Store Type | Name | Signature Prefix | Max Size / Key Formula |
| :--- | :--- | :--- | :--- |
| `0` | `RouterInfo` | None (raw `Unsigned`) | `4096` bytes max; key = `SHA256(RouterIdentity)` |
| `1` | `LeaseSet` (Legacy) | None (raw `Unsigned`) | Up to 16 leases (`44B` each); key = `SHA256(Destination)` |
| `3` | `LeaseSet2` | `0x03 \|\| Unsigned` | Up to 16 `Lease2`s (`40B` each) + multi-key encryption list; key = `SHA256(Destination)` |
| `5` | `EncryptedLeaseSet` | `0x05 \|\| Unsigned` | Outer wrapper (`24..4096B` ciphertext); key = `SHA256(sigType[2, BE] \|\| blindedPubKey[32])` |
| `7` | `MetaLeaseSet` | `0x07 \|\| Unsigned` | Up to 16 `MetaLease` entries (`40B` each) + revocations; key = `SHA256(Destination)` |

#### `LeaseSet2` Multi-Key Selection (`SelectUsableEncryptionKey`)

A `LeaseSet2` advertises one or more `(CryptoKeyType, KeyData)` pairs. When preparing an outbound garlic session, `SelectUsableEncryptionKey(nowMillis, supported...)` checks that the `LeaseSet2` header and at least one `Lease2` are unexpired at `nowMillis`, then picks the highest-priority supported encryption key (`CryptoMLKEM1024X25519` -> `CryptoMLKEM768X25519` -> `CryptoX25519`).

#### Offline Signatures (`OfflineSignature`)

When `LeaseSet2Header.Flags & 0x0001 != 0`, the header includes an `OfflineSignature` block:

```
expiresSeconds[4, BE] || transientSigType[2, BE] || transientPubKey[keyLen] || masterSignature[sigLen]
```

`Verify()` checks two invariants:
1. `Offline.Expires >= Header.Published + Header.Expires` and `Offline.Expires >= lease.EndDate` for every lease in the set.
2. The destination's long-term identity key verifies `masterSignature` over `expiresSeconds[4] || transientSigType[2] || transientPubKey`, and the `transientPubKey` verifies the outer `LeaseSet2` signature over `0x03 || Unsigned`.

---

## 4. I2NP Wire Framing (`foundation/internal/i2np/i2np.go`)

I2NP messages use three header encodings depending on the carrier layer:

```
1. Standard 16-Byte Header (TunnelGateway, Legacy, Standalone):
┌──────────┬───────────────────┬───────────────────────────────────┬───────────────┬──────────┐
│ Type (1B)│ MessageID (4B, BE)│ Expiration Millis (8B, BE)        │ Size (2B, BE) │ Chksum(1B│
│          │                   │                                   │ (<= 62,690 B) │ SHA256[0]│
└──────────┴───────────────────┴───────────────────────────────────┴───────────────┴──────────┘

2. Transport 9-Byte Header (NTCP2 BlockI2NP, SSU2 BlockI2NP, ECIES Garlic Cloves):
┌──────────┬───────────────────┬───────────────────────────┐
│ Type (1B)│ MessageID (4B, BE)│ Expiration Secs (4B, BE)  │
└──────────┴───────────────────┴───────────────────────────┘

3. Legacy 5-Byte Short Header:
┌──────────┬───────────────────────────┐
│ Type (1B)│ Expiration Secs (4B, BE)  │
└──────────┴───────────────────────────┘
```

### Supported I2NP Message Types

| Type ID | Constant | Payload Wire Layout |
| :--- | :--- | :--- |
| `1` | `DatabaseStore` | `key[32] \|\| storeType[1] \|\| replyToken[4] \|\| [if replyToken!=0: replyTunnelID[4] \|\| replyGateway[32]] \|\| [if storeType==0: gzipLen[2] \|\| gzipData, else rawData]` |
| `2` | `DatabaseLookup` | `key[32] \|\| from[32] \|\| flags[1] \|\| [if flags&1: replyTunnelID[4]] \|\| excludedCount[2, <=512] \|\| excluded[count*32] \|\| [if encrypted: replyKey[32] \|\| tagCount[1] \|\| tags]` |
| `3` | `DatabaseSearchReply` | `key[32] \|\| count[1] \|\| peerHashes[count*32] \|\| from[32]` |
| `10` | `DeliveryStatus` | `msgID[4, BE] \|\| timestampMillis[8, BE]` (12 bytes exact) |
| `11` | `Garlic` | `length[4, BE] \|\| encryptedGarlicData[length]` |
| `18` | `TunnelData` | `tunnelID[4, BE, !=0] \|\| encryptedLayerPayload[1024]` (1028 bytes exact) |
| `19` | `TunnelGateway` | `tunnelID[4, BE, !=0] \|\| length[2, BE] \|\| standardI2NPMessage[length]` |
| `20` | `Data` | `length[4, BE] \|\| payload[length]` |
| `21` / `22` | `TunnelBuild` / `Reply` | `8 * 528` bytes (`4224` bytes fixed) |
| `23` / `24` | `VariableTunnelBuild` / `Reply` | `count[1, 1..8] \|\| records[count * 528]` |
| `25` / `26` | `ShortTunnelBuild` / `Reply` | `count[1, 1..8] \|\| records[count * 218]` |
| `231` | `TunnelTest` | `msgID[4, BE] \|\| timestampMillis[8, BE]` (12 bytes exact) |
