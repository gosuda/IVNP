# ivnp-reseed

Autonomous I2P network indexer and SU3 reseed server (`gosuda.org/ivnp/cmd/ivnp-reseed`). `ivnp-reseed` runs an embedded floodfill router, crawls the live I2P DHT with deficit-weighted prefix exploration across all 256 K-buckets, verifies peer reachability via token-bucket TCP probing, selects maximally diverse peer subsets using Max-Min XOR farthest-point sampling, and serves RSA-4096 / SHA-512 signed `.su3` bootstrap archives.

---

## Architecture

```
[I2P Network (netId=2)]
       │ (Passive floodfill stores + active DHT prefix-tree lookups)
       ▼
┌───────────────────────────────────────────────────────────────────┐
│ Embedded Floodfill Router (NTCP2 / SSU2, Tainted-Copy State)      │
│ - HarvestLoop (4s ticker): imports verified RouterInfos           │
│ - Records confirmed tunnel build participation (+15 pt bonus)     │
│ - Deficit-weighted DHT prefix exploration across 256 K-buckets    │
└───────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ Bounded PeerStore (Cap: 5,000 routers, atomic peers.gob snapshot) │
│ - Subnet (/16 IPv4, /48 IPv6) and router family contention bounds │
│ - EWMA RTT, rolling 3h probe window, and composite quality score  │
└───────────────────────────────┬───────────────────────────────────┘
                                │ Prober (8.0 probes/s, burst 16, 1.5s timeout)
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ 4-Stage Diverse Peer Selector (75 peers per SU3 bundle)           │
│ 1. Hard qualification gate (v2 transport, >=85% probe rate,       │
│    >=1h uptime, <24h RouterInfo age) with 4-step relaxation       │
│ 2. Subnet (/16 IPv4, /48 IPv6) and family uniqueness filter       │
│ 3. Max-Min XOR Farthest-Point Sampling (50% floodfill quota first)│
│ 4. 256-bucket stratification for partial bundle readers           │
└───────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│ Epoch Bundle Pool (16 distinct RSA-4096 / SHA-512 SU3 archives)   │
│ - Raw PKCS#1 v1.5 SHA-512 signature (I2P SU3 ContentType 3)       │
│ - Served over HTTP with ETag caching and live HTML dashboard      │
└───────────────────────────────────────────────────────────────────┘
```

### Core Mechanisms

1. **Embedded Floodfill Crawler (`crawler.go`)**: Runs an embedded `node.Subsystem` in floodfill and tainted-copy mode. In addition to active iterative lookups, it passively receives unsolicited `DatabaseStore` publications from the network and rewards peers that accept exploratory or transit tunnel hops (`RecordTunnelUsed`).
2. **Deficit-Weighted Prefix Exploration (`TreeExplore`)**: On every pass, the crawler inspects peer counts across all 256 `Hash[0]` K-buckets:
   - Empty buckets (`0` peers) receive 4-way quadrant subdivision queries (`[0x00, 0x40, 0x80, 0xC0]`).
   - Severely sparse buckets (`< 4` peers) receive 2-way subdivision queries.
   - Moderately sparse (`< 8`) and minor deficit (`< 16`) buckets receive targeted refresh lookups.
3. **Dual Exploration Budget (`DynamicExplorationBudget`)**:
   - **Expansion Mode** (`Reachable < 1024`): Launches `24` concurrent exploration queries per pass and prioritizes newcomer and sparse-bucket probing.
   - **Maintenance Mode** (`Reachable >= 1024`): Launches `8` repair queries per pass and applies exponential probe backoff (`5m * 2^(fails-1)`, capped at `2h`) to unresponsive peers.
4. **Max-Min XOR Farthest-Point Sampling (`selector.go`)**: Rather than drawing fixed counts per prefix, `farthestPointSample` runs greedy farthest-point sampling across the full 256-bit XOR keyspace ($O(K \cdot N)$). Each pick maximizes the minimum XOR distance to all already-selected peers, filling the 50% floodfill quota first and then drawing from the full qualified pool to produce a 75-peer bundle (`bundleSize = 75`).
5. **Hard Qualification Gate & Relaxation Ladder**: Candidates must advertise a dialable NTCP2 or SSU2 address, publish a `RouterInfo` within the client's 24-hour reseed window (`±2m` clock skew), and pass the qualification ladder (`gateStrict`: $\ge 85\%$ probe success and $\ge 1\text{h}$ uptime -> `gateNoUptime` -> `gateCumulativeRate` -> `gateReachable`). If fewer than `-min-bundle-peers` qualify, the server retains the previous epoch's bundle pool.
6. **Sybil & Eclipse Contention Bounds (`store.go`)**: Both `PeerStore` admission and bundle selection enforce at most one router per IPv4 `/16` subnet, IPv6 `/48` prefix, and declared router `family`. A newly admitted peer that outranks an existing group member evicts the dominated entry (`PruneRedundant`).
7. **16-Bundle Epoch Pool (`packager.go`, `server.go`)**: Every refresh interval (`10m` default), `ivnp-reseed` builds a pool of `16` distinct 75-peer SU3 archives (`bundlePoolSize = 16`) and rotates across them on incoming download requests so concurrent bootstrap clients do not hammer identical peer subsets.

---

## HTTP Endpoints

| Method | Endpoint | Content-Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | `text/html; charset=utf-8` | Real-time web dashboard with 256-bucket DHT heatmap and probe telemetry |
| `GET` | `/stats` | `application/json` | Operational telemetry (`DetailedStatsResponse`: RTT percentiles, bucket fill, diversity, signer metadata) |
| `GET` | `/i2pseeds.su3?netid=2` | `application/octet-stream` | Standard I2P SU3 reseed archive (RSA-4096 / SHA-512 signed ZIP of `routerInfo-<hash>.dat` files) |
| `GET` | `/reseed-rsa.crt` | `application/x-x509-ca-cert` | X.509 PEM certificate for SU3 verification (alias: `/reseed.crt`) |
| `GET` | `/reseed-rsa.pub.pem` | `text/plain` | 4096-bit RSA public key in PKIX PEM format (alias: `/reseed.pub`) |
| `GET` | `/health` | `text/plain` | Container liveness probe (returns `OK\n`, HTTP `200`) |

All `/i2pseeds.su3` responses include `Cache-Control: public, max-age=600` and an `ETag` header; conditional requests with a matching `If-None-Match` receive `304 Not Modified`. Certificate and public key endpoints set `Cache-Control: public, max-age=86400`.

---

## SU3 Wire Format (`/i2pseeds.su3`)

- **Container Header**: 40-byte I2P SU3 header (`Magic = "I2Psu3\x00"`, `FileType = 0` [ZIP], `ContentType = 3` [Reseed], `SignatureType = 0x0006` [RSA-SHA512-4096], `SignatureLength = 512`).
- **Signature Calculation**: Raw PKCS#1 v1.5 block-type-1 signature over the 64-byte `SHA-512` digest of `header || version || signerID || zipPayload` without an ASN.1 `DigestInfo` prefix, matching Java I2P (`NONEwithRSA`), `i2pd`, and IVNP.
- **Inner Payload**: Deflate-compressed ZIP archive containing `75` verified `routerInfo-<i2pbase64>.dat` files stratified across `Hash[0]` buckets.

---

## Peer Scoring Model (`store.go`)

Each stored peer is evaluated on a composite quality scale:

$$\text{Score} = S_{\text{probe}} + S_{\text{latency}} + S_{\text{floodfill}} + S_{\text{recency}} + S_{\text{dualstack}} + S_{\text{tunnel}} - P_{\text{fails}}$$

```go
// 1. Bayesian / Laplace-Smoothed Probe Reliability (0 to 40 pts)
smoothedRatio := float64(SuccessProbes+1) / float64(TotalProbes+3)
score += smoothedRatio * 40.0

// 2. Hyperbolic EWMA RTT Score (0 to 25 pts)
if IsReachable && EWMARTT > 0 {
	score += 25.0 / (1.0 + (float64(EWMARTT.Milliseconds()) / 200.0))
}

// 3. Accessible Floodfill Bonus (+25 pts)
if IsFloodfill {
	score += 25.0
}

// 4. RouterInfo Publication Recency (0 to 10 pts, linear decay over 24h)
if hoursOld < 24.0 {
	score += (1.0 - (hoursOld / 24.0)) * 10.0
}

// 5. Dual-Stack IPv4 + IPv6 Reachability (+5 pts)
if len(IPv4) > 0 && len(IPv6) > 0 {
	score += 5.0
}

// 6. Confirmed Tunnel Build Participation (+15 pts)
if TunnelBuildAccepted {
	score += 15.0
}

// 7. Consecutive Timeout Penalty (-15 pts per consecutive failure)
score -= float64(ConsecutiveFails) * 15.0
```

---

## CLI Reference

```
Usage of ivnp-reseed:
  -listen string
        HTTP reseed server listen address(es), comma-separated (default ":8080")
  -data-dir string
        Base persistent data directory (default "/data")
  -temp-dir string
        Temporary directory for tainted copy state (default os.TempDir())
  -peers-file string
        Path to peer cache file (default "<data-dir>/peers.gob")
  -target int
        Target number of diverse reachable peers in store (default 1024)
  -min-bundle-peers int
        Minimum qualified peers required to publish a new SU3 bundle pool (default 10)
  -min-probe-rate float
        Minimum rolling probe success rate for strict qualification (default 0.85)
  -interval duration
        Refresh interval for harvesting, probing, and packaging (default 10m0s)
  -netid uint
        I2P network ID (default 2)
  -signer-id string
        SU3 signer common name (default "reseed@ivnp.network", env RESEED_SIGNER_ID)
  -seed-phrase string
        Deterministic RSA-4096 signing key seed phrase (env RESEED_SEED_PHRASE preferred)
  -router-port int
        Port for embedded router NTCP2/SSU2 transports (default 0 for random/ephemeral)
  -router-advertise-host string
        Public host or IP advertised in the embedded router's RouterInfo so remote
        routers can establish inbound connections (env RESEED_ROUTER_ADVERTISE_HOST).
        Requires -router-port.
  -router-advertise-port int
        Public port advertised when NAT port forwarding maps an external port to a
        different internal -router-port (default: same as -router-port)
  -no-router
        Disable embedded router (offline replay/test mode)
  -pprof string
        Optional localhost address for net/http/pprof profiling
  -healthcheck string
        Query health endpoint URL and exit 0 (healthy) or 1 (unhealthy)
  -once
        Run a single harvesting and packaging pass and exit
  -version
        Print version and exit
```

---

## Deterministic Signing Key & State Persistence

| Environment Variable | CLI Flag | Purpose |
| :--- | :--- | :--- |
| `RESEED_SIGNER_ID` | `-signer-id` | SU3 signer Common Name (for example, `reseed@ivnp.network`) |
| `RESEED_SEED_PHRASE` | `-seed-phrase` | Seed phrase used to derive the RSA-4096 signing key deterministically via `HKDF-SHA512` (`"ivnp-reseed"`, `"reseed-rsa-4096"`) and `filippo.io/keygen.RSA(4096, secret)`. Pass via environment variable so the phrase does not appear in process argument tables. |

When `RESEED_SEED_PHRASE` is set, `ivnp-reseed` reproduces the exact same RSA-4096 private key and X.509 certificate in memory on every restart; no private key file is ever written to disk. If no seed phrase is provided, `ivnp-reseed` generates an ephemeral keypair at startup.

Persistent artifacts in `-data-dir` (`peers.gob`, `i2pseeds.su3`, `reseed-rsa.crt`, `reseed-rsa.pub.pem`) are written through an atomic `.tmp` write-and-rename sequence, and any stale `.tmp` files are cleaned up on startup.

> [!WARNING]
> **Back Up `RESEED_SEED_PHRASE` Securely**:
> Downstream routers (Java I2P, `i2pd`, and IVNP) authenticate reseed bundles by pinning the signer's X.509 certificate. Losing or omitting `RESEED_SEED_PHRASE` causes `ivnp-reseed` to generate a new keypair on restart, which will cause clients pinning your previous certificate to reject new `.su3` downloads.

---

## Deployment

### Standalone Binary

```bash
go build -trimpath -o /usr/local/bin/ivnp-reseed ./cmd/ivnp-reseed

# Run behind NAT with port forwarding configured on port 39898:
RESEED_SIGNER_ID="reseed@example.org" \
RESEED_SEED_PHRASE="your secret recovery phrase here" \
  ivnp-reseed -listen ":8080,:8443" -data-dir /var/lib/ivnp-reseed \
  -router-port 39898 -router-advertise-host reseed.example.org
```

### Docker (Distroless)

```bash
docker build -f cmd/ivnp-reseed/Dockerfile -t ivnp-reseed .

docker run -d \
  --name ivnp-reseed \
  --restart unless-stopped \
  -p 8080:8080 \
  -v ivnp_reseed_data:/data \
  -e RESEED_SIGNER_ID="reseed@ivnp.network" \
  -e RESEED_SEED_PHRASE="twelve word seed phrase goes here ..." \
  ivnp-reseed
```

### Installing the Signer Certificate on Clients

Download the public certificate from `/reseed-rsa.crt` and place it into the client router's reseed certificate store using the filename `<signer_id_with_at_replaced_by_at_>` (for example, `reseed_at_ivnp.network.crt`):

- **Java I2P (`i2p.i2p`)**: `~/.i2p/certificates/reseed/` or `/var/lib/i2p/i2p-config/certificates/reseed/`
- **i2pd (`C++`)**: `~/.i2pd/certificates/reseed/` or `/var/lib/i2pd/certificates/reseed/`
- **IVNP**: `controlplane/internal/reseed/certs/`
