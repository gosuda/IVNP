# ivnp-reseed

Autonomous I2P network indexer and reseed server. Actively crawls the live I2P DHT, continuously verifies router reachability via rate-limited out-of-band probing, stratifies peers across 256 K-Buckets, and publishes signed bootstrap packages in both I2P SU3 and IVNP binary stream formats.

---

## Architecture

```
[I2P Network]
      │ (DHT lookups / exploration)
      ▼
┌─────────────────────────────────────────────────────────────┐
│ Embedded Client Router (Port 0, Unadvertised, SSU2)         │
│ - NetDB Table (In-Memory Routing Info)                      │
│ - Tuned Exploratory Tunnels (6 In / 6 Out, Pool Cap 16)     │
└─────────────────────────────┬───────────────────────────────┘
                              │ ActiveCrawler.Harvest()
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Bounded PeerStore (Cap: 5,000 routers, worst-score eviction)│
│ - EWMA RTT tracking & reachability states                   │
│ - JSON persistence: reseed-peers.json                       │
└─────────────────────────────┬───────────────────────────────┘
                              │ Prober.ProbeAll() (15 probes/sec)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Stratified K-Bucket Selector (256 DHT Buckets)              │
│ - Accessible Floodfill Quota (≥ 35%)                        │
│ - IPv4 /24 Subnet & Router Family Anti-Sybil Constraints    │
│ - Bayesian Uptime & Non-Linear Latency Scoring              │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
      [BuildSU3 Archive]             [BuildIVBS Binary]
    (RSA-4096 / SHA-512)            (Ed25519 / Zero-Alloc)
               │                              │
               └──────────────┬───────────────┘
                              ▼
           ┌─────────────────────────────────────┐
           │ HTTP Reseed Server & Web Dashboard │
           │ (Ports 8080 & 8443, 5m refresh cycle│
           └─────────────────────────────────────┘
```

### Core Invariants

1. **Active Outbound Crawling**: An embedded IVNP router binds to ephemeral UDP port `0` without advertised endpoints or NAT-PMP/UPnP port forwarding. Because the node cannot accept unsolicited incoming connections, any router that successfully handshakes with this instance is mathematically guaranteed to be publicly reachable (*Accessible*).
2. **DDoS Protection & Probe Cooldown**: Outbound reachability checks are throttled by a token bucket rate limiter at `15.0 queries/sec` with a 10-minute per-peer cooldown (`ProbeCooldownInterval`). Probing uses non-disruptive TCP/UDP transport handshakes with a 1.5-second hard timeout.
3. **Sybil & Eclipse Mitigation**: Peer selection enforces a hard limit of 1 router per IPv4 `/24` subnet and 1 router per declared `family`, distributed uniformly across all 256 K-Buckets.
4. **Memory Bound**: The in-memory peer store caps storage at 5,000 entries. When saturated, lowest-scoring peers are evicted via min-heap/linear scan before accepting newcomers.

---

## HTTP Endpoints

| Method | Endpoint | Content-Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | `text/html; charset=utf-8` | Standalone real-time dark-mode Web Dashboard with live DHT heatmap |
| `GET` | `/stats` | `application/json` | Operational metrics (RTT percentiles, K-bucket distribution, diversity) |
| `GET` | `/i2pseeds.su3?netid=2` | `application/octet-stream` | Standard I2P SU3 archive (RSA-4096 / SHA-512 signed ZIP) |
| `GET` | `/ivnpseeds.bin?netid=2` | `application/octet-stream` | High-speed IVNP zero-allocation binary stream (Ed25519 signed) |
| `GET` | `/health` | `text/plain` | Container liveness check (returns `OK\n`, HTTP 200) |

All reseed downloads return `Cache-Control: public, max-age=300` and an `ETag` matching the archive hash. Conditional requests with `If-None-Match` receive `304 Not Modified`.

---

## Wire Formats

### 1. I2P Standard SU3 (`/i2pseeds.su3`)
- **Outer Container**: SU3 specification (Magic `I2Psu3\0`, ContentType `3` [Reseed], FileType `0` [ZIP]).
- **Signature**: RSA-4096 with SHA-512 digest (PKCS#1 v1.5 padding).
- **Payload**: Deflate-compressed ZIP containing individual `routerInfo-<hash>.dat` files.
- **Client Compatibility**: Java I2P (`i2p.i2p`) and C++ `i2pd`.

### 2. IVNP Binary Seed (`/ivnpseeds.bin`)
Designed for sub-millisecond memory-mapped parsing with zero heap allocations.

```
+---------------+---------------+---------------+---------------+
| Magic "IVBS"  |  Version (2B) |  NetID (1B)   |   Flags (1B)  |
+---------------+---------------+---------------+---------------+
|                   Timestamp Unix-Milli (8B)                   |
+---------------+---------------+---------------+---------------+
|   Count (2B)  | Length 0 (2B) | Raw RouterInfo 0 Bytes...     |
+---------------+---------------+---------------+---------------+
| Length 1 (2B) | Raw RouterInfo 1 Bytes...                     |
+---------------+---------------+---------------+---------------+
| ...                                                           |
+---------------------------------------------------------------+
|                   Ed25519 Signature (64B)                     |
+---------------------------------------------------------------+
```

---

## Peer Scoring Model

Peers are evaluated on a 105-point composite scale:

$$\text{Score} = S_{\text{uptime}} + S_{\text{latency}} + S_{\text{floodfill}} + S_{\text{recency}} + S_{\text{dualstack}} - P_{\text{fails}}$$

```go
// 1. Bayesian / Laplace Smoothed Uptime (0 ~ 40 pts)
smoothedRatio := float64(SuccessProbes + 1) / float64(TotalProbes + 2)
score += smoothedRatio * 40.0

// 2. Hyperbolic RTT Decay (0 ~ 25 pts)
// Preserves discrimination across cross-continental peers (>300ms)
if IsReachable && EWMARTT > 0 {
    score += 25.0 / (1.0 + (float64(EWMARTT.Milliseconds()) / 200.0))
}

// 3. Accessible Floodfill Bonus (+25 pts)
if IsFloodfill {
    score += 25.0
}

// 4. RouterInfo Recency Bonus (0 ~ 10 pts)
// Linear decay over 24 hours based on RouterInfo.Published
if hoursOld < 24.0 {
    score += (1.0 - (hoursOld / 24.0)) * 10.0
}

// 5. Dual-Stack Reachability (+5 pts)
if len(IPv4) > 0 && len(IPv6) > 0 {
    score += 5.0
}

// 6. Consecutive Failure Penalty (-15 pts per consecutive timeout)
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
  -peers-file string
        Path to peer cache file (default "<data-dir>/reseed-peers.json")
  -target int
        Target number of diverse peers in reseed archive (default 1000)
  -interval duration
        Refresh interval for harvesting, probing, and packaging (default 5m0s)
  -netid uint
        I2P network ID (default 2)
  -signer-id string
        SU3 signer common name (default "reseed@ivnp.network")
  -no-router
        Disable embedded router (test/replay mode)
  -healthcheck string
        Query health endpoint URL and exit 0 (healthy) or 1 (unhealthy)
  -once
        Run a single harvesting/packaging pass and exit
  -version
        Show version and exit
```

---

## Deployment

### Standalone Binary

```bash
# Build
go build -trimpath -o /usr/local/bin/ivnp-reseed ./cmd/ivnp-reseed

# Run with dual-port binding (HTTP 8080 for proxy, 8443 for direct)
ivnp-reseed -listen ":8080,:8443" -data-dir /var/lib/ivnp-reseed
```

### Docker (Distroless)

Build and run using the hardened distroless image (`gcr.io/distroless/static-debian12:nonroot`, UID 65532):

```bash
# Build image from git repository root
docker build -f cmd/ivnp-reseed/Dockerfile -t ivnp-reseed .

# Run container with persistent storage
docker run -d \
  --name ivnp-reseed \
  --restart unless-stopped \
  -p 8080:8080 \
  -v ivnp_reseed_data:/data \
  ivnp-reseed
```

### Nginx Reverse Proxy Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name reseed.example.org;

    ssl_certificate     /etc/letsencrypt/live/reseed.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/reseed.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
