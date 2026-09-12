# ivnp-reseed

Autonomous I2P network indexer and reseed server. Actively crawls the live I2P DHT with targeted prefix tree exploration across 256 K-Buckets, continuously verifies router reachability via rate-limited out-of-band probing, and publishes signed bootstrap packages in standard I2P SU3 format.

---

## Architecture

```
[I2P Network]
      │ (DHT lookups / active tree exploration)
      ▼
┌─────────────────────────────────────────────────────────────┐
│ Embedded Router in Floodfill Mode (SSU2/NTCP2)             │
│ - NetDB Replication & Lookups (Passive & Active Crawling)   │
│ - Tuned Exploratory Tunnels (Pool Cap 32, Pending Cap 128)  │
│ - Deficit-Weighted DHT Tree Exploration (256 K-Buckets)     │
└─────────────────────────────┬───────────────────────────────┘
                              │ ActiveCrawler.HarvestRefs() & Tunnel Hops
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Bounded PeerStore (Cap: 5,000 routers, diversity protection)│
│ - EWMA RTT & confirmed tunnel build acceptance tracking     │
│ - JSON persistence: reseed-peers.json                       │
│ - Real-time 256 K-Bucket deficit & reachability tracking    │
└─────────────────────────────┬───────────────────────────────┘
                              │ Prober.ProbeAll() (Deficit-prioritized, 48 workers)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Stratified K-Bucket Selector (Strict 4-Round Leveling)      │
│ - Accessible Floodfill Quota (≥ 35%)                        │
│ - IPv4 /16 Subnet & Router Family Anti-Sybil Constraints    │
│ - Strict Cap (max 5 peers/bucket) to prevent slot hoarding  │
│ - 100% Directly Reachable Guarantee (when reachable > 256)  │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
                     [BuildSU3 Archive]
                    (RSA-4096 / SHA-512)
                              │
                              ▼
            ┌─────────────────────────────────────┐
            │ HTTP Reseed Server & Web Dashboard  │
            │ (Ports 8080 & 8443, 5m refresh cycle│
            └─────────────────────────────────────┘
```

### Core Invariants

1. **Embedded Floodfill Router**: Runs as a full floodfill router (`cfg.Router.Floodfill = true`) by default. In addition to active queries, it passively accepts and stores unsolicited NetDB `DatabaseStoreMessage` publications from the network, maximizing visibility.
2. **Deficit-Weighted DHT Prefix Exploration**: The crawler analyzes the 256-bucket distribution in the peer store every pass. Buckets with severe deficits receive prioritized 4-way quadrant exploration queries (`[0x00, 0x40, 0x80, 0xC0]`) down the DHT prefix tree to discover nodes in unrepresented keyspace prefixes.
3. **Dual Exploration Budget Allocation**:
   - *Expansion Mode* (Reachable < 1024): Deep exploration (48 queries per pass), rapid 60s probe retry for failed peers, newcomer and sparse-bucket probing priority.
   - *Maintenance Mode* (Reachable $\ge$ 1024): Conservative repair (12 queries for sparse buckets), 3m RTT refresh on active nodes, backoff on failing nodes.
4. **256 K-Bucket Slot Imbalance Resolution**: Prevents node hoarding (e.g. 15 nodes in one bucket while others have 0 or 1):
   - Prober prioritizes candidates from sparse buckets (< 4 reachable peers).
   - PeerStore eviction protects sparse buckets (only evicts from buckets with > 4 peers).
   - Selector enforces strict 4-round bucket leveling ($256 \times 4 = 1024$) with a hard overflow cap of 5 peers per bucket.
5. **Directly Reachable Package Guarantee**: When verified reachable peers exceed 256, the reseed package strictly contains only directly reachable peers (no dead/unverified node padding). If $\le 256$ (cold-start), candidate peers are admitted up to target to ensure initial network bootstrap.
6. **Sybil & Eclipse Mitigation**: Peer selection enforces a hard limit of 1 router per IPv4 `/16` subnet and 1 router per declared `family`.
7. **Confirmed Tunnel Build Acceptance**: Actively monitors tunnel hops from exploratory/transit circuits and rewards verified routers with a composite score bonus (+15 pts).

---

## HTTP Endpoints

| Method | Endpoint | Content-Type | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | `text/html; charset=utf-8` | Standalone real-time dark-mode Web Dashboard with live DHT heatmap |
| `GET` | `/stats` | `application/json` | Operational metrics (RTT percentiles, K-bucket distribution, diversity, signer info) |
| `GET` | `/i2pseeds.su3?netid=2` | `application/octet-stream` | Standard I2P SU3 archive (RSA-4096 / SHA-512 signed ZIP) |
| `GET` | `/reseed-rsa.crt` | `application/x-x509-ca-cert` | X.509 Certificate in PEM format for SU3 verification (alias: `/reseed.crt`) |
| `GET` | `/reseed-rsa.pub.pem`| `text/plain` | 4096-bit RSA Public Key in PKIX PEM format (alias: `/reseed.pub`) |
| `GET` | `/health` | `text/plain` | Container liveness check (returns `OK\n`, HTTP 200) |

All reseed downloads return `Cache-Control: public, max-age=300` and an `ETag` matching the archive hash. Conditional requests with `If-None-Match` receive `304 Not Modified`. Certificate and public key endpoints return `Cache-Control: public, max-age=86400`.

---

## Wire Formats

### I2P Standard SU3 (`/i2pseeds.su3`)
- **Outer Container**: SU3 specification (Magic `I2Psu3\0`, ContentType `3` [Reseed], FileType `0` [ZIP]).
- **Signature**: RSA-4096 with SHA-512 digest (PKCS#1 v1.5 padding).
- **Payload**: Deflate-compressed ZIP containing individual `routerInfo-<hash>.dat` files.
- **Client Compatibility**: Java I2P (`i2p.i2p`) and C++ `i2pd`.

---

## Peer Scoring Model

Peers are evaluated on a 120-point composite scale:

$$\text{Score} = S_{\text{uptime}} + S_{\text{latency}} + S_{\text{floodfill}} + S_{\text{recency}} + S_{\text{dualstack}} + S_{\text{tunnel}} - P_{\text{fails}}$$

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

// 6. Confirmed Tunnel Build Acceptance (+15 pts)
if TunnelBuildAccepted {
    score += 15.0
}

// 7. Consecutive Failure Penalty (-15 pts per consecutive timeout)
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
        Path to peer cache file (default "<data-dir>/reseed-peers.json")
  -target int
        Target number of diverse peers in reseed archive (default 1024)
  -interval duration
        Refresh interval for harvesting, probing, and packaging (default 5m0s)
  -netid uint
        I2P network ID (default 2)
  -signer-id string
        SU3 signer common name (default "reseed@ivnp.network")
  -router-port int
        Port for embedded router NTCP2/SSU2 transports (default 0 for random/ephemeral)
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

---

## Key Management & Backup Guide

`ivnp-reseed` signs all bootstrap SU3 packages using an RSA 4096-bit private key and SHA-512.

### Key Files

Within `-data-dir` (default `/data`):

| File | Type | Permissions | Description |
| :--- | :--- | :--- | :--- |
| `reseed-rsa.key` | PKCS#1 RSA Private Key | `0600` | **CRITICAL & CONFIDENTIAL**: Private key used to sign SU3 archives. |
| `reseed-rsa.crt` | X.509 Certificate | `0644` | Public certificate (Subject CN = `-signer-id`, 10-year validity). |
| `reseed-rsa.pub.pem` | PKIX RSA Public Key | `0644` | Standard PEM-encoded RSA 4096-bit public key. |

> [!WARNING]
> **Why Backing Up `reseed-rsa.key` is Mandatory:**
> Client routers (Java I2P, i2pd, IVNP) trust a reseed service by pinning its X.509 certificate. If `reseed-rsa.key` is lost (e.g. recreating a Docker container without a persistent volume or host storage failure), `ivnp-reseed` will automatically generate a **new** keypair on startup. As a result, all existing downstream routers will reject the newly signed SU3 packages with `SU3 signature verification failed`.
>
> Always back up `reseed-rsa.key` securely offsite!

### Backing Up the Private Key

#### From Docker (Running Container / Volume)

1. **Direct copy from a running container:**
   ```bash
   # Copy private key and public certificate to current directory
   docker cp ivnp-reseed:/data/reseed-rsa.key ./reseed-rsa.key.backup
   docker cp ivnp-reseed:/data/reseed-rsa.crt ./reseed-rsa.crt.backup

   # Protect backup permissions immediately
   chmod 600 ./reseed-rsa.key.backup
   ```

2. **Archive directly from Docker named volume (recommended for automated cron backups):**
   ```bash
   docker run --rm \
     -v ivnp_reseed_data:/data:ro \
     -v $(pwd):/backup \
     alpine tar czf /backup/ivnp-reseed-keys-$(date +%Y%m%d).tar.gz -C /data reseed-rsa.key reseed-rsa.crt

   chmod 600 ivnp-reseed-keys-*.tar.gz
   ```

#### From Bare-Metal / Standalone Host

```bash
# If using default host directory /var/lib/ivnp-reseed
sudo cp /var/lib/ivnp-reseed/reseed-rsa.key /secure/backup/reseed-rsa.key.backup
sudo cp /var/lib/ivnp-reseed/reseed-rsa.crt /secure/backup/reseed-rsa.crt.backup
sudo chmod 600 /secure/backup/reseed-rsa.key.backup
```

### Restoring the Private Key

#### Into a New Docker Container / Volume

```bash
# 1. Create the Docker volume if not existing
docker volume create ivnp_reseed_data

# 2. Copy the backed up private key into the volume with nonroot ownership (UID 65532)
docker run --rm \
  -v ivnp_reseed_data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cp /backup/reseed-rsa.key.backup /data/reseed-rsa.key && chown 65532:65532 /data/reseed-rsa.key && chmod 600 /data/reseed-rsa.key"

# 3. Launch the container - it will detect the existing key and reuse it
docker run -d \
  --name ivnp-reseed \
  --restart unless-stopped \
  -p 8080:8080 \
  -v ivnp_reseed_data:/data \
  ivnp-reseed
```

#### Into Bare-Metal / Standalone Host

```bash
sudo mkdir -p /var/lib/ivnp-reseed
sudo cp /secure/backup/reseed-rsa.key.backup /var/lib/ivnp-reseed/reseed-rsa.key
sudo chmod 600 /var/lib/ivnp-reseed/reseed-rsa.key
sudo chown $(whoami):$(whoami) /var/lib/ivnp-reseed/reseed-rsa.key
```

### Pre-generating Custom Keys with OpenSSL (Optional)

If you prefer to generate your 4096-bit RSA signing key and self-signed certificate in advance before starting `ivnp-reseed`:

```bash
# 1. Generate 4096-bit RSA private key
openssl genrsa -out reseed-rsa.key 4096
chmod 600 reseed-rsa.key

# 2. Generate self-signed certificate matching your signer ID (10 years)
openssl req -new -x509 -key reseed-rsa.key -out reseed-rsa.crt -days 3650 \
  -subj "/CN=reseed@ivnp.network/O=I2P Anonymous Network"

# 3. Place both files in your -data-dir (/data)
```

### Installing the Reseed Certificate on Downstream Routers

Users or administrators can download your `.crt` directly from the Web Dashboard (Download `.crt` button) or via `https://reseed.example.org/reseed-rsa.crt`.

- **Java I2P (`i2p.i2p`)**:
  Place the `.crt` file into the reseed certificate directory:
  - Linux (user): `~/.i2p/certificates/reseed/`
  - Linux (service): `/var/lib/i2p/i2p-config/certificates/reseed/`
  - Windows: `%APPDATA%\I2P\certificates\reseed\`
  - Filename format: `<signer_id_with_underscores>.crt` (e.g. `reseed_at_ivnp.network.crt`).
- **i2pd (`C++`)**:
  Place into `/var/lib/i2pd/certificates/reseed/` or `~/.i2pd/certificates/reseed/`.
- **IVNP**:
  Place into `controlplane/internal/reseed/certs/` or router reseed certificate directory.

