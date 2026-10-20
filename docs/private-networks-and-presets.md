# Private Networks, Presets & Parameter Tuning Guide

IVNP treats every overlay network as an explicit protocol context identified by a 1-byte `netId` (`1..255`). The public I2P network (`netId = 2`) and a private mesh (`netId = 42` or `netId = 88`) execute the exact same NTCP2, SSU2, I2NP, ECIES-X25519-AEAD-Ratchet, I2P Streaming, and Datagram2 state machines. They differ only in their baseline operating profile (`public`, `dedicated`, or `direct`), bootstrap trust anchors, and peer admission policies.

This guide explains why public anonymity defaults stall small or single-subnet deployments, how the three built-in presets configure every underlying parameter, which preset fits real-world workloads (such as a local clipboard-sync sidecar or a multi-site service mesh), and how to override individual raw parameters in Go or `ivnp.conf`.

---

## 1. Why Public I2P Defaults Stall Small and Local Networks

The `public` profile (`netId = 2`) is calibrated for an untrusted global overlay containing tens of thousands of routers across thousands of autonomous systems. Its eclipse-resistance and anonymity invariants intentionally reject the topology of a 2-to-20 node private mesh or an office LAN:

```
Public I2P Assumptions (netId = 2)             Private / LAN Mesh Reality
────────────────────────────────────────────   ────────────────────────────────────────────
• Thousands of distinct /16 IPv4 prefixes      • All nodes share 192.168.1.0/24 or 10.0.0.0/16
• 50+ routers required before WaitReady()      • 2 to 10 nodes total (e.g., laptop + desktop + NAS)
• 3-hop tunnels with strict /16 hop diversity  • 1-hop or 2-hop tunnels across identical subnets
• 4 to 5 independent floodfills confirm stores • Every node acts as floodfill; K = 1 or K = 2
• Public SU3 reseed servers & .i2p outproxies  • Offline / air-gapped or private peer seeds
```

Running a small private network with unadjusted `public` settings triggers five deterministic failure modes:

1. **Kademlia K-Bucket `/16` Subnet Quota Rejection (`BucketSubnetQuota = 2`)**:
   In `controlplane/internal/netdb`, each Kademlia bucket and the SU3 reseed ingestion filter (`Reseed.BucketSubnetQuota = 2`) admit at most 2 routers sharing the same IPv4 `/16` or IPv6 `/32` prefix. On a home Wi-Fi network (`192.168.1.0/24`), a corporate VLAN (`10.20.0.0/16`), or a cloud VPC (`172.16.0.0/16`), every host shares one `/16` prefix. The 3rd node is silently dropped from the routing table.
2. **Tunnel Hop IP Diversity Exhaustion (`IPRestriction = 2`)**:
   The tunnel participant selector (`controlplane/internal/tunnel/selector.go`) enforces two constraints by default: no two hops in a tunnel may share an IPv4 `/16` (or IPv6 `/32`) subnet, and no router hash may appear twice in the same tunnel. Building a 3-hop tunnel requires 3 distinct remote routers on 3 distinct `/16` subnets. A 2-node mesh or a single-subnet LAN has zero valid candidate paths and fails every tunnel build.
3. **Two-Node 1-Hop Self-Relay Deadlock (`OBEP == IBGW`)**:
   In a 2-node mesh (`Node A` and `Node B`), `Node A`'s 1-hop outbound tunnel uses `Node B` as its Outbound Endpoint (`OBEP = B`), while `Node B`'s 1-hop inbound tunnel uses `Node A` as its Inbound Gateway (`IBGW = A`). When `Node A` sends a message to `Node B`'s destination, `Node B` (acting as `OBEP`) must forward the `TunnelGateway` frame to `Node A` (acting as `IBGW`), which then encrypts and delivers the 1024-byte `TunnelData` frame back to `Node B` (the Inbound Endpoint, `IBEP`). Similarly, when `Node A` builds a 1-hop outbound tunnel through `Node B`, `Node B` must send the build reply back to `Node A`'s inbound gateway (`Node B` itself) without attempting to dial a transport session to its own router hash (`controlplane/internal/runtime/controller_transport.go`).
4. **Unreachable Readiness and Floodfill Confirmation Quorums**:
   Under `public` defaults, `NetDB.MinRouters = 50` blocks `Router.WaitReady` until 50 peers are known, and `LeaseSetFloodfillK = 4` requires 4 independent floodfill `DeliveryStatus` confirmations before `Router.NewDestination` returns. A 2-node or 3-node cluster waits until its context deadline expires.
5. **External Clearnet & Public Overlay Contamination**:
   Public defaults enable clearnet SU3 reseed fetching from `reseed.i2p-projekt.de` (hardcoded to `netId = 2`), `.i2p` hosts.txt subscriptions (`reg.i2p`, `stats.i2p`), and public HTTP outproxies (`exit.stormycloud.i2p`). On an isolated network, these background tasks generate continuous DNS/HTTPS failures or reject archives due to `netId` mismatches.

---

## 2. Choosing a Preset: Realistic Deployment Scenarios

IVNP provides three profiles (`NetworkProfilePublic`, `NetworkProfileDedicated`, and `NetworkProfileDirect`) paired with matching network and destination constructors in `gosuda.org/ivnp`:

| Decision Axis | `direct` (`NetworkProfileDirect`) | `dedicated` (`NetworkProfileDedicated`) | `public` (`NetworkProfilePublic`) |
| :--- | :--- | :--- | :--- |
| **Target Scale** | `2` to `30` nodes (often on one LAN/VPC or personal device group) | `3` to `200+` nodes across multiple subnets, sites, or cloud regions | Global public I2P network (`netId = 2`) or large untrusted overlays (`200+` nodes) |
| **Trust & Threat Model** | Trusted devices or ACL-gated peers (`AdmitPeers`); link encryption & authentication prioritized over hop anonymity | Semi-trusted or federated nodes; preserves subnet eclipse quotas (`16` per `/16`) and multi-floodfill quorum (`K = 2`) | Untrusted global peers; strict `/16` quotas (`2`), 3-hop client tunnels, and `K = 4..5` floodfill quorum |
| **Same-Subnet (`/16` / `/24`) Compatibility** | **Native**: `/16` bucket quotas and hop IP restrictions are disabled (`0`) | **Up to 16 peers per `/16`** in NetDB; tunnel hops require distinct `/16` unless `WithIPRestriction(0)` is set | **Max 2 peers per `/16`** per K-bucket; every tunnel hop must reside in a distinct `/16` |
| **Minimum Viable Cluster** | **2 nodes** (`MinRouters = 1`, `FloodfillK = 1`) | **3 nodes** (`MinRouters = 2`, `FloodfillK = 2`) | **50+ nodes** (`MinRouters = 50`, `FloodfillK = 4..5`) |
| **Failure Detection Speed** | **Fast** (`3s` maintenance, `5s` probe timeout, `2` failures) | **Moderate** (`5s` maintenance, `10s` probe timeout, `2` failures) | **Conservative** (`60s` maintenance, `60s` probe timeout, `2` failures) |
| **Network Constructor** | `ivnp.NewDirectNetwork(name, netID, opts...)` | `ivnp.NewDedicatedNetwork(name, netID, opts...)` | `ivnp.NewNetwork(name, netID, opts...)` / `ivnp.DefaultI2PNetwork()` |
| **Destination Constructor** | `ivnp.DirectDestinationConfig()` | `ivnp.DedicatedDestinationConfig()` | `ivnp.DefaultDestinationConfig()` |

### Scenario A: Clipboard & File-Sync Sidecar Across Personal Devices (`direct`)

Suppose you are building a cross-platform desktop sidecar that synchronizes clipboard buffers, screenshots, and local terminal sessions between a developer's MacBook, a Linux workstation, and a home Mini-PC:

- **Topology realities**: Often only 2 devices are awake at the same time. At home or in the office, both devices sit on the same `192.168.1.0/24` Wi-Fi network. When the laptop lid opens, clipboard sync must resume within a few seconds rather than waiting minutes for stale tunnel expiry.
- **Why `direct` fits**:
  - `MinRouters = 1` and `LeaseSetFloodfillK = 1` allow a 2-device mesh (`MacBook` + `Workstation`) to reach `WaitReady` and confirm `LeaseSet2` publication with zero external infrastructure.
  - `DisableBucketSubnetQuota = true` and `DisableIPRestriction = true` allow all devices to share `192.168.1.0/24` or `127.0.0.1` (during local multi-instance development).
  - `DirectDestinationConfig()` builds `1-hop` client tunnels with `Count = 1` active tunnel and `Backup = 1` hot standby per direction, minimizing background packet chatter on battery-powered laptops while keeping failover instant.
  - `MaintenanceInterval = 3s` and `ProbeTimeout = 5s` detect dead tunnels after Wi-Fi roaming or sleep/wake within `6 to 10 seconds`.

### Scenario B: Office LAN Microservices & Air-Gapped Lab Clusters (`direct`)

Suppose an engineering team runs internal gRPC services, build artifact caches, or telemetry collectors across 10 machines on an isolated `10.10.0.0/16` corporate subnet:

- **Topology realities**: Every machine has a `10.10.x.y` address (a single `/16` prefix). Outbound internet access is blocked at the firewall. Services address each other by cryptographic `.b32.i2p` identities so credentials and endpoints remain portable across DHCP leases or container IP changes.
- **Why `direct` fits**:
  - Public reseed, outproxies, and `.i2p` addressbook polling are disabled automatically (`Reseed.Enabled = false`, `Outproxies = []`, `Subscriptions = nil`), preventing air-gapped log noise and outbound connection attempts.
  - Every node enables `Floodfill = true` and `Transit = true` (`ParticipationContributor`), forming a flat, self-healing DHT across the LAN without dedicated infrastructure servers.
  - Pairing `NewDirectNetwork` with `WithPeerAdmission(AdmitPeers(allowedHashes...))` rejects any unapproved host on the office VLAN immediately after cryptographic `RouterInfo` verification during the NTCP2/SSU2 handshake.

### Scenario C: Multi-Site Dedicated Overlay & Federated Infrastructure (`dedicated`)

Suppose an organization operates a private overlay (`netId = 42`) connecting 12 routers distributed across 4 cloud regions (`us-east`, `eu-central`, `ap-northeast`, and an on-premise data center) with a private `ivnp-reseed` server:

- **Topology realities**: Nodes span multiple public `/16` networks, though a single region may host 4 to 8 nodes in the same subnet. The operator wants resilience against single-node floodfill failure (`K = 2`) and wants tunnel hops placed across distinct `/16` regions when possible.
- **Why `dedicated` fits**:
  - `BucketSubnetQuota = 16` (up from `2` in `public`) lets up to 16 regional nodes share a `/16` per K-bucket while still bounding subnet floods.
  - `MinRouters = 2`, `RouterInfoFloodfillK = 2`, and `LeaseSetFloodfillK = 2` require at least two peers to confirm publications, preventing a single restarting node from blackholing `LeaseSet2` lookups.
  - `DedicatedDestinationConfig()` maintains `2` active 1-hop tunnels per direction (`Inbound.Count = 2`, `Outbound.Count = 2`) for higher aggregate bandwidth and multi-path distribution.
  - If all nodes in a test environment happen to share one `/16` cloud VPC, add `ivnp.WithIPRestriction(0)` to relax tunnel hop subnet separation while keeping all other `dedicated` parameters intact.

### Scenario D: Dual-Homed Hybrid Overlay (`direct` + `public` with Happy Eyeballs)

Suppose a desktop collaboration app or P2P git remote helper wants LAN-speed transfers when two teammates are on their private `direct` mesh (`netId = 88`), but also wants reachability over the public I2P network (`netId = 2`) when one teammate is traveling without direct UDP/TCP reachability:

- **How IVNP handles this**:
  - Configure `RouterConfig.SetNetworks(directNet, publicNet)` with `DefaultNetwork: "lan"`.
  - Bind a single `Destination` to `Networks: []string{"lan", "i2p"}`. Both networks share the exact same `.b32.i2p` address.
  - When dialing with `"i2p"` or `"stream"`, `Destination.DialContext` runs `DialHappyEyeballs`: it dials `"lan"` (`direct`) at `t = 0ms` and staggers `"i2p"` (`public`) by `250ms`. If the local mesh connects first, the public dial is canceled immediately.

---

## 3. Complete Raw Parameter Matrix

The table below lists every parameter affected by `NetworkProfile` (`state/internal/configuration/operating.go`, `networks.go`, and `config.go`), its INI configuration key, its Go API surface, and its exact raw values across all three presets.

### 3.1 Router, NetDB, Tunnel & Reseed Parameters (`state.Operating` & `ivnp.NetworkConfig`)

| Domain | Parameter (`state.Operating` Field) | INI Key (`ivnp.conf`) | Go Option / Field (`gosuda.org/ivnp`) | `public` Default | `dedicated` Preset | `direct` Preset | Valid Override Range |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Network** | `Network.ID` | `[network] id` | `NetworkConfig.NetworkID` | `2` | Caller-supplied (`1..255`) | Caller-supplied (`1..255`) | `1..255` |
| **Network** | `Network.Profile` | `[network] profile` | `WithNetworkProfile(p)` | `"public"` | `"dedicated"` | `"direct"` | `"public"`, `"dedicated"`, `"direct"` |
| **Router Role** | `Router.Floodfill` | `[router] floodfill` | `WithPublicParticipation(...)` | `false` (`ParticipationWarm`) | `true` (`ParticipationContributor`) | `true` (`ParticipationContributor`) | `bool` |
| **Router Role** | `Router.Transit` | `[router] transit` | `WithPublicParticipation(...)` | `true` (`ParticipationWarm`) | `true` (`ParticipationContributor`) | `true` (`ParticipationContributor`) | `bool` |
| **NetDB** | `NetDB.BucketCapacity` | `[netdb] bucket_capacity` | `(fixed at 24 in embedded)` | `24` | `24` | `24` | `5..1024` (INI) |
| **NetDB** | `NetDB.BucketSubnetQuota` | `[netdb] bucket_subnet_quota` | `NetDBConfig.BucketSubnetQuota` | `2` (per `/16` IPv4, `/32` IPv6) | `16` | `0` (disabled) | `0..1024` (INI) / `0..64` (Go; `0` disables) |
| **NetDB** | `NetDB.DisableBucketSubnetQuota` | `(set when quota = 0)` | `NetDBConfig.DisableBucketSubnetQuota` | `false` | `false` | `true` | `bool` |
| **NetDB** | `NetDB.MinRouters` | `[netdb] min_routers` | `NetDBConfig.MinRouters` | `50` | `2` | `1` | `1..10000` (INI) / `1..1000` (Go) |
| **NetDB** | `NetDB.RouterInfoFloodfillK` | `[netdb] router_info_floodfill_k` | `NetDBConfig.RouterInfoFloodfillK` | `5` | `2` | `1` | `1..16` |
| **NetDB** | `NetDB.LeaseSetFloodfillK` | `[netdb] lease_set_floodfill_k` | `NetDBConfig.LeaseSetFloodfillK` | `4` | `2` | `1` | `1..16` |
| **NetDB** | `NetDB.ExplorationBootstrapDelay` | `[netdb] exploration_bootstrap_delay` | `NetDBConfig.ExplorationBootstrapDelay` | `1s` | `500ms` | `500ms` | `100ms..10m` |
| **NetDB** | `NetDB.ExplorationSteadyDelay` | `[netdb] exploration_steady_delay` | `NetDBConfig.ExplorationSteadyDelay` | `5s` | `5s` | `3s` | `100ms..10m` (INI) / `1s..1h` (Go) |
| **NetDB** | `NetDB.BootstrapRouterInfoPaths` | `[netdb] bootstrap_router_info_files` | `WithPeerSeeds(rawRouterInfos...)` | `nil` | `nil` | `nil` | Up to `64` file paths (INI) |
| **Tunnel** | `Tunnel.Hops` | `[tunnel] hops` | `Exploratory.Inbound.Hops` | `3` (INI) / `2` (Go exploratory) | `1` | `1` | `1..7` |
| **Tunnel** | `Tunnel.IPRestriction` | `[tunnel] ip_restriction` | `WithIPRestriction(mode)` | `2` (`/16` IPv4, `/32` IPv6) | `2` (`/16` IPv4, `/32` IPv6) | `0` (disabled) | `0..4` (`0` disables) |
| **Tunnel** | `Tunnel.DisableIPRestriction` | `(set when ip_restriction = 0)` | `TunnelPolicyConfig.DisableIPRestriction` | `false` | `false` | `true` | `bool` |
| **Tunnel** | `Tunnel.ExploratoryInboundTarget` | `[tunnel] exploratory_inbound_target` | `Exploratory.Inbound.Count` | `4` (INI) / `2` (Go) | `2` | `2` | `1..16` |
| **Tunnel** | `Tunnel.ExploratoryOutboundTarget` | `[tunnel] exploratory_outbound_target` | `Exploratory.Outbound.Count` | `4` (INI) / `2` (Go) | `2` | `2` | `1..16` |
| **Tunnel** | `Tunnel.ExploratoryPoolCapacity` | `[tunnel] exploratory_pool_capacity` | `(derived from Count + Backup)` | `8` | `6` | `4` | `2..64` (`>= 2 * target`) |
| **Tunnel** | `Tunnel.ClientInboundTarget` | `[tunnel] client_inbound_target` | `DestinationConfig.Tunnels.Inbound.Count` | `2` | `2` | `2` (INI) / `1+1` (Go) | `1..16` |
| **Tunnel** | `Tunnel.ClientOutboundTarget` | `[tunnel] client_outbound_target` | `DestinationConfig.Tunnels.Outbound.Count` | `2` | `2` | `2` (INI) / `1+1` (Go) | `1..16` |
| **Tunnel** | `Tunnel.ClientPoolCapacity` | `[tunnel] client_pool_capacity` | `(derived from Count + Backup)` | `4` | `6` | `4` | `2..64` (`>= 2 * target`) |
| **Tunnel** | `Tunnel.Lifetime` | `[tunnel] lifetime` | `(protocol constant: 10m)` | `10m` | `10m` | `10m` | `10m` |
| **Tunnel** | `Tunnel.RenewBefore` | `[tunnel] renew_before` | `Exploratory.RenewBefore` | `210s` (`3m30s`) | `210s` (INI) / `180s` (Go) | `210s` (INI) / `180s` (Go) | `1s..9m59s` (`< lifetime`) |
| **Tunnel** | `Tunnel.MaintenanceInterval` | `[tunnel] maintenance_interval` | `WithTunnelTiming(maint, ...)` | `1m` (`60s`) | `5s` | `3s` | `1s..10m` (INI) / `100ms..10m` (Go) |
| **Tunnel** | `Tunnel.ProbeTimeout` | `[tunnel] probe_timeout` | `WithTunnelTiming(..., probe, ...)` | `1m` (`60s`) | `10s` | `5s` | `1s..10m` (INI) / `500ms..2m` (Go) |
| **Tunnel** | `Tunnel.ProbeFailureThreshold` | `[tunnel] probe_failure_threshold` | `WithTunnelTiming(..., threshold)` | `2` | `2` | `2` | `1..255` (INI) / `1..16` (Go) |
| **Reseed** | `Reseed.Enabled` | `[reseed] enabled` | `(auto-enabled when ReseedURLs != nil)` | `true` | `false` | `false` | `bool` |
| **Reseed** | `Reseed.Endpoints` | `[reseed] endpoints` | `WithReseedURLs(urls)` | 12 public `.su3` URLs | `nil` | `nil` | HTTPS URLs with `?netid=<id>` |
| **Reseed** | `Reseed.TrustedCertPaths` | `[reseed] trusted_cert_files` | `WithTrustedReseedCerts(pemOrDER...)` | Embedded public certs | `nil` | `nil` | Up to `16` (Go) / `64` (INI) certs |
| **Reseed** | `Reseed.BucketSubnetQuota` | `[reseed] bucket_subnet_quota` | `(follows NetDB.DisableBucketSubnetQuota)` | `2` | `16` | `0` (disabled) | `0..64` (`0` disables) |
| **Reseed** | `Reseed.BucketAdmitLimit` | `[reseed] bucket_admit_limit` | `(INI configurable)` | `20` | `20` | `20` | `1..256` |
| **Reseed** | `Reseed.VerifyAnchorCount` | `[reseed] verify_anchor_count` | `(INI configurable)` | `16` | `2` | `1` | `1..64` |
| **Reseed** | `Reseed.MergeWait` | `[reseed] merge_wait` | `(INI configurable)` | `0s` (`5s` runtime default; `< 0` skips wait) | `0s` | `0s` | `-10m..10m` |
| **Services** | `HTTPProxy.Outproxies` | `[http_proxy] outproxies` | `(daemon only)` | `["exit.stormycloud.i2p"]` | `[]` (disabled) | `[]` (disabled) | Comma-separated hosts |
| **Services** | `AddressBook.Subscriptions` | `[addressbook] subscriptions` | `(daemon only)` | 4 public `.i2p` / GitHub URLs | `nil` (disabled) | `nil` (disabled) | Comma-separated HTTP(S) URLs |

### 3.2 Destination Presets (`ivnp.DestinationConfig` in `config.go`)

In the embedded Go API, `RouterConfig` controls router-level exploratory tunnels and NetDB parameters, while each `Destination` owns its client tunnel pool (`DestinationConfig.Tunnels`):

| Field | `DefaultDestinationConfig()` (`public`) | `DedicatedDestinationConfig()` (`dedicated`) | `DirectDestinationConfig()` (`direct`) | Valid Bounds (`config.go`) |
| :--- | :--- | :--- | :--- | :--- |
| `Policy.Kind` | `DestinationPublicLS2` | `DestinationPublicLS2` | `DestinationPublicLS2` | `DestinationPublicLS2`, `DestinationEncryptedLS2` |
| `Tunnels.Inbound.Hops` | `3` | `1` | `1` | `1..3` |
| `Tunnels.Inbound.Count` | `3` | `2` | `1` | `1..6` (`Count + Backup <= 6`) |
| `Tunnels.Inbound.Backup` | `1` | `0` | `1` | `0..5` (`Count + Backup <= 6`) |
| `Tunnels.Outbound.Hops` | `3` | `1` | `1` | `1..3` |
| `Tunnels.Outbound.Count` | `3` | `2` | `1` | `1..6` (`Count + Backup <= 6`) |
| `Tunnels.Outbound.Backup` | `1` | `0` | `1` | `0..5` (`Count + Backup <= 6`) |
| `Tunnels.RenewBefore` | `210s` (`3m30s`) | `180s` (`3m00s`) | `180s` (`3m00s`) | `30s..300s` |
| `PacketQueue.MaxPackets` | `64` | `64` | `64` | `> 0` |
| `PacketQueue.MaxBytes` | `1048576` (`1 MiB`) | `1048576` (`1 MiB`) | `1048576` (`1 MiB`) | `> 0` |

---

## 4. Detailed Parameter Mechanics & Tuning Guide

Every preset applies its baseline values first (`DefaultOperatingForProfile`), and then applies any explicit INI keys or Go `NetworkOption` overrides on top. You never lose fine-grained control by choosing a preset.

### 4.1 Network Identity & Peer Admission (`netId`, `AdmitPeer`, `EncryptedLeaseSet`)

- **`netId` Isolation (`[network] id` / `NetworkConfig.NetworkID`)**:
  Every `RouterInfo` carries a `"netId"` mapping option, and both NTCP2 (Noise prologue / frame validation) and SSU2 verify that peers advertise the local context's `netId`. Pick a consistent integer in `1..255` (excluding `2`, which is reserved for public I2P) for all nodes in your private mesh.
- **Transport-Layer Peer Allowlists (`WithPeerAdmission` / `AdmitPeers`)**:
  Because `netId` is a 1-byte public integer (`1..255`), `netId` alone prevents accidental cross-talk with public I2P routers, not deliberate connection attempts from an unauthorized host that knows your IP and `netId`. To enforce cryptographic membership at the transport boundary, configure `WithPeerAdmission`:
  - `ivnp.AdmitPeers(allowedHashes...)`: Admits only peers whose verified 32-byte SHA-256 `IdentHash` is in the allowlist.
  - `ivnp.RejectPeers(blockedHashes...)`: Denies specific router identity hashes.
  - `ivnp.ChainAdmission(fn1, fn2, ...)`: Evaluates admission checks in order until one returns an error.
  - Custom `PeerAdmissionFunc`: Inspects `PeerAdmission{Network, NetworkID, Transport, Direction, Remote, Peer, RouterInfo}` synchronously before a session is installed.
- **Destination-Layer Access Control (`DestinationEncryptedLS2`)**:
  Even inside a shared `dedicated` network, a sensitive service destination can hide its `LeaseSet2` behind blinded `Red25519` keys and two-layer ChaCha20 encryption (`DestinationPolicy{Kind: DestinationEncryptedLS2, ClientAuth: ClientAuthDH}` or `ClientAuthPSK`), so only authorized client destinations can decrypt its inbound tunnel gateways.

### 4.2 NetDB Subnet Quotas, Readiness & Floodfill Quorum (`[netdb]` / `WithNetDBConfig`)

- **`bucket_subnet_quota` (`NetDBConfig.BucketSubnetQuota` / `DisableBucketSubnetQuota`)**:
  Controls how many routers sharing the same IPv4 `/16` or IPv6 `/32` prefix can occupy a single Kademlia K-bucket (`controlplane/internal/netdb/kbucket.go`).
  - Set to `0` (`DisableBucketSubnetQuota: true`, default in `direct`) whenever nodes run on a flat LAN (`192.168.x.x`, `10.x.x.x`), Docker bridge, or loopback interface.
  - Set to `8..16` (default `16` in `dedicated`) when nodes are distributed across public networks but multiple nodes may co-locate in the same cloud region `/16`.
- **`min_routers` (`NetDBConfig.MinRouters`)**:
  Minimum number of non-local peers in the NetDB before the control plane reports NetDB readiness (`Router.WaitReady`) and transitions the explorer from `ExplorationBootstrapDelay` to `ExplorationSteadyDelay`.
  - In a `2-node` cluster, `min_routers` **must** be `1` (`direct` default). Setting `min_routers = 2` on a 2-node cluster causes `WaitReady` to block forever because each node only sees 1 remote peer.
  - In a `N-node` cluster (`N >= 3`), set `min_routers` to `min(N-1, 4)` so nodes wait for initial mesh connectivity before declaring readiness.
- **`router_info_floodfill_k` and `lease_set_floodfill_k`**:
  Number of closest floodfill routers (by Kademlia XOR distance to the daily routing key) targeted during `DatabaseStore` publication (`controlplane/internal/netdb/publisher.go`).
  - In a `2-node` cluster, set both to `1` (`direct` default).
  - In a `3 to 10 node` cluster, `2` (`dedicated` default) ensures every `LeaseSet2` resides on at least two peers.
  - In a `20+ node` cluster, increase to `3` or `4` via `WithNetDBConfig(NetDBConfig{RouterInfoFloodfillK: 3, LeaseSetFloodfillK: 3})`.
- **`exploration_bootstrap_delay` and `exploration_steady_delay`**:
  Controls how frequently `controlplane/internal/netdb/explorer.go` issues iterative Kademlia lookups for random keys to discover new peers. Lowering `exploration_bootstrap_delay` to `250ms..500ms` accelerates initial mesh convergence when nodes boot sequentially.

### 4.3 Tunnel Hops, IP Restriction & Probe Timing (`[tunnel]` / `WithIPRestriction`, `WithTunnelTiming`)

- **`ip_restriction` (`WithIPRestriction(mode)`)**:
  Controls subnet prefix separation between hops within a single tunnel (`controlplane/internal/tunnel/selector.go`):
  - `0`: Disabled (`direct` default). Hops may share any IP subnet (including identical `127.0.0.1` loopback IP addresses on different ports), though a multi-hop tunnel still requires distinct router identity hashes per hop.
  - `1`: Distinct IPv4 `/8` or IPv6 `/16` per hop.
  - `2`: Distinct IPv4 `/16` or IPv6 `/32` per hop (`public` and `dedicated` default).
  - `3`: Distinct IPv4 `/24` or IPv6 `/48` per hop.
  - `4`: Distinct IPv4 `/32` or IPv6 `/64` (exact IP address) per hop. Use `WithIPRestriction(4)` in a `dedicated` cluster when all nodes share a `/24` LAN subnet (`192.168.1.10`, `192.168.1.11`, `192.168.1.12`) and you want 2-hop tunnels that forbid two routers on the exact same host IP from participating in the same tunnel.
- **`hops` (`TunnelDirectionConfig.Hops`)**:
  A `K-hop` tunnel requires at least `K` distinct remote transit routers in the NetDB.
  - `1-hop` (`direct` and `dedicated` default): Works with as few as `2` total nodes in the network (`1` remote peer).
  - `2-hop`: Requires at least `3` total nodes in the network (`2` distinct remote transit peers).
  - `3-hop`: Requires at least `4` total nodes in the network (`3` distinct remote transit peers).
- **`maintenance_interval`, `probe_timeout`, and `probe_failure_threshold` (`WithTunnelTiming`)**:
  `PairedPoolMaintainer` (`controlplane/internal/tunnel/pool.go`) ticks every `maintenance_interval` to replenish expiring tunnels and send loopback health probes (`Outbound -> Inbound`) across active tunnels. If a probe is not echoed within `probe_timeout` for `probe_failure_threshold` consecutive checks, the tunnel is evicted and rebuilt immediately.
  - For laptop sidecars or Wi-Fi meshes where nodes roam or sleep (`direct`), `3s` maintenance + `5s` probe timeout + `2` failures replaces broken paths in `< 10s`.
  - For WAN overlays with transcontinental RTTs (`dedicated`), `5s` maintenance + `10s` probe timeout avoids false-positive evictions during transient congestion.

### 4.4 Bootstrap Mechanisms: Static Peer Seeds vs. Private Reseed Server

Private networks never contact public I2P reseed servers unless explicitly configured. You can seed a private network using three methods:

1. **In-Memory / Programmatic Peer Seeds (`WithPeerSeeds` or `Node().ImportRouterInfo`)**:
   - Export a node's signed `RouterInfo` wire bytes at runtime via `router.Node().ExportLocalRouterInfo("mesh")` and import them into peers via `WithPeerSeeds(riBytes...)` at startup or `router.Node().ImportRouterInfo(ctx, "mesh", riBytes)` dynamically (for example, after discovering a peer over mDNS, Bluetooth LE, QR code, or a coordination API).
2. **Static `RouterInfo` Files on Disk (`[netdb] bootstrap_router_info_files`)**:
   - In `ivnp.conf`, list up to 64 comma-separated paths to `.dat` `RouterInfo` files. On startup, the control plane verifies each file's cryptographic signature and `netId` before admitting it into the NetDB.
3. **Private `ivnp-reseed` HTTPS Server (`WithReseedURLs` + `WithTrustedReseedCerts`)**:
   - For larger `dedicated` deployments (`10+` nodes), run `cmd/ivnp-reseed` configured with your private `netId` and a dedicated RSA-4096 signing certificate.
   - Configure nodes with `WithReseedURLs([]string{"https://reseed.internal.example/i2pseeds.su3?netid=42"})` and `WithTrustedReseedCerts(privateRootCertPEM)`. Note that every reseed URL **must** include the exact `?netid=<NetworkID>` query string (`networks.go:validateBootstrap`), preventing accidental cross-network seeding.

---

## 5. End-to-End Configuration Recipes

### 5.1 Recipe 1: Clipboard Synchronization Sidecar (`direct` Profile in Go)

This example shows how two desktop sidecar processes (such as a MacBook and a Linux workstation on `192.168.1.0/24`) form a closed 2-node `direct` mesh (`netId = 88`), enforce a mutual router hash allowlist, and exchange clipboard updates over authenticated `Datagram2` packets (for small text snippets) and I2P streaming connections (for large image/file payloads).

```go
package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"gosuda.org/ivnp"
)

type SidecarNodeConfig struct {
	DataDir          string
	BindAddr         netip.AddrPort // e.g., 0.0.0.0:19110
	AdvertisedAddr   netip.AddrPort // e.g., 192.168.1.10:19110
	PeerRouterInfos  [][]byte       // Signed RouterInfo bytes of paired user devices
	AllowedPeerHosts []ivnp.Hash    // IdentHashes of the user's paired devices
}

func startClipboardSidecar(ctx context.Context, sc SidecarNodeConfig) (*ivnp.Router, *ivnp.Destination, error) {
	cfg := ivnp.DefaultRouterConfig()
	cfg.Persistence = &ivnp.PersistenceConfig{Directory: sc.DataDir}

	// Build a "direct" network context (netId = 88):
	// - /16 subnet quota disabled (0) and hop IP restriction disabled (0)
	// - MinRouters = 1, FloodfillK = 1 (2 devices suffice; no 3rd-party server needed)
	// - 1-hop exploratory tunnels, 3s maintenance, 5s probe timeout
	cfg.SetNetworks(ivnp.NewDirectNetwork(
		"clipsync",
		88,
		ivnp.WithListenAddress(sc.BindAddr, sc.BindAddr),
		ivnp.WithAdvertisedAddress(sc.AdvertisedAddr, sc.AdvertisedAddr),
		ivnp.WithPeerSeeds(sc.PeerRouterInfos...),
		ivnp.WithPeerAdmission(ivnp.AdmitPeers(sc.AllowedPeerHosts...)),
	))

	router, err := ivnp.NewRouter(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	if err := router.WaitReady(ctx); err != nil {
		_ = router.Close()
		return nil, nil, err
	}

	// DirectDestinationConfig uses 1-hop client tunnels (1 active + 1 backup).
	destCfg := ivnp.DirectDestinationConfig()
	destCfg.Networks = []string{"clipsync"}
	dest, err := router.NewDestination(ctx, destCfg)
	if err != nil {
		_ = router.Close()
		return nil, nil, err
	}

	return router, dest, nil
}

// broadcastClipboardText sends an authenticated, replay-resistant Datagram2
// payload to a paired device's .b32.i2p destination on port 7701.
func broadcastClipboardText(dest *ivnp.Destination, targetB32 string, text []byte) error {
	pktConn, err := dest.ListenPacket("clipsync-datagram2", ":0")
	if err != nil {
		return err
	}
	defer pktConn.Close()

	targetAddr, err := ivnp.ParseAddr(net.JoinHostPort(targetB32, "7701"))
	if err != nil {
		return err
	}
	_ = pktConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = pktConn.WriteTo(text, targetAddr)
	return err
}

// sendLargeClipboardImage streams a multi-megabyte image or file to a paired
// device over a reliability-controlled I2P streaming connection on port 7702.
func sendLargeClipboardImage(ctx context.Context, dest *ivnp.Destination, targetB32 string, r io.Reader) error {
	conn, err := dest.DialContext(ctx, "clipsync", net.JoinHostPort(targetB32, "7702"))
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = io.Copy(conn, r)
	return err
}
```

> [!TIP]
> **Dynamic Device Pairing without Pre-Shared Files**: When pairing a new device on the same LAN (for example, via mDNS discovery or a local QR code), call `rawRI, err := router.Node().ExportLocalRouterInfo("clipsync")` on each side, exchange `rawRI` over the pairing channel, and call `peerHash, err := router.Node().ImportRouterInfo(ctx, "clipsync", remoteRawRI)` at runtime. Both routers immediately schedule an NTCP2/SSU2 handshake and converge without restarting.

### 5.2 Recipe 2: Multi-Site Dedicated Overlay with Custom Overrides (`dedicated` Profile in Go)

This example configures a node in an 8-node `dedicated` cluster (`netId = 42`) where nodes use `2-hop` client tunnels for intra-cluster relay privacy, relax tunnel IP restrictions to `4` (distinct `/32` host IPs rather than `/16` subnets so multiple nodes in one VPC `/16` can form multi-hop chains), and require `K = 3` floodfill confirmations.

```go
package main

import (
	"context"
	"net/netip"
	"time"

	"gosuda.org/ivnp"
)

func buildDedicatedClusterRouter(ctx context.Context, bind, advertised netip.AddrPort, reseedCert []byte) (*ivnp.Router, *ivnp.Destination, error) {
	cfg := ivnp.DefaultRouterConfig()
	cfg.SetNetworks(ivnp.NewDedicatedNetwork(
		"corp_mesh",
		42,
		ivnp.WithListenAddress(bind, bind),
		ivnp.WithAdvertisedAddress(advertised, advertised),
		// Seed from an internal ivnp-reseed server (?netid=42 is mandatory):
		ivnp.WithBootstrap(ivnp.BootstrapConfig{
			ReseedURLs:    []string{"https://reseed.corp.internal/i2pseeds.su3?netid=42"},
			ReseedTimeout: 15 * time.Second,
			TrustedCerts:  [][]byte{reseedCert},
		}),
		// Override NetDB readiness and floodfill quorum for an 8-node cluster:
		ivnp.WithNetDBConfig(ivnp.NetDBConfig{
			BucketSubnetQuota:    32,
			MinRouters:           3,
			RouterInfoFloodfillK: 3,
			LeaseSetFloodfillK:   3,
		}),
		// Allow hops in the same /16 cloud VPC as long as each hop has a distinct IP (/32):
		ivnp.WithIPRestriction(4),
		ivnp.WithTunnelTiming(5*time.Second, 8*time.Second, 2),
	))

	router, err := ivnp.NewRouter(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Start from DedicatedDestinationConfig and override client tunnels to 2 hops:
	destCfg := ivnp.DedicatedDestinationConfig()
	destCfg.Networks = []string{"corp_mesh"}
	destCfg.Tunnels.Inbound.Hops = 2
	destCfg.Tunnels.Outbound.Hops = 2

	dest, err := router.NewDestination(ctx, destCfg)
	if err != nil {
		_ = router.Close()
		return nil, nil, err
	}
	return router, dest, nil
}
```

### 5.3 Recipe 3: Dual-Homed Hybrid Destination (`direct` + `public` with Happy Eyeballs)

A single `Router` and `Destination` can bridge a low-latency `direct` mesh (`"lan"`, `netId = 88`) and the public I2P overlay (`"i2p"`, `netId = 2`):

```go
cfg := ivnp.DefaultRouterConfig()
cfg.SetNetworks(
	ivnp.NewDirectNetwork("lan", 88,
		ivnp.WithListenAddress(lanBind, lanBind),
		ivnp.WithAdvertisedAddress(lanAdv, lanAdv),
		ivnp.WithPeerSeeds(lanPeerSeeds...),
	),
	ivnp.DefaultI2PNetwork(),
)
cfg.DefaultNetwork = "lan"

router, err := ivnp.NewRouter(ctx, cfg)
if err != nil {
	return err
}
defer router.Close()

destCfg := ivnp.DirectDestinationConfig()
destCfg.Networks = []string{"lan", "i2p"} // Preference order: "lan" first, "i2p" second
dest, err := router.NewDestination(ctx, destCfg)
if err != nil {
	return err
}
defer dest.Close()

// Merged listener accepts streams arriving from either "lan" or "i2p":
ln, err := dest.ListenContext(ctx, "i2p", ":8080")

// Unqualified "i2p" dial starts "lan" at t=0ms and staggers "i2p" by 250ms:
conn, err := dest.DialContext(ctx, "i2p", net.JoinHostPort(remoteB32, "8080"))
if err == nil {
	// Inspect whether "lan" or "i2p" won the race:
	winningNet := ivnp.ConnectionNetwork(conn)
	_ = winningNet
}
```

### 5.4 Recipe 4: Standalone Daemon (`ivnpd`) INI Configurations

#### Direct Office / LAN Mesh (`ivnp.conf`)

Use `profile = direct` when running `ivnpd` on an office LAN, home lab, or 2-to-30 node local cluster seeded from static `RouterInfo` files:

```ini
[paths]
data_dir = /var/lib/ivnp-lan

[network]
id = 88
profile = direct ; Enables floodfill+transit, disables /16 quotas & IP restrictions, sets 1-hop & K=1

[ntcp2]
enabled = true
bind_host = 0.0.0.0
bind_port = 19110
advertise_host = 192.168.1.10
advertise_port = 19110

[ssu2]
enabled = true
bind_host = 0.0.0.0
bind_port = 19110
advertise_host = 192.168.1.10
advertise_port = 19110

[netdb]
bootstrap_router_info_files = /etc/ivnp-lan/peers/node-b.dat, /etc/ivnp-lan/peers/node-c.dat

[sam]
enabled = true
listen_host = 127.0.0.1
listen_port = 7656
udp_host = 127.0.0.1
udp_port = 7655
```

#### Dedicated Multi-Site Overlay (`ivnp.conf` with Custom Raw Overrides)

Use `profile = dedicated` when running `ivnpd` across a multi-site private overlay with a private `ivnp-reseed` server and custom NetDB / tunnel overrides:

```ini
[paths]
data_dir = /var/lib/ivnp-dedicated

[network]
id = 42
profile = dedicated ; Baseline: floodfill=true, transit=true, quota=16, min_routers=2, K=2, hops=1

[ntcp2]
enabled = true
bind_host = 0.0.0.0
bind_port = 19220
advertise_host = 203.0.113.15
advertise_port = 19220

[ssu2]
enabled = true
bind_host = 0.0.0.0
bind_port = 19220
advertise_host = 203.0.113.15
advertise_port = 19220

[netdb]
; Override baseline dedicated values for a 10-node cluster in a shared /16 VPC:
min_routers = 3
bucket_subnet_quota = 0
router_info_floodfill_k = 3
lease_set_floodfill_k = 3
exploration_bootstrap_delay = 250ms
exploration_steady_delay = 3s

[tunnel]
hops = 2
ip_restriction = 4 ; Require distinct /32 host IPs per hop, allowing shared /16 subnet
maintenance_interval = 5s
probe_timeout = 8s
probe_failure_threshold = 2

[reseed]
enabled = true
endpoints = https://reseed.internal.example/i2pseeds.su3?netid=42
trusted_cert_files = /etc/ivnp-dedicated/reseed-ca.crt
bucket_subnet_quota = 0
bucket_admit_limit = 32
verify_anchor_count = 3
merge_wait = 1s
```

Validate any `ivnp.conf` file before starting the daemon:

```sh
ivnpd -config /etc/ivnp-dedicated/ivnp.conf -test-config
```
