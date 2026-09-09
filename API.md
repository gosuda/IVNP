# Embedded Router and Network API

## 1. Status and scope

This document defines the public embedding API. Declaration blocks specify exported signatures; concrete types have private implementation state. `Hash`, `DestinationPolicy`, and destination-policy constants retain their public meanings. Daemon and low-level APIs are accessed through their owning subsystem packages rather than compatibility aliases in the root package.

The embedding boundary is `Router -> Destination -> network I/O`. Configuration is supplied as Go values. The library does not read, create, watch, or reload `ivnp.conf`. The daemon may translate a configuration file into the same validated runtime settings.

- `Router` owns router identity, transport sockets, NetDB, exploratory tunnels, and destination lifetimes.
- `Destination` owns one application identity, client tunnels, LeaseSet publication, and virtual-port bindings.
- Streams implement `net.Conn` and `net.Listener`.
- Signed datagrams use `PacketConn`, which implements `net.PacketConn`.
- Unsigned datagrams use `UnauthPacketConn`, which deliberately does **not** implement `net.PacketConn`.

A Router is not a Destination. Router identity is never substituted for an application identity. Router creates and owns Destinations but exposes no application stream or packet I/O. Every application connection, listener, and packet socket belongs to an explicitly created Destination.

Normative MUST/MUST NOT requirements below are implementation acceptance criteria.

## 2. Static configuration

```go
func DefaultRouterConfig() RouterConfig
func DefaultDestinationConfig() DestinationConfig

type RouterConfig struct {
    Persistence        *PersistenceConfig
    NetworkID          uint32
    NTCP2              TransportConfig
    SSU2               TransportConfig
    Bootstrap          BootstrapConfig
    Exploratory        TunnelPoolConfig
    Limits             RouterLimits
    Resolver           NameResolver
    Logger             *slog.Logger
}

type PersistenceConfig struct {
    Directory string
}

type TransportConfig struct {
    Enabled     bool
    Bind        netip.AddrPort
    Advertised  netip.AddrPort
    MaxSessions int
    IdleTimeout time.Duration
}

type BootstrapConfig struct {
    RouterInfos   [][]byte
    ReseedURLs    []string
    ReseedTimeout time.Duration
}

type TunnelPoolConfig struct {
    Inbound     TunnelDirectionConfig
    Outbound    TunnelDirectionConfig
    RenewBefore time.Duration
}

type TunnelDirectionConfig struct {
    Hops   int
    Count  int
    Backup int
}

type RouterLimits struct {
    MaxDestinations        int
    PacketQueueBytes       int64
    MaxPendingPacketWrites int
}

type DestinationConfig struct {
    Identity     *foundation.LocalDestination
    Policy       DestinationPolicy
    Tunnels      TunnelPoolConfig
    PacketQueue  PacketQueueConfig
    RemoteAccess []RemoteLeaseSetAccess
}

type PacketQueueConfig struct {
    MaxPackets int
    MaxBytes   int64
}
```

### 2.1 Defaults and validation

Default functions are pure: no filesystem, randomness, environment lookup, name lookup, or network I/O. Each call returns independently owned slices. Use a default function and modify its result; constructors do not merge a supplied configuration with hidden defaults.

| Setting | Default | Validation / meaning |
|---|---|---|
| `Persistence` | Nil | In-memory router state. A nonnil value explicitly enables disk persistence and requires a nonempty Directory. |
| `NetworkID` | 2 | 0..255; not inferred from an address. |
| NTCP2 / SSU2 | Both enabled | At least one enabled. Disabled transports require their other fields to be zero. |
| Transport bind | `0.0.0.0:0` | Valid native IP address; port 0 asks the OS to allocate a port. An IPv6 bind explicitly selects IPv6 for that transport. |
| Advertised endpoint | Invalid `netip.AddrPort` | Derive through the existing transport address-discovery rules. An explicit value must be a usable unicast address with nonzero port; it is a declaration, not a reachability guarantee. |
| Sessions / idle timeout | 256 / 10 minutes | Both positive for an enabled transport. |
| Bootstrap router infos | Empty | Canonical binary RouterInfo records; validate signatures, network ID, and current usability before seeding. Invalid supplied records fail Router construction. |
| Reseed URLs | Maintained built-in HTTPS endpoints for network 2 | Nil or empty disables reseeding; no fallback. Each URL must contain exactly `netid=<NetworkID>` as its query. Changing NetworkID requires replacing the default URLs or disabling reseeding. SU3 signature/trust validation and imported RouterInfo network matching remain mandatory. |
| Reseed timeout | 30 seconds | Positive when URLs are present; zero is allowed only when reseeding is disabled. |
| Exploratory pool | Each direction: 3 hops, Count 4, Backup 0 | Independent directional settings; see tunnel policy below. |
| Destination pool | Each direction: 3 hops, Count 2, Backup 0 | Independent per-Destination settings; no zero-hop production mode. |
| Tunnel renewal lead time | 210 seconds | 1 second <= RenewBefore < 10 minutes; applies to active and backup tunnels. |
| Router destinations | 64 | 1..64, including destinations under construction and still closing. |
| Router packet queue bytes | 64 MiB | Positive; aggregate retained encoded datagram bytes across all destinations. |
| Pending packet writes | 64 | Positive; router-wide bound on admitted packet writes, including route preparation. Saturation returns `ErrResourceLimit`; no unbounded internal wait queue. |
| Per-socket queue | 64 packets, 1 MiB | Both positive; byte limit at least `MaxReceiveDatagramSize` and no larger than the router budget. |
| Destination identity | Nil | Generate a transient identity compatible with the publication policy. |
| Publication | `DestinationPublicLS2` | Validate using the policy rules below. |
| Resolver / logger | Nil / nil | No human-name resolution / use `slog.Default()`. Neither collaborator is closed by Router. |

The zero `RouterConfig` and zero `DestinationConfig` are not complete configurations. Boolean zero is false, not an omitted value. To disable a transport after taking defaults, assign `TransportConfig{}`.

All internal tunnel lifetimes remain ten minutes. Other core resource limits retain validated implementation defaults; the facade does not expose allocator, queue-layout, or packet-pool implementation details as configuration.

Constructors validate before creating network side effects. They copy configuration slices, nested records, and secret bytes before retaining them. Callers MUST NOT mutate configuration or release supplied keys concurrently with construction; after return, caller-owned values may be changed or wiped. Injected resolver/logger objects are shared references and must support concurrent use.

No SAM, HTTP proxy, SOCKS5 proxy, management listener, metrics listener, hosts-file subscription, or automatic NAT port-mapping service is started by `NewRouter`. Daemon frontends are independently composed clients of the core. Native transport and explicit reseed traffic are expected network effects.

### 2.2 Router persistence and destination keys

Router state is in memory by default. `Persistence == nil` selects an instance-local state store; `Persistence != nil` selects private disk-backed state. The selection is fixed at construction, with no runtime mode switch or automatic fallback between modes. An empty Directory in a nonnil PersistenceConfig is `ErrInvalidConfig`, not a request for in-memory operation.

#### In-memory mode

- Generate router identity and transport keys for this Router lifetime. Keep NetDB, peer caches, and other router-owned state in memory.
- Do not read or create router data/state/master-key/lock files, create temporary directories, emulate a filesystem, spill caches to disk, or discover an existing data directory. A writable working directory or home directory is not required.
- Each Router owns independent state. Neither a process-global store nor another Router's cache or identity is reused implicitly.
- Closing or failing construction joins owned work, wipes private key/state copies, and releases the in-memory store. Immutable public identity snapshots may remain readable on a closed handle as specified below.
- Each NewRouter call generates a new router identity and starts without a previous peer cache. Supplied bootstrap records and configured reseeding still apply; in-memory does not mean offline or immediately ready.
- NetDB and caches MUST have finite entry and retained-byte budgets and bounded eviction/admission behavior. They do not become unbounded maps because persistence is disabled. The packet queue budget is separate and does not bound total Router memory.

This is a router-owned storage guarantee, not a ban on all process filesystem access. Injected loggers/resolvers and caller-managed key storage may perform I/O; operating-system/runtime facilities may also access files. The API does not prevent swap, core dumps, or external memory inspection and does not promise that secrets can never reach physical storage.

#### Persistent mode

Copy PersistenceConfig at construction and resolve Directory relative to the working directory once. No implicit `./data` is selected. The directory is private and exclusively locked for the Router lifetime. Router keys and supported caches may be persisted there without any configuration file. Existing ownership, permissions, atomic-write, and encrypted-state protections remain required.

Only an absent state/master-key pair permits creation of a new router identity. A missing half of that pair, corrupt state, wrong permissions, lock failure, or a load failure MUST fail construction rather than regenerate identity or silently switch to memory. A directory containing legacy named application destinations is rejected with `ErrStateConflict`; it must be migrated explicitly or a dedicated embedded state directory must be used. Opening the new Router MUST NOT silently instantiate, rotate, or migrate application identities from the daemon's named-destination store.

#### Destination keys are independent of router persistence

`DestinationConfig.Identity` is validated and cloned. The caller retains the original `foundation.LocalDestination` and must eventually call `ReleaseSensitive` on it. Unsupported key/policy combinations fail; imported keys are never replaced to make a policy fit.

Nil identity produces a nonpersistent endpoint. Public LS2 generation uses the existing legacy-compatible public destination generator; encrypted LS2 uses the existing encrypted-destination generator. These defaults do not restrict compatible imported identities.

To preserve an application identity across runs, generate/import it explicitly, persist it using caller-owned secure storage, then pass it to `NewDestination`. Existing `foundation.GenerateLocalDestination`, `GenerateLegacyLocalDestination`, `GenerateEncryptedLocalDestination`, `ImportLocalDestination`, `PrivateEncodedLen`, and `MarshalPrivateTo` provide the key operations. Serialized private material is not a public destination string. The network facade does not export its private clone or implicitly save it in router state. Closing it does not delete caller storage.

| Router storage | Destination identity input on each open | Router identity on a later open | Service address on a later open |
|---|---|---|---|
| In memory | Nil | New | New |
| In memory | Same caller-retained/imported keys | New | Preserved |
| Persistent, same valid directory | Nil | Preserved | New |
| Persistent, same valid directory | Same caller-retained/imported keys | Preserved | Preserved |

Router persistence never implicitly persists an automatically generated Destination. Stable service identity requires reusing its Destination keys, not a persistent Router. Reconstructing a Router still requires fresh sessions, tunnels, and publication; persistent identity/cache does not preserve live execution state.

### 2.3 Publication policy and remote access

Reuse the existing `DestinationPolicy` fields `Kind`, `Secret`, `DHClients`, and `PSKClients` rather than introducing a second publication-policy representation.

| Kind | Required fields | Forbidden fields |
|---|---|---|
| `DestinationPublicLS2` | None | Secret and both client lists |
| `DestinationEncryptedNone` | None; optional blinding Secret | Both client lists |
| `DestinationEncryptedDH` | Nonempty DHClients | PSKClients |
| `DestinationEncryptedPSK` | Nonempty PSKClients | DHClients |

`Secret` is the LeaseSet blinding secret, **not** an authorization PSK. DH entries are authorized clients' X25519 public keys. PSK entries are 32-byte symmetric authorization keys. Enforce the existing encoded LeaseSet size and key compatibility checks; encrypted publication with an offline-signing identity is rejected. Copy and wipe retained private policy material with its destination.

Remote lookup credentials are separate and scoped to the originating Destination:

```go
type RemoteAuthKind uint8

const (
    RemoteAuthNone RemoteAuthKind = iota
    RemoteAuthDH
    RemoteAuthPSK
)

type RemoteLeaseSetAccess struct {
    Identity  []byte
    Secret    []byte
    Kind      RemoteAuthKind
    DHPrivate [32]byte
    DHPublic  [32]byte
    PSK       [32]byte
}
```

`Identity` is a complete canonical binary public Destination identity, not base64 or a private key. It determines the remote hash. Duplicate hashes, unknown kinds, malformed identities, and incompatible signing types are configuration errors. None requires all authorization-key fields to be zero; DH requires a valid matching X25519 keypair and zero PSK; PSK requires zero DH fields. An all-zero PSK is representable but unsuitable for deployment. Secret/key-size and encoded-policy limits use the existing remote-ELS validation. Credentials are copied, retained only by this destination, and wiped on close. They are not returned by address resolution, shared with siblings, or persisted automatically.

### 2.4 Tunnel quantities, backups, and hop counts

`RouterConfig.Exploratory` configures the router-owned exploratory pool. `DestinationConfig.Tunnels` independently configures each application pool. Neither silently inherits mutable settings from another pool. Inbound and outbound may have different hop counts, active targets, and backup targets. Values are fixed at construction.

For each direction:

- Hops is the number of remote participating routers in that tunnel, excluding the local creator. Valid range is 1..7. The builder must not silently shorten a path to satisfy demand; insufficient eligible peers can delay construction/readiness.
- Count is the target number of healthy active tunnels, not an established-connection limit or an exact count guaranteed at every instant. Valid range is 1..16.
- Backup is the additional target number of already-built, healthy spare tunnels, not extra storage capacity or pending build requests. Valid range is 0..15, with Count + Backup <= 16.
- Maintain Count + Backup usable tunnels once resources and peers permit. Prioritize restoring missing active tunnels before filling the reserve. Promote a usable backup when an active tunnel fails or approaches retirement, then replenish the reserve.
- A backup uses the same directional hop policy and expires/renews like an active tunnel. It consumes construction work and execution resources even when it carries no application traffic.

Outbound backups are excluded from normal outbound selection while the active target is satisfied. Inbound backups must be eligible for publication/control reply routing to be useful without a fresh build; remote peers choose published leases, so the API cannot promise that inbound backups carry no traffic. Publish at most the wire limit of 16 inbound leases, prioritizing usable active and backup candidates. This is readiness redundancy, not guaranteed peer-disjoint paths, reserved bandwidth, or lossless instantaneous failover.

Renewal overlap is separate from Backup: even Backup 0 starts replacements before expiration. Near-expiry entries awaiting replacement do not count as healthy reserve. Keep still-admitted uses and previously advertised inbound leases valid through their required draining/expiry lifetime; do not free sensitive circuit state merely to make a numeric pool count match the target.

The tunnel lifetime remains fixed at ten minutes. RenewBefore controls how early replacement work becomes eligible. Maintenance must observe the renewal boundary in time rather than poll at an interval longer than the configured lead time; build completion is still subject to peer availability and admission budgets. Add scheduling jitter only without delaying past that boundary.

Pool capacity is derived, not a public backup setting. Provision bounded installed-entry headroom of twice the sum of both directions' Count + Backup, allowing one replacement generation; the validated maximum is 64 entries per pool. Pending builds have separate bounded admission shared by the Router. Filling configured targets does not bypass that admission or promise a construction concurrency equal to the target count. Previously admitted uses remain protected if reclamation must be deferred.

Readiness retains the lifecycle contract: one usable inbound/outbound pair and, for a Destination, confirmed publication. Construction does not wait for every active slot or backup slot to fill; remaining demand is maintained in the background. Operators must not interpret WaitReady as proof that the entire configured reserve is populated.

#### Default rationale

Keep three hops in both directions as the conservative privacy default. Retain the existing four-per-direction exploratory target because all destinations share its discovery/bootstrap work, and two-per-direction client target to avoid a single active tunnel being the normal operating state. Dedicated Backup defaults to zero: two active client tunnels already provide path redundancy, and proactive renewal does not require idle spares.

For availability-sensitive services, set Backup to 1 in each client direction. That raises the steady-state client target from four to six tunnels, a 50% increase in circuit count before renewal overlap, not a measured 50% increase in CPU or bandwidth. A constrained deployment may explicitly reduce exploratory Count to 2; a single active client tunnel per direction trades away redundancy. Fewer hops can reduce path work but weakens path separation and is not an automatic low-resource fallback.

These are conservative design defaults grounded in the existing counts and renewal lead time, not benchmarked optima. More tunnels increase key/build/maintenance work; they do not guarantee proportional throughput. Inbound backups are not equivalent to idle outbound backups.

```go
func availabilityDestinationConfig() ivnp.DestinationConfig {
    cfg := ivnp.DefaultDestinationConfig()
    cfg.Tunnels.Inbound.Backup = 1
    cfg.Tunnels.Outbound.Backup = 1
    return cfg
}
```

The destination factory receives each Destination's directional policy explicitly. Active/reserve selection and replenishment belong to the control-plane pool and maintainer; Backup is not mapped to PoolCapacity. The daemon retains its separately configured pool defaults, while the embedding API supplies its own per-instance policy.

## 3. Router and Destination lifecycle

```go
type Router struct { /* private state */ }
type Destination struct { /* private state */ }

func NewRouter(ctx context.Context, cfg RouterConfig) (*Router, error)
func (r *Router) Hash() Hash
func (r *Router) NewDestination(ctx context.Context, cfg DestinationConfig) (*Destination, error)
func (r *Router) WaitReady(ctx context.Context) error
func (r *Router) Close() error

func (d *Destination) Hash() Hash
func (d *Destination) B32() string
func (d *Destination) Destination() []byte
func (d *Destination) WaitReady(ctx context.Context) error
func (d *Destination) Close() error
```

- `NewRouter` validates configuration, creates an in-memory store or opens/locks the explicitly configured persistent store, loads applicable seeds, and starts the core. Success means local startup, not tunnel readiness or remote reachability. It creates no application Destination and never waits for application LeaseSet publication.
- `NewDestination` reserves capacity and identity exclusively within the Router, clones/generates keys, installs its owner-bound runtime, and waits for live inbound/outbound tunnels and confirmed LeaseSet publication. The same identity cannot be live twice, even with different policies: return `ErrIdentityInUse`.
- Failure or cancellation during either constructor returns a nil object after rolling back owned runtime resources, workers, bindings, and key copies. In-memory state is released without storage side effects. In persistent mode, newly created durable router state may remain on disk; rollback does not mean deleting persistent identity, and acquired locks must be released. Rollback failures are joined with the primary error.
- An already-canceled context fails before creating resources. A successful return transfers lifetime ownership to the returned object. Subsequent cancellation of the construction context does not close it. Nil contexts are invalid API use and panic, following Go context conventions.
- With reseeding disabled and no usable cached/static peers, Router startup can succeed, but readiness may wait until context expiry. There is no invented online-ready fallback.
- Router `WaitReady` observes a live owner-correct exploratory inbound/outbound pair while running. It does not require a fixed peer count or any application Destination to exist or be ready. Exploratory tunnels are not published LeaseSets.
- Destination `WaitReady` observes its own live inbound/outbound pair and confirmed publication. Both readiness operations are point-in-time observations, not latches: a later call checks current state. Neither establishes a route to every remote peer.
- Background tunnel, publication, and route maintenance remains IVNP-owned. Temporary loss of readiness does not replace identity or permanently close an endpoint.

Public hash/address information is immutable and remains readable after close. `Destination()` returns a fresh copy of the I2P-base64 public destination bytes, matching the existing endpoint representation. It never exposes private material.

### 3.1 Closure and concurrency

Router, Destination, connections, and listeners support concurrent method calls. Config structs and Dialer/ListenConfig fields must not be mutated concurrently with their use. Zero-value Router/Destination/socket handles are not usable; obtain them from constructors.

`Close` is terminal and idempotent. Concurrent closers wait for the same completion and receive the same accumulated cleanup error. Router close rejects new admissions, cancels owned work, closes destinations and transports, and joins workers. In-memory mode wipes private state and releases owned storage without flushing or creating files. Persistent mode commits required router state, wipes retained private copies, and releases the state lock even when persistence fails; independent cleanup failures are joined. No separate `Start`, `Wait`, or restart is exposed on the new Router.

Destination close rejects new I/O, closes its streams/listeners/packet sockets, drains its admitted operations, releases bindings and capacity, and wipes its key/policy copies. It does not close siblings, Router, caller keys, or caller storage.

Listener close stops acceptance and wakes blocked `Accept`; accepted connections remain open. Packet socket close cancels that socket's operations and releases its one binding; it never closes its Destination. Operations already completed before close remain completed. Pending operations that close aborts fail with an error matching `net.ErrClosed`.

Destination construction racing Router close either returns a fully registered object owned by that Router or fails after cleanup. A successful result may immediately be closed by a concurrent Router close. No child escapes ownership registration.

### 3.2 Identity and service addresses

`Destination.B32()` returns the canonical lowercase `.b32.i2p` hostname with no port, scheme, or path. It is the primary public service identity for sharing and connection configuration. Combine it with a service port using `net.JoinHostPort`; Destination creation alone does not bind a port.

`Destination.Hash()` exposes the same identity in binary form for equality checks and typed packet targets. `Router.Hash()` identifies router infrastructure, not an application endpoint; encoding it as B32 does not make it a service address.

Destination has no `Addr()` method returning an unbound port-zero address. Use a listener's `Addr()`, a packet socket's `LocalAddr()`, or a connection's `LocalAddr()`/`RemoteAddr()` for actual network addresses. Router has no `B32()` or `Addr()` service accessor.

## 4. Addresses and resolution

```go
type Addr struct {
    Hash Hash
    Port uint16
}

func (a Addr) Network() string
func (a Addr) String() string
func ParseAddr(address string) (Addr, error)

type NameResolver interface {
    LookupDestination(ctx context.Context, name string) (Hash, error)
}

func (d *Destination) ResolveAddr(ctx context.Context, address string) (Addr, error)
```

`Addr` is a comparable value, not a pointer into a packet buffer. There is no separately mutable Host. `Network()` returns `"i2p"`. `String()` always includes a decimal port: canonical lowercase B32 hostname plus `:port`; a zero hash formats as `:port`. Port zero is retained in formatting for parsed bind requests, while successful bindings report the allocated nonzero port. Keep hashes as values internally and produce B32 strings at the public string boundary, not eagerly for every packet.

`ParseAddr` is pure and accepts canonical-length B32 hostnames with a decimal port, or `:port`. Hostname case is normalized. Ports must be decimal 0..65535; omitted ports, service names, signs, surrounding whitespace, URLs, native IP addresses, base64 identities, and malformed B32 hosts fail with `ErrAddressInvalid`.

Destination `ResolveAddr` additionally accepts `name.i2p:port` through the resolver injected in RouterConfig. Router shares that collaborator with its Destinations but does not expose a resolution convenience method. Resolution never uses native DNS, `/etc/hosts`, proxy settings, or an implicit address book. The resolver receives a lowercase hostname without port and returns a nonzero destination hash. Without it, a human-readable name returns `ErrNameResolutionUnavailable`; B32 addresses still work without a resolver. An error is not permission to fall back to clearnet. Resolver errors retain their causes.

Bind accepts only `:port` or this Destination's own B32 hash with a port; it does not resolve human names. A different hash returns `ErrAddressUnavailable`. Dial and packet destinations require a nonzero hash and a nonzero remote port. Remote port zero is rejected, not allocated on the peer. Legacy port-zero and wildcard routing remain explicit lower-level operations outside this facade.

Resolving an address maps a name to an identity. It does not authenticate an incoming packet, fetch a LeaseSet, establish a session, or guarantee a later send. LeaseSet lookup and route preparation belong to the sending Destination's control-plane owner and use its private lookup credentials.

## 5. Stream API and collaborators

```go
func (d *Destination) Dial(network, address string) (net.Conn, error)
func (d *Destination) DialContext(ctx context.Context, network, address string) (net.Conn, error)
func (d *Destination) Listen(network, address string) (net.Listener, error)
func (d *Destination) ListenContext(ctx context.Context, network, address string) (net.Listener, error)

type Dialer struct {
    Destination *Destination
    Timeout     time.Duration
    Deadline    time.Time
    LocalPort   uint16
}

func (d *Dialer) Dial(network, address string) (net.Conn, error)
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error)

type ListenConfig struct {
    Destination *Destination
}

func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error)
func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (*PacketConn, error)
func (lc *ListenConfig) ListenUnauthPacket(ctx context.Context, network, address string) (*UnauthPacketConn, error)
```

Stream networks are `"i2p"`, `"i2p-stream"`, and `"tcp"`. All mean I2P streaming protocol 6 on the bound Destination. `"tcp"` enables direct `http.Transport.DialContext` integration; it never means a native TCP dial. Empty network, `tcp4`, `tcp6`, `udp`, and all unknown names return `ErrUnsupportedNetwork`.

Destination's short methods use `context.Background`. Direct `DialContext` uses no additional timeout and an ephemeral local port. Dialer uses the earliest nonzero bound from caller context, Timeout, and Deadline for resolution, route preparation, and stream establishment. Timeout zero adds no limit; negative is invalid; a past nonzero Deadline expires immediately. A successful connection is detached from the dial context and uses its own deadlines thereafter.

Dialer is destination-bound, not backed by a minimal interface unable to carry LocalPort. The implementation passes LocalPort through an explicit lower-layer dial capability; it never silently ignores it or smuggles it through a context value. Nil Destination in either collaborator returns `ErrDestinationRequired`.

Listen context covers bind/setup only. After success, cancellation does not close the listener or packet socket. The context belongs in `ListenConfig.Listen(ctx, network, address)`, as in the standard library; no second `ListenConfig.ListenContext` spelling is provided.

### 5.1 Binding and port allocation

Each listener/socket binds exactly one `(destination, protocol, local port)`; no address reuse or wildcard binding is exposed. Different protocols may use the same number, including 17 versus 19 and 18 versus 20.

A local port of zero allocates a nonzero available port from 49152..65535. Allocation checks and reservation are atomic within the relevant protocol namespace. Exhaustion returns `ErrNoPortsAvailable`. A nonzero requested port must be free or returns `ErrAddressInUse`.

A stream dial reserves its source port until the connection terminates. A listener reserves its port until close; accepted streams may retain their local port without retaining the listening reservation. A replacement listener can bind after close while those streams remain active; new stream IDs must not alias an old installation. An outbound dial cannot claim a port retained by an active stream or listener. Failed setup releases its reservation before returning. Actual ports are returned by connection/listener/socket addresses; the public API never reports an ephemeral request as port zero.

Packet sockets send with their bound local port. No per-write source override exists. Packet protocol selection and port binding remain demultiplexing rules, not proof that the signed datagram authenticated those port values.

### 5.2 Stream behavior

Returned streams satisfy the full `net.Conn` contract, including concurrent calls, partial reads/writes, deadline changes affecting blocked I/O, and close unblocking I/O. Stream/listener addresses are `Addr` values. A listener is usable with `http.Server.Serve` and gRPC without a custom accept loop. An accepted peer hash derives from the authenticated stream handshake, not a caller-supplied hostname.

## 6. Packet protocol separation

| Constructor network | Wire protocol | Socket type | Source / integrity property |
|---|---:|---|---|
| `ListenPacket("i2p", ...)` | 19 | `*PacketConn` | Same as explicit Datagram2 |
| `ListenPacket("i2p-datagram2", ...)` | 19 | `*PacketConn` | Verified signing identity and signed payload; target-bound |
| `ListenPacket("i2p-datagram1", ...)` | 17 | `*PacketConn` | Verified signing identity and payload; **not** target-bound |
| `ListenUnauthPacket("i2p-datagram3", ...)` | 20 | `*UnauthPacketConn` | Sender-supplied claimed hash; unsigned |
| `ListenUnauthPacket("i2p-raw", ...)` | 18 | `*UnauthPacketConn` | No datagram source identity; raw bytes |

Each socket sends and receives exactly its selected protocol for its lifetime. There is no negotiation, dual-version binding, unsigned fallback, or version switch based on a received packet. Unknown names and names belonging to the other constructor return `ErrUnsupportedNetwork`. In particular, unauthenticated open does not accept `"i2p"` or `"udp"` as a shortcut.

Protocol 19 is the default authenticated format; protocol 17 is explicit interoperability support with weaker target-binding semantics. An offline-signing identity cannot open protocol 17. Incompatible key/format combinations return `ErrUnsupportedIdentity`, not an unsigned socket. Arbitrary I2CP protocols and raw wire subscriptions remain lower-level capabilities, not extra packet network names.

## 7. Authenticated PacketConn

```go
type PacketConn struct { /* private state */ }

func (d *Destination) ListenPacket(network, address string) (*PacketConn, error)
func (d *Destination) ListenPacketContext(ctx context.Context, network, address string) (*PacketConn, error)

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error)
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error)
func (c *PacketConn) LocalAddr() net.Addr
func (c *PacketConn) Close() error
func (c *PacketConn) SetDeadline(t time.Time) error
func (c *PacketConn) SetReadDeadline(t time.Time) error
func (c *PacketConn) SetWriteDeadline(t time.Time) error
func (c *PacketConn) MaxPayloadSize() int

var _ net.PacketConn = (*PacketConn)(nil)
```

`ReadFrom` returns decoded application bytes and an `Addr` value containing the verified sender identity hash and outer source port. `WriteTo` accepts an `Addr` or a nonnil `*Addr`, copied on entry. Other `net.Addr` implementations fail with `ErrAddressInvalid`; the implementation MUST NOT parse arbitrary `addr.String()` values. Received sender port zero is representable, but cannot be used as a remote write target through this facade.

The receive path MUST parse and verify the selected signed format before releasing application bytes:

- Protocol 17 verifies the payload signature using the enclosed identity. It does not bind the signature to this receiver.
- Protocol 19 verifies against this Destination's hash, including the offline authorization chain and its expiration when present. An authorization is expired when current Unix time is greater than its expiration; equality is valid. Out-of-range verification time fails closed.
- If authenticated outer provenance exists, a conflicting verified sender identity is rejected. Absence of such provenance is not fabricated into an identity; valid datagram signatures provide their own sender proof.
- Malformed framing, unsupported keys, invalid/expired signatures, conflicting provenance, and packets beyond the receive size bound are discarded before application delivery. A bad remote packet does not close the socket or surface as an application read error. Waiting continues under the existing read deadline.

### 7.1 What authentication does not mean

Neither signed format authenticates outer source/destination ports. Protocol 17 signs the application payload (using the protocol's DSA special rule where applicable). Protocol 19 signs `target hash || flags || encoded options || offline section || payload`; the target hash is signing input, not an additional on-wire field.

Neither format promises freshness, exactly-once delivery, ordering, a replay cache, or application authorization. Datagram2 target binding does not stop replay to the same destination or redirection between its ports. An offline-key expiration is not a packet timestamp. Applications needing those properties must bind their service identifier, nonce/sequence, and authorization to their own signed/authenticated payload.

Thus the **hash** in a returned address identifies the signing identity; the complete hash/port tuple is not an authenticated service identity. Encrypted routing alone does not upgrade an unsigned format to this contract.

## 8. Unauthenticated packets

```go
type UnauthPacketConn struct { /* private state */ }

type UnauthPacket struct {
    ClaimedSource    Hash
    HasClaimedSource bool
    FromPort         uint16
}

func (d *Destination) ListenUnauthPacket(network, address string) (*UnauthPacketConn, error)
func (d *Destination) ListenUnauthPacketContext(ctx context.Context, network, address string) (*UnauthPacketConn, error)

func (c *UnauthPacketConn) ReadPacket(p []byte) (n int, packet UnauthPacket, err error)
func (c *UnauthPacketConn) WriteTo(p []byte, target Addr) (n int, err error)
func (c *UnauthPacketConn) LocalAddr() Addr
func (c *UnauthPacketConn) Close() error
func (c *UnauthPacketConn) SetDeadline(t time.Time) error
func (c *UnauthPacketConn) SetReadDeadline(t time.Time) error
func (c *UnauthPacketConn) SetWriteDeadline(t time.Time) error
func (c *UnauthPacketConn) MaxPayloadSize() int
```

`UnauthPacket` is metadata for the single datagram copied into the supplied buffer, not a buffer-owning object. It has no `Release` method, retained payload slice, `net.Addr` implementation, or automatic reply operation.

- Datagram3 always carries a 32-byte claimed hash and two-byte flags, followed by optional options and payload. `HasClaimedSource` is true even if the received claimed hash is zero. Both the hash and `FromPort` are untrusted. Outbound Datagram3 always claims this socket's Destination hash; no API permits arbitrary sender impersonation.
- Raw protocol 18 contains exactly the application bytes. `HasClaimedSource` is false and `ClaimedSource` is zero, regardless of any internal transport peer metadata. `FromPort` is outer, untrusted metadata; it is not a source address. Raw transmission also sets this socket's outer local port.
- Incoming Datagram3 framing/options are validated, but no authentication is asserted. Raw bytes are not interpreted as a Datagram1/2/3 envelope. Oversize or malformed packets are dropped under the common receive policy.

There is deliberately no `ReadFrom`, embedded `net.PacketConn`, `AsPacketConn`, or `Unauthenticated bool` switch on the authenticated socket. A caller cannot accidentally pass unsigned packets to code expecting this library's authenticated `PacketConn` boundary. Generic Go `net.PacketConn` itself makes no authentication promise; this separation is an IVNP API policy.

To send a reply to a Datagram3 claim, the application must explicitly construct an `Addr` after applying its own validation/admission policy. This conversion does not authenticate the claim. Blind echo or amplification to a claimed address is unsafe. Raw packets have no implicit reply target; an application needs a separately known destination or its own authenticated payload protocol.

Integrating unsigned packets with a library that requires `net.PacketConn` requires an application-owned adapter and an explicit trust decision. No adapter can invent a source for raw protocol 18. Use signed datagrams when generic reply-address semantics are required.

## 9. Common packet I/O contract

### 9.1 Message boundaries and memory

- One successful read consumes one datagram, including an empty datagram. Zero-length buffers also consume one datagram.
- If `len(p)` is smaller than the application payload, copy its prefix, consume/discard the remainder, and return `n = len(p)` with `ErrMessageTruncated`. Return the corresponding address/metadata even with this error. No remainder appears in the next read. A zero-length payload read into an empty buffer succeeds without truncation.
- No-data read failures return `n = 0`, nil authenticated address or zero unauthenticated metadata, and an error. A zero-length datagram is not EOF.
- Reads copy application bytes into caller storage before releasing/wiping the internal message. Returned address/metadata values survive later reads and close.
- Writes do not retain the caller's slice after return, including failure. Callers must not mutate it during the operation. Codecs operate on bounded storage; buffers do not dynamically grow in the bulk path.
- Successful `WriteTo` returns `len(p)` and nil, including zero for an empty payload. Failures return zero and an error; there is no successful short datagram write or retry of an application remainder.

### 9.2 Size limits

```go
const (
    MaxSendDatagramSize    = 32768
    MaxReceiveDatagramSize = 62690
)
```

These are **encoded datagram** limits, excluding outer I2CP compression, garlic, and transport framing. They describe this implementation's local policy, not a universal I2P application-payload limit or a remote peer's acceptance guarantee.

`MaxPayloadSize()` is the maximum local application write size for the socket's fixed format and signing identity. Outbound sockets emit no optional Mapping entries. Let D be the encoded sender identity length, S the long-term signature length, Kt the transient public-key length, and St the transient signature length:

| Format | Outbound overhead H | Maximum application write |
|---|---:|---:|
| Datagram1 | D + S | 32768 - H |
| Datagram2, online | D + 2 + S | 32768 - H |
| Datagram2, offline | D + 2 + 6 + Kt + S + St | 32768 - H |
| Datagram3 | 34 | 32734 |
| Raw | 0 | 32768 |

The six offline bytes are expiration and signing-key type; the target hash adds no wire overhead. Inbound canonical option mappings are accepted where the wire format permits them and stripped with the envelope; they contribute their full encoded length to the receive limit. Unknown flag bits are rejected. Wire-level custom options are not exposed by this facade.

Reject oversize writes with `ErrMessageTooLarge` before route lookup, signing, or transmission. Never split an application write into multiple datagrams. Underlying tunnels/transports may fragment one encoded datagram. Frame/encryption overhead may still cause an explicit send failure; do not promise peer delivery from the size check. Allocate `MaxReceiveDatagramSize` when a caller needs a buffer large enough for any admitted application payload; `MaxPayloadSize` is not an inbound bound because peer identity/options differ.

### 9.3 Queues and resource pressure

Every socket snapshots its Destination's PacketQueueConfig at bind. Account retained encoded datagram bytes, including framing, against both the per-socket and router-wide byte budgets. Count empty raw datagrams against MaxPackets. Reserve capacity before copying; charge buffers being verified until released. Bound pre-verification ingress through existing router ingress limits as well.

Overflow drops the newest incoming datagram without evicting already queued messages or blocking established-session forwarding. Packet receive is lossy even on local self-delivery. Do not return an inbound queue-overflow error as if the remote endpoint acknowledged rejection. Queue bounds do not provide delivery guarantees.

Close drains queued storage, wipes sensitive copies, and returns all reservations exactly once. Work already admitted to a closing socket cannot enqueue into a later socket reusing the same numeric port; binding ownership includes an installation lifetime.

### 9.4 Deadlines, cancellation, and send outcome

All socket methods are safe for concurrent use. Concurrent readers each receive one distinct dequeued datagram; no ordering between goroutines is promised. Writes remain whole datagrams but ordering is not promised.

SetDeadline changes both directions; the directional methods change only their direction. Deadlines are absolute. Zero clears the limit. A past deadline expires immediately. Updates wake blocked operations and apply to pending as well as future I/O; clearing/extending permits future attempts. An operation already returned as timed out is not resurrected.

Deadline failures wrap `os.ErrDeadlineExceeded` and satisfy `net.Error.Timeout()`. A context-limited constructor/dial/resolve/readiness failure preserves `context.Canceled` or `context.DeadlineExceeded` instead. Bind contexts do not become socket I/O contexts. Calls beginning after close return `net.ErrClosed`; an already-running operation racing close/deadline may report either winning cause.

A packet write's deadline and socket close bound admission, owner-bound LeaseSet/route preparation, resource waits, and transport submission. No new data-plane lookup or connection setup is introduced: preparation remains control-plane work, followed by prepared execution. A preexisting expired deadline fails before local self-delivery too.

Success means the complete datagram was locally submitted, not received or acknowledged by the peer. Failure/cancellation may occur after some underlying encrypted bytes or fragments were sent. It does not prove non-delivery. The facade MUST NOT resubmit after an ambiguous send failure or downgrade protocol to retry. Refresh/retry of route preparation before application transmission remains permissible within the deadline.

Transport cancellation may require retiring a shared encrypted session to protect framing/nonce state; the API does not promise zero collateral transport reconnects. It still must not close unrelated Destination objects or transfer their ownership.

## 10. Destination-only networking

The Router method set is limited to `Hash`, `NewDestination`, `WaitReady`, and `Close`. It does not implement a dial/listen interface and has no stream, packet, address-resolution, or service-address convenience methods.

There is no default Destination configuration, implicit application identity, first-created selection, default accessor, or fallback to another identity. Applications explicitly retain the Destination returned by `NewDestination` and use it for all I/O.

| Operation | Public owner |
|---|---|
| Create router infrastructure | `NewRouter` |
| Create application identity and await its readiness | `Router.NewDestination` |
| Obtain a service hostname | `Destination.B32` |
| Resolve a peer name/address | `Destination.ResolveAddr` |
| Dial or listen for streams | Destination, or a Destination-bound Dialer/ListenConfig |
| Bind signed or unsigned packet sockets | Destination, or a Destination-bound ListenConfig |
| Observe bound/connected addresses | Listener, connection, or packet socket |

Dialer and ListenConfig accept only an explicit Destination, never a Router. Creating or closing a sibling cannot change an existing socket's identity. Router still owns native transport sockets internally; removing application I/O methods does not remove its transport responsibilities.

## 11. Errors

Use `errors.Is`/`errors.As`, not message matching. Existing root stream errors retain their meanings. New sentinels are part of the target API:

| Error | Meaning |
|---|---|
| `ErrInvalidConfig` | Invalid static configuration; returned as `*ConfigError` |
| `ErrStateConflict` | Unsafe/incompatible existing embedded state; never regenerate identity |
| `ErrDestinationRequired` | Nil Destination in a collaborator |
| `ErrIdentityInUse` | Duplicate live/closing destination identity |
| `ErrUnsupportedIdentity` | Key/format/publication combination not supported |
| `ErrUnsupportedNetwork` | Network string not supported by this operation |
| `ErrAddressInvalid` | Malformed address or invalid remote target |
| `ErrAddressUnavailable` | Bind host is not this destination |
| `ErrAddressInUse` | Requested local binding/source port is occupied |
| `ErrNoPortsAvailable` | Ephemeral range exhausted |
| `ErrNameResolutionUnavailable` | Human name supplied without a resolver |
| `ErrResourceLimit` | Destination or packet-operation admission limit reached |
| `ErrMessageTooLarge` | Application write exceeds the format's local bound |
| `ErrMessageTruncated` | One consumed incoming payload did not fit the buffer |
| `net.ErrClosed` | Closed owner, stream, listener, or socket |
| `os.ErrDeadlineExceeded` | Stream/socket/dialer deadline expired |

```go
type ConfigError struct {
    Field string
    Err   error
}

func (e *ConfigError) Error() string
func (e *ConfigError) Unwrap() error
func (e *ConfigError) Is(target error) bool
```

ConfigError.Is matches ErrInvalidConfig; Unwrap preserves the underlying cause. Field is a stable Go field path such as `NTCP2.Bind` or `RemoteAccess[0].Identity`. Error strings, fields, and logs must not contain keys, secrets, credentials, or private payloads.

Dial/listen/packet failures use `*net.OpError` with operation `dial`, `listen`, `read`, or `write`, the selected network, and available public addresses. Preserve the underlying sentinel/cause, including truncation. Resolver and lifecycle failures retain causes without pretending to be packet I/O. Close combines independent cleanup failures using `errors.Join`.

## 12. Examples

Examples use `gosuda.org/ivnp` and the standard packages shown by the identifiers. Constructors may wait for local startup or destination readiness as specified above; callers must supply appropriate context bounds.

### 12.1 Static Router and explicit Destination

```go
func serve(ctx context.Context, handler http.Handler) (err error) {
    cfg := ivnp.DefaultRouterConfig()
    router, err := ivnp.NewRouter(ctx, cfg)
    if err != nil {
        return err
    }
    defer func() { err = errors.Join(err, router.Close()) }()

    dest, err := router.NewDestination(ctx, ivnp.DefaultDestinationConfig())
    if err != nil {
        return err
    }
    defer func() { err = errors.Join(err, dest.Close()) }()

    ln, err := dest.Listen("i2p", ":8080")
    if err != nil {
        return err
    }
    defer func() { err = errors.Join(err, ln.Close()) }()
    return (&http.Server{Handler: handler}).Serve(ln)
}
```

The application supplies a bounded construction context. Its cancellation after construction does not stop Serve; server shutdown is an explicit application action through `http.Server.Shutdown`, listener close, or owner close. Share `dest.B32()` with clients as the service hostname and the bound listener address when the service port is also needed.

The default configuration uses in-memory state and needs no data-directory setup. To opt into persistence before constructing the Router:

```go
func persistentRouterConfig(directory string) ivnp.RouterConfig {
    cfg := ivnp.DefaultRouterConfig()
    cfg.Persistence = &ivnp.PersistenceConfig{Directory: directory}
    return cfg
}
```

An empty directory makes NewRouter fail validation. This option preserves Router identity, not the transient Destination created by serve.

### 12.2 HTTP client on one identity

```go
func fetch(ctx context.Context, dest *ivnp.Destination, remoteB32 string) (err error) {
    transport := &http.Transport{DialContext: dest.DialContext}
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport}
    req, err := http.NewRequestWithContext(ctx, http.MethodGet,
        "http://"+net.JoinHostPort(remoteB32, "8080")+"/health", nil)
    if err != nil {
        return err
    }
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer func() { err = errors.Join(err, resp.Body.Close()) }()
    _, err = io.Copy(io.Discard, resp.Body)
    return err
}
```

Pass the remote service's `Destination.B32()` result as remoteB32; no name resolver is required for that B32 hostname. The HTTP transport supplies the `tcp` network to this local Destination's dialer. The transport intentionally has no environment-proxy function. HTTPS still performs normal TLS certificate validation; I2P does not disable it. Human-readable `.i2p` names remain available through an explicitly injected resolver.

### 12.3 Signed datagram exchange

```go
func exchange(dest *ivnp.Destination, target ivnp.Addr) (err error) {
    pc, err := dest.ListenPacket("i2p-datagram2", ":0")
    if err != nil {
        return err
    }
    defer func() { err = errors.Join(err, pc.Close()) }()
    if err = pc.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
        return err
    }
    if _, err = pc.WriteTo([]byte("request"), target); err != nil {
        return err
    }
    buffer := make([]byte, ivnp.MaxReceiveDatagramSize)
    _, _, err = pc.ReadFrom(buffer)
    return err
}
```

A production request/reply protocol must validate the responding identity and its own transaction nonce/service binding. The first received packet is not necessarily a response to the write.

### 12.4 Unsigned reception without an implicit reply

```go
func receiveUnsigned(dest *ivnp.Destination) (info ivnp.UnauthPacket, err error) {
    pc, err := dest.ListenUnauthPacket("i2p-datagram3", ":9000")
    if err != nil {
        return info, err
    }
    defer func() { err = errors.Join(err, pc.Close()) }()
    if err = pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
        return info, err
    }
    buffer := make([]byte, ivnp.MaxReceiveDatagramSize)
    _, info, err = pc.ReadPacket(buffer)
    return info, err
}
```

The returned ClaimedSource is unverified, including after successful parsing. Switching the network to `"i2p-raw"` produces metadata with no claimed source; code must use HasClaimedSource, not a zero-hash test, to distinguish them.

## 13. Ownership layers and migration

The new concrete Router/Destination are embedding facades, not aliases of the daemon Node or the L3 DestinationEndpoint interface. Their concrete Dialer, ListenConfig, and packet types are root-owned adapters. Root-specific return types MUST NOT be added to lower-layer interfaces.

Lifecycle composition belongs in L7; L5 owns identity registration, publication, lookup credentials, resolution/route policy, and route preparation; L4 owns installed execution, streaming, bounded queues, ratchets, nonces, replay/retransmission state, and established transport I/O. Necessary lower-layer capabilities use shared L3 types and canonical subsystem root imports. No L3/L4/L5 implementation imports `ivnp` to implement this facade.

Reuse existing datagram codecs and verification rules; do not implement a second wire format in the facade. The facade may orchestrate control-plane preparation, but packet bulk forwarding never performs implicit lookup or connection setup. Preserve authenticated-source and private-lookup provenance explicitly across asynchronous ingress; generic Delivery comments are not evidence of signature verification.

The root package exposes the embedding API only. Daemon callers use `node.NewSubsystem` with `state.ConfigurationOperating` and `node.Options`; configuration-file operations use the state subsystem. Advanced destination contracts live in `interfaces/destination`, legacy stream adapters in `interfaces/stream`, and wire/key helpers in foundation. Root `Node`, `New(Config, Options)`, configuration loaders, endpoint/controller aliases, legacy stream adapters, and base64/B32 helper re-exports are removed without compatibility shims. Named persistent destination management retains its existing semantics in the owning subsystem; it is not overloaded with endpoint construction or confused with Close. Each router instance has one lifecycle owner and one destination registry.

Daemon and embedded initialization use distinct identity policies. Embedded construction suppresses automatic named application destinations and migration while keeping tunnel services active; merely disabling daemon listeners would not establish that boundary.

Storage selection belongs at initialization and the state-ownership boundary. Reuse domain-specific state operations with memory and disk implementations; do not introduce a virtual filesystem or require temporary files for memory mode. In-memory state need not be serialized into encrypted file-format blobs; encryption and atomic file replacement belong at the disk boundary. Storage mode MUST NOT add branches, lookups, or locks to established stream/packet execution.

The embedded default is in-memory independently of daemon policy. The daemon may explicitly select persistent storage and keep its existing operational defaults. This change does not remove or silently relocate an existing daemon's state directory.

## 14. Contract verification

1. Static construction performs no configuration-file I/O and starts no daemon frontend; supplied configuration and key copies survive caller mutation after return.
2. The default in-memory mode performs no router-owned data-directory/file discovery, creation, reads, writes, or cache spill during construction, operation, close, or failure. Separate Router instances have independent identities/state; bounded NetDB/cache admission does not spill to disk under pressure. Collaborator I/O and OS/runtime facilities are outside this storage guarantee.
3. Constructor cancellation/failure releases owned resources; close joins workers; construction contexts do not control returned lifetimes; no child escapes concurrent Router close.
4. Router exposes no application stream/packet or default-Destination API and constructs no implicit application identity. Every socket is bound to its explicit Destination; sibling creation/closure cannot change that identity. Duplicate identity admission is atomic.
5. A service's Destination.B32 hostname connects through another Destination without a resolver; listener/connection addresses stringify to B32 host:port with the actual port. A real http.Transport invocation works with its `tcp` callback while an invalid/non-I2P address never triggers native DNS/TCP fallback. Listener setup cancellation does not terminate a returned listener.
6. Port allocation/binding handles collisions, exhaustion, rollback, protocol namespaces, accepted stream lifetimes, and close/rebind without stale ingress delivery.
7. PacketConn satisfies net.PacketConn; UnauthPacketConn does not. Unsigned constructors cannot be reached through authenticated network names and no fallback weakens authentication.
8. Real datagram codecs prove valid signatures, invalid signatures, wrong Datagram2 target, offline expiration, and untrusted Datagram3 claims. Tests do not assert nonexistent signed-port or replay guarantees.
9. Raw receive never fabricates a source, and Datagram3's zero claimed hash remains present. Encoded-size boundaries, empty packets, truncation, address lifetime, and caller-buffer reuse follow the common contract.
10. Deadline extension/clearing and Close wake already-blocked reads, route preparation, and writes; all owned buffers/queue reservations are released under overflow, cancellation, and concurrent close.
11. Packet writes report local submission only and do not resubmit after ambiguous failure. Private lookup credentials stay with their originating Destination.
12. Existing daemon management semantics and architecture-layer checks remain valid. Live peer interoperability for each claimed wire format is reported separately from in-memory codec or lifecycle evidence.
13. Explicit persistence rejects an empty directory, orphaned/corrupt state, and unavailable locks without key rotation or memory fallback; a fully absent state/key pair may be created. Constructing a new Router against the same valid directory preserves Router identity and releases locks even on failed construction/close.
14. In both modes, caller-supplied Destination keys preserve service address across Router reconstruction, while nil identities are transient and never enter durable named storage. Caller keys are never migrated or wiped by Router cleanup.
15. Exploratory and per-Destination inbound/outbound Hops, Count, Backup, and RenewBefore reach their owning builders/maintainers independently. Invalid ranges fail before construction; builders do not shorten paths implicitly. Backup promotion/replenishment, renewal with Backup 0, bounded overlap, publication lease limits, and cleanup preserve admitted circuit lifetimes. Readiness does not require a fully populated reserve.

## References

- [Issue #7: generic embedded transport facade](https://github.com/gosuda/IVNP/issues/7)
- [Go net contracts](https://pkg.go.dev/net)
- [Go HTTP Transport](https://pkg.go.dev/net/http#Transport)
- Repository wire authority: `dataplane/internal/datagram/datagram.go`, `dataplane/internal/datagram/modern.go`.
- Existing signature-verifying consumer: `client/internal/sam/datagram.go`.
- Existing key/policy ownership: `interfaces/destination/destination_interface.go`, `controlplane/internal/runtime/client_destination.go`, `foundation/internal/identity/address_generator.go`.
