# Embedded Router Architecture

`router.Router` is an embedded owner, not a daemon singleton. Construction has no I/O; `Start(context.Context)` owns socket binds, address publication, transport start, reseed work, cancellation, and shutdown ordering. `Close` is idempotent and closes listeners/packet sockets before canceling workers so blocking native calls are released. `Wait` returns the first terminal runtime error.

## Network boundary

The router depends on `SocketRuntime`, not concrete TCP or UDP types:

```go
type SocketRuntime interface {
    ListenStream(context.Context, Endpoint) (net.Listener, error)
    DialStream(context.Context, Endpoint) (net.Conn, error)
    ListenPacket(context.Context, Endpoint) (net.PacketConn, error)
}
```

`NativeSocketRuntime` delegates to `net.ListenConfig` and `net.Dialer`. Alternative overlay backends can interpret `Endpoint` without changing router lifecycle ownership. No Yggdrasil endpoint, configuration field, or publication path exists.

`AddressPublisher` generates RouterInfo address options independently from socket binding. NAT-PMP and UPnP results feed the publisher; binding a port alone never proves reachability.

For an enabled transport, an omitted `advertise_port` or `advertise_port = 0`
selects automatic mapping. The router binds first, so `bind_port = 0` maps the
kernel-selected port. Automatic publication requires a non-loopback bind
address. NAT-PMP is attempted before UPnP; a non-zero static advertised
endpoint bypasses both. Gateway discovery is automatic unless `[nat]`
provides `natpmp_endpoint = 10.2.0.1:5351` or
`upnp_endpoint = http://192.168.0.1/rootDesc.xml`. NAT-PMP renewal uses the
gateway-granted lifetime rather than the requested two minutes and renews at
two-thirds of that grant.
Mapping loss removes the endpoint and republishes the RouterInfo as
firewalled; shutdown explicitly removes live mappings.

Binding both transports to loopback with port `0` is the explicit client-only
shape. NTCP2 remains available for outbound sessions, no public transport
endpoint is advertised, and automatic NAT-PMP/UPnP mapping is disabled.

For public NTCP2 interoperability, configure `LocalRouterInfoConfig.RouterVersion`
to a maintained I2P router version. Native peers reject a RouterInfo without a
compatible `router.version`; IVNP does not invent one on the application's behalf.

## Public I2P stream API

`ivnp.Dialer` and `ivnp.ListenerConfig` call a `StreamNetwork`; they never map
an `.i2p` address to native TCP. `router.DestinationManager` is the embedded
implementation: it owns one or more isolated `DestinationSession` instances,
each backed by the bounded tunnel Streaming runtime. A manager or session may
be passed directly to the public API after its tunnel sender and inbound
delivery path have been wired.

Before an outbound tunnel build, the builder sends the selected inbound
reply-gateway RouterInfo to the outbound endpoint. The same rule applies to a
DatabaseLookup sent with a tunnel reply route: the queried floodfill receives
the reply-gateway RouterInfo first. This prevents remote endpoints from timing
out while trying to route a reply using only a router hash and tunnel ID.

## Startup order

1. Create the router child context.
2. Bind configured stream and packet endpoints through `SocketRuntime`.
3. Snapshot/publish local addresses through `LocalInfo`.
4. Start `TransportManager` with owned bindings.
5. Start bounded reseed work through the existing verified `reseed.Client` path.

Any startup failure rolls back every acquired socket/resource. Shutdown reverses ownership: listeners and packet sockets, transport manager, context cancellation, workers, then final status.
