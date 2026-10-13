# IVNP

[![Go: Reference](https://badge-api.gosuda.org/badge.svg?label=Go&message=Reference&style=old-school&size=200&letterSpacing=0&labelColor=292724&color=007d9c&labelTextColor=ffffff&textColor=ffffff)](https://pkg.go.dev/gosuda.org/ivnp)

I2P router for Go. Runs as a standalone daemon or an embedded library.
Includes SAM v3.3, HTTP and SOCKS5 proxies, and a local address book.

Requires Go 1.27+.

## Daemon

### Install and Run

```sh
go install gosuda.org/ivnp/cmd/ivnpd@latest
ivnpd -config ivnp.conf
```

Or from source:

```sh
go run ./cmd/ivnpd -config ivnp.conf
```

- Web console: `http://127.0.0.1:7070`
- SAM bridge: `127.0.0.1:7656`

The embedded SAM bridge advertises `IVNP_AUTH=1` in its HELLO reply. After
`SESSION CREATE`, send `SESSION AUTH` on the owning control socket to obtain a
256-bit capability (`IVNP_AUTH=<64 hexadecimal characters>`). Separate TCP
connections must include that option with `STREAM CONNECT`, `STREAM ACCEPT`,
`STREAM FORWARD`, `DATAGRAM SEND`, and `RAW SEND`. Include it in the SAM UDP
header as well, for example `3.3 my-id destination IVNP_AUTH=<token>` followed
by a newline and the datagram body. Commands on the owning control socket
retain access to that session and its PRIMARY children without an extra token.

This security extension is required for third-party clients using detached
connections with the embedded SAM bridge. The bundled SAM client negotiates it
automatically, while external SAM bridges without this extension remain
supported. Keep the capability confidential; closing the owning control socket
revokes it.

### Configuration

The daemon generates `ivnp.conf` on first start if missing.
By default, state and router keys are stored in `./data`.

To configure a custom data path:

```ini
[paths]
data_dir = /path/to/ivnp-data
```

CLI flags:
- `-webui-listen <addr:port>`: Change web console bind address (default `127.0.0.1:7070`)
- `-webui=false`: Disable web console

## Embedded Library

```sh
go get gosuda.org/ivnp
```

`ivnp.NewRouter` runs fully in-memory by default without creating disk files. Network traffic is routed through application-managed `Destination` instances.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

cfg := ivnp.DefaultRouterConfig()
router, err := ivnp.NewRouter(ctx, cfg)
if err != nil {
    return err
}
defer router.Close()

dest, err := router.NewDestination(ctx, ivnp.DefaultDestinationConfig())
if err != nil {
    return err
}
defer dest.Close()

listener, err := dest.ListenContext(ctx, "i2p", ":8080")
if err != nil {
    return err
}
defer listener.Close()

fmt.Println(net.JoinHostPort(dest.B32(), "8080"))
```

### Persistence and Identity

To persist router state across restarts, set `cfg.Persistence`:

```go
cfg.Persistence = &ivnp.PersistenceConfig{Directory: "./router-data"}
```

Ephemeral destinations are not written to disk. For a persistent service address, supply a fixed `DestinationConfig.Identity`.

### Dialing

Connect to a remote service using `dest.DialContext(ctx, "i2p", addr)`.
B32 addresses (`*.b32.i2p`) route directly without a resolver. Resolving human-readable `.i2p` hostnames requires setting `RouterConfig.Resolver`.

See [examples](example_test.go) for complete usage patterns.

## Development

```sh
go test ./...
go test -race ./...
go run gosuda.org/ivnp/tools/importformatter -write
gojgp lint ./...
```

### Integration Tests

The HTTP proxy round-trip integration test requires a running SAM bridge:

```sh
IVNP_EEPSITE_PROXY=http://127.0.0.1:4444 IVNP_SAM_ADDRESS=127.0.0.1:7656 \
  go test -tags=integration -run '^TestHTTPProxyCompletesI2PChallengeRoundTrip$' \
  -count=1 -timeout=12m .
```

## License

[MIT](LICENSE)
