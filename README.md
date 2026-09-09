# IVNP

An I2P router for Go applications. Run it as a daemon or embed it in your app.
Includes a SAM bridge, HTTP and SOCKS5 proxies, and an address book.

Requires **Go 1.27 or newer**.

## Run the router

```sh
go install gosuda.org/ivnp/cmd/ivnpd@latest
ivnpd -config ivnp.conf
```

From a source checkout, use `go run ./cmd/ivnpd -config ivnp.conf` instead.

- Open the router console at **http://127.0.0.1:7070**.
- Point SAM-compatible applications at **127.0.0.1:7656**.
- The first I2P connection may take several minutes. Keep the router running
  while it connects to peers and prepares tunnels.
- Press **Ctrl+C** to stop.

The console and SAM bridge listen locally by default. HTTP and SOCKS5 proxies
must be enabled in the configuration before use.

## Configuration and saved data

The daemon creates `ivnp.conf` if it does not exist. Unspecified options use defaults.
Router data is saved in `./data`, relative to the directory where you start it.
To choose another location:

```ini
[paths]
data_dir = /path/to/ivnp-data
```

Keep configuration and saved data private. Stop the router before backing them
up, and do not share one data directory between running instances. On Windows,
use a local NTFS drive.

Use `-webui-listen 127.0.0.1:8080` to change the console address or `-webui=false`
to disable it. Review access controls before exposing any service beyond your
machine.

## Use in a Go application

```sh
go get gosuda.org/ivnp
```

The embedding API starts in memory: it creates no config files, state directories,
or default application identity. Create a Destination before opening streams or
packet sockets; the Router itself has no networking methods.

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

Import `gosuda.org/ivnp` and the standard `context`, `time`, `net`, and `fmt`
packages for this snippet. Destination construction waits for its tunnels and
confirmed publication, so use a bounded context. Successful constructors
transfer lifetime ownership to the returned object; later context cancellation
does not close it.

To retain router state across runs, explicitly set
`cfg.Persistence = &ivnp.PersistenceConfig{Directory: "./router-data"}` before
`NewRouter`. This does not persist automatically generated application
Destinations; supply an application-owned identity through
`DestinationConfig.Identity` when a stable service address is required.

Share `dest.B32()` and a port with clients. Connect through a Destination with
`dest.DialContext(ctx, "i2p", serviceAddress)`. Human-readable `.i2p` names require
an explicitly supplied `RouterConfig.Resolver`; B32 addresses need no resolver.
See [the Go examples](example_test.go) and [the API contract](API.md).

ECIES receive windows look ahead **512 tags** by default and retain bounded
history for packet loss and reordering. This does not change the I2P wire format.

## Development

```sh
go test ./...
go test -race ./...
go run gosuda.org/ivnp/tools/importformatter -write
gojgp lint ./...
```

Storage security checks run on Linux, macOS, and Windows. Windows-only checks
stay on Windows; Windows arm64 also has a cross-build check.

## License

[MIT](LICENSE)
