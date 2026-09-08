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

IVNP creates `ivnp.conf` if it does not exist. Unspecified options use defaults.
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

Import `gosuda.org/ivnp`. See [the Go examples](example_test.go) for starting a
router and opening an I2P connection. Close the router and connections when your
application is finished with them.

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
