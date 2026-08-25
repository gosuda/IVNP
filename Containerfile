# Official Java I2P router with SAM enabled for native live interoperability.
FROM geti2p/i2p@sha256:c6ddb2b47fe4afee1872325331655ffe3800775f26f8bfeff02ee6a0eb2bbee4 AS java-i2p
RUN sed -i 's/^clientApp\.1\.startOnLoad=false$/clientApp.1.startOnLoad=true/' /entrypoint/i2p-config-templates/clients.config

# The multi-architecture digest resolves to the immutable linux/amd64 manifest
# sha256:6033334f349f3912236ed6a06c5ed066605e58632dc415779b0d00a1568afa8d.
FROM golang:1.27-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466 AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM go-build AS soak-build
RUN mkdir -p /out && \
    CGO_ENABLED=0 go build -trimpath -o /out/ivnp ./command/ivnp && \
    CGO_ENABLED=0 go build -trimpath -o /out/ivnp-soak ./integration/soak

# Export-only image used by scripts/live-interop-soak.sh. The script copies both
# binaries once, hashes them, and never rebuilds during a measured run.
FROM scratch AS soak-binaries
COPY --from=soak-build /out/ivnp /ivnp
COPY --from=soak-build /out/ivnp-soak /ivnp-soak

# Preserve the repository's ordinary container verification behavior as the
# default target while keeping the live public-network campaign opt-in.
FROM go-build AS verification
RUN go test ./...
ENV IVNP_SAM_INTEGRATION=0
CMD ["go", "test", "-tags=integration", "-count=1", "-run=TestJavaI2P", "-timeout=6m", "./service/sam"]
