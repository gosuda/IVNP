# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Build Stage
# Usage (run from git repository root):
#   docker build -f cmd/ivnp-reseed/Dockerfile -t ivnp-reseed .
# ------------------------------------------------------------------------------
FROM golang:alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=active-distroless" \
    -o /bin/ivnp-reseed \
    ./cmd/ivnp-reseed

# Prepare empty persistent data directory with nonroot permissions (UID/GID 65532)
RUN mkdir -p /data && chown -R 65532:65532 /data

# ------------------------------------------------------------------------------
# Runtime Stage: Google Distroless Static
# Hardened, zero-shell, zero-package-manager, non-root (65532:65532)
# ------------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/ivnp-reseed /ivnp-reseed
COPY --from=builder --chown=nonroot:nonroot /data /data

USER nonroot:nonroot
WORKDIR /data
VOLUME ["/data"]

# RESEED_SIGNER_ID: SU3 signer common name shown to clients.
# RESEED_SEED_PHRASE: seed phrase deriving the RSA-4096 signing key
# deterministically (RESEED_SEED_KDF → det-keygen). No key file is used; the
# phrase is the only backup. Without it an ephemeral key is generated on each start:
#   docker run -e RESEED_SEED_KDF=argon2id-v2 -e RESEED_SEED_PHRASE="<saved random phrase>" ...
# Generate the phrase once (for example: openssl rand -base64 32) and keep it.
# RESEED_SEED_KDF: hkdf-sha512 (legacy default, unstretched) or argon2id-v2
# (stretched, salted with the signer ID, phrase of at least 32 characters).
# Changing it changes the signing key; see README "Seed Phrase Derivation Versions".
# Prefer env over -seed-phrase so the phrase stays out of the command line.
ENV RESEED_SIGNER_ID="reseed@ivnp.network"

EXPOSE 8080 8443

# Self-contained healthcheck using binary's built-in -healthcheck flag (no shell or wget needed)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/ivnp-reseed", "-healthcheck", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/ivnp-reseed"]
CMD ["-listen", ":8080", "-data-dir", "/data", "-target", "1024", "-interval", "10m"]
