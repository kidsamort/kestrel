# kestrel-sync — one static binary, one volume.
#
# Build context is the repository root:
#   docker build -f deploy/Dockerfile -t kestrel-sync .
#
# The workspace manifest lists every desktop crate, so the manifests and sources
# are copied whole; only the `kestrel-sync` package is built, and nothing from
# Tauri or the shell is compiled or linked. `target/` and `gen/` are never
# copied, which is why this file lists paths instead of copying the repository
# wholesale.
FROM rust:1.90-alpine AS builder

# rusqlite's `bundled` feature compiles SQLite from source; that needs a C
# compiler, and the musl target needs its headers.
RUN apk add --no-cache gcc musl-dev

WORKDIR /src

COPY src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/build.rs src-tauri/tauri.conf.json ./src-tauri/
COPY src-tauri/capabilities ./src-tauri/capabilities
COPY src-tauri/icons ./src-tauri/icons
COPY src-tauri/src ./src-tauri/src
COPY src-tauri/core ./src-tauri/core
COPY src-tauri/cli ./src-tauri/cli
COPY src-tauri/mcp ./src-tauri/mcp
COPY src-tauri/nmhost ./src-tauri/nmhost
COPY src-tauri/passkey ./src-tauri/passkey
COPY src-tauri/net ./src-tauri/net
COPY src-tauri/engine ./src-tauri/engine
COPY src-tauri/sync ./src-tauri/sync

# `--locked`: an image must build from the committed dependency set, not from
# whatever the registry resolved that day.
RUN cargo build --release --locked -p kestrel-sync --manifest-path src-tauri/Cargo.toml

FROM alpine:3.20

RUN addgroup -S -g 10001 kestrel \
    && adduser -S -u 10001 -G kestrel kestrel \
    && mkdir -p /data \
    && chown kestrel:kestrel /data

COPY --from=builder /src/src-tauri/target/release/kestrel-sync /usr/local/bin/kestrel-sync

# Plain HTTP is deliberate: TLS belongs to the reverse proxy in front of this
# container. Binding all interfaces is what makes it reachable from the proxy;
# the compose file publishes it on loopback only.
ENV KESTREL_SYNC_ADDR=0.0.0.0:8787 \
    KESTREL_SYNC_DB=/data/kestrel-sync.db \
    KESTREL_SYNC_BLOBS=/data/blobs

# The database and the blob directory must be on the same volume: a backup is
# both, and one without the other is not a working service.
VOLUME ["/data"]
EXPOSE 8787

USER 10001:10001

# The service handles SIGTERM and stops accepting new connections; requests in
# flight finish.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/kestrel-sync"]
