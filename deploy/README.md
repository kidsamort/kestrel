# Self-hosting Kestrel sync

One container, one volume, one SQLite file and a directory of ciphertext blobs.
The service stores no readable vault content — the wire contract and the threat
model are in [`PROTOCOL.md`](../PROTOCOL.md).

> **Verified once, with Podman.** The image was built and the container run on
> 2026-11-15 with `podman 6.1.4` on Windows/WSL2 (`podman build` +
> `podman run`, not compose): the service answers `401` with
> `x-kestrel-protocol: 1`, creates `kestrel-sync.db` and `blobs/` on the volume,
> runs as uid 10001, and a write to the container's root filesystem is refused
> (`Read-only file system`). The image is 12.3 MB.
>
> The `docker compose` commands below were **not** run: Docker is not installed
> on that machine, and the compose path was exercised only through
> `podman-compose 1.6.0`'s presence. Treat the first compose run as a bug hunt
> and tell us what breaks.
>
> One real bug was found by that first build: the Dockerfile's copy list had
> gone stale and omitted `src-tauri/net` and `src-tauri/engine`, so
> `cargo build` failed on the workspace manifest. It is fixed here.

## Three commands to a running self-host

### Without compose (Podman or Docker, verified)

```sh
# 1. Build the image from the repository root.
podman build -f deploy/Dockerfile -t kestrel-sync:0.1 .

# 2. Run it with the same flags the compose file uses.
podman run -d --name kestrel-sync \
  -p 127.0.0.1:8787:8787 \
  -v kestrel-sync-data:/data \
  --read-only --tmpfs /tmp \
  --security-opt no-new-privileges \
  kestrel-sync:0.1

# 3. Prove it is up: 401 means the route exists and authentication is enforced.
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/v1/sync/state
```

### With compose

From the repository root:

```sh
# 1. Build the image and start the service with its volume.
docker compose -f deploy/docker-compose.yml up -d --build

# 2. Prove it is up: 401 means the route exists, the service answers, and
#    authentication is enforced (there is no anonymous read).
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/v1/sync/state

# 3. Watch the log while you point a client at it.
docker compose -f deploy/docker-compose.yml logs -f kestrel-sync
```

Step 2 prints `401`. Anything else is a failure: `000` means nothing is
listening, and `404` means you reached a different server.

The service speaks plain HTTP. Do not expose `8787` to the internet; put a TLS
proxy in front of it (see below). The compose file already publishes the port on
loopback only.

## Configuration

Everything is environment variables. Unset means the default.

| Variable | Default | Meaning |
|---|---|---|
| `KESTREL_SYNC_ADDR` | `127.0.0.1:8787` | listen address |
| `KESTREL_SYNC_DB` | `kestrel-sync.db` | SQLite database file |
| `KESTREL_SYNC_BLOBS` | `blobs/` beside the database | ciphertext directory |
| `KESTREL_SYNC_MAX_BODY` | `4194304` | largest request body in bytes (minimum 1024) |
| `KESTREL_SYNC_MAX_ACCOUNTS` | `0` | account cap, `0` = unlimited |

The container sets the first three to paths under `/data`, which is the volume.
Exit codes: `0` clean shutdown, `2` bad configuration, `3` the database or the
listener could not be opened.

## TLS and the reverse proxy

Terminate TLS at a proxy and forward the request target unchanged — the request
signature covers the exact path and query string, so a proxy that rewrites
`/v1/sync/pull` or appends a trailing slash will turn every request into a `401`.

Caddy on the host:

```caddyfile
sync.example.com {
    reverse_proxy 127.0.0.1:8787
    request_body {
        max_size 4MB
    }
}
```

If the proxy is a service in the same compose project, remove the `ports:` block
from `deploy/docker-compose.yml` and proxy to `http://kestrel-sync:8787`. In that
case the service is only reachable on the compose network, which is what you
want.

Rate limiting belongs at the proxy too: `POST /v1/accounts` is unauthenticated
by design, so a public instance should either set
`KESTREL_SYNC_MAX_ACCOUNTS` or limit account creation per source address.

## Storage and backup

The volume holds exactly two things and both are required:

```
/data/kestrel-sync.db     SQLite database (accounts, devices, offers, item rows)
/data/blobs/ab/<sha256>   ciphertext, content-addressed
```

Back up by stopping the service and copying the volume; a running SQLite
database has a `-wal` file that is part of the state. Restore the database and
the blob directory together, then start the service. The exact commands are in
[`PROTOCOL.md` § Self-host runbook](../PROTOCOL.md#self-host-runbook).

The archive is not plaintext, but it is the complete account state: treat it as
sensitive, encrypt it at rest, and test a restore before you need one.

The container runs as uid/gid `10001`. A named volume inherits that ownership
from the image, which is why the compose file works without further setup. If
you replace the volume with a host bind mount, `chown -R 10001:10001` the
directory first or the service will fail to open the database.

## Upgrading

```sh
docker compose -f deploy/docker-compose.yml up -d --build
```

Take a backup first; a release that changes the schema migrates in place at
startup. The schema version is recorded in the `meta` table.

## What this deployment does not do

No TLS inside the container, no rate limiting, no login or billing, no device
revocation (v1 has no endpoint for it), and no automatic garbage collection of
unreferenced blobs. Each of those is a deliberate boundary described in
`PROTOCOL.md`, not a missing part of the build.
