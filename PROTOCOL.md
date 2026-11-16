# Kestrel sync protocol, version 1

This document is the wire contract between a Kestrel device and a sync service.
It is enough to write a server, to write a client, and to run one for yourself.
The reference server is `src-tauri/sync` (crate `kestrel-sync`); the deploy
files are in `deploy/`.

The service is **server-blind**: it stores ciphertext it cannot read, the
metadata a merge needs, and nothing else. That claim is enforced by the schema,
not just by policy — see [What the server can see](#what-the-server-can-see) and
the `schema_has_no_content_columns` test.

- Transport: JSON over HTTP/1.1 on a configured port. TLS is terminated by a
  reverse proxy in every supported deployment; the service itself speaks plain
  HTTP.
- Encoding: UTF-8 JSON bodies, lowercase hex for ids, keys, nonces, signatures
  and ciphertext, standard base64 for the sealed envelope.
- Protocol version: `1` (see [Version negotiation](#version-negotiation)).

## Contents

1. [Data model](#data-model)
2. [Encoding conventions](#encoding-conventions)
3. [Authentication](#authentication)
4. [Endpoints](#endpoints)
5. [The merge rule](#the-merge-rule)
6. [What the server can see](#what-the-server-can-see)
7. [Threat model](#threat-model)
8. [Storage layout](#storage-layout)
9. [Self-host runbook](#self-host-runbook)
10. [Version negotiation](#version-negotiation)
11. [Limits and error codes](#limits-and-error-codes)

---

## Data model

```
Account
  account_id            32 hex chars (16 random bytes), chosen by the creating device
  devices               one or more
  items                 one row per item, plus tombstones

Device
  device_id             32 hex chars, chosen by the device
  device_signing_pub    Ed25519 public key, 32 bytes; every request is signed with it
  device_agreement_pub  X25519 public key, 32 bytes; receives the sealed account key
  device_name           human label, 1..=128 characters, shown in other devices' UI
  created_at            server time, unix seconds
  revoked_at            server time when the account withdrew this device's access;
                        absent while the device may sign

Item
  item_id               opaque client-chosen id, 1..=128 chars [A-Za-z0-9_-]
  clock                 version vector: { device_id -> counter }
  deleted               false = live, true = tombstone
  ciphertext            the sealed item body, opaque bytes, hex on the wire
```

The account key hierarchy — how the account key is wrapped to
`device_agreement_pub` and how item keys are derived — is client-side and not
part of this protocol. The server handles `sealed` blobs it cannot open.

## Encoding conventions

| Field | Encoding | Exact shape |
|---|---|---|
| `account_id`, `device_id`, `new_device_id` | lowercase hex | 32 characters (16 bytes) |
| clock keys (device ids) | lowercase hex | 32 characters |
| `device_signing_pub`, `device_agreement_pub` | lowercase hex | 64 characters (32 bytes) |
| `code_hash` | lowercase hex | 64 characters (SHA-256) |
| `nonce` | lowercase hex | 32 characters (16 random bytes) |
| `signature` | lowercase hex | 128 characters (64 bytes) |
| `ciphertext`, `sealed` (decoded) | hex / base64 | opaque bytes |
| counters, `seq`, timestamps, `limit`, `since` | JSON integer | `u64`, except `expires_at`/`created_at` which are unix seconds |
| `device_name` | UTF-8 | 1..=128 characters after trimming, control characters rejected, whitespace-only refused |
| `code` (claim) | UTF-8 | 1..=256 characters; the printed code is 52 base32 characters plus dashes |

Uppercase hex is accepted for ids, clock keys and `code_hash` and is normalised
to lowercase: they are identifiers compared as values. Three fields are
different. A **nonce must be lowercase**: normalising it would let a captured
request be replayed with different capitalisation and slip past the replay set
that is keyed on the nonce string. A **signature is decoded as bytes**, so its
case carries no meaning and either case parses. Clock counters and timestamps
are integers and have no case.

Unknown members in a request body are **rejected** (`400 invalid_body`);
unknown query parameters are ignored. A request body must be a JSON object
exactly as specified.

`item_id` is chosen by the client. The server never interprets it beyond
checking the alphabet, and it never appears in a URL.

## Authentication

Every request except `POST /v1/accounts` and `POST /v1/enroll/claim` carries:

```
Authorization: Kestrel <device_id>.<unix_seconds>.<nonce>.<signature>
```

The four fields are separated by a single `.` and there are no spaces inside the
token. Example (the signature here is 128 zeros — it has the right shape and
will not verify):

```
Authorization: Kestrel 0a1b2c3d4e5f60718293a4b5c6d7e8f9.1731686400.9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The signed bytes are exactly this string, UTF-8, with no trailing newline:

```
kestrel-sync/v1\n
<METHOD>\n
<path?query>\n
<hex(sha256(raw request body))>\n
<unix_seconds>\n
<nonce>
```

* `METHOD` is the request method, uppercase, as sent (`GET`, `POST`).
* `path?query` is the **exact request target as sent**, starting with `/`, with
  no scheme or host. If there is no query, it is just the path. A proxy that
  rewrites the path (adding a trailing slash, collapsing `//`) will break
  signatures; configure it to pass the request target unchanged.
* The body digest is `hex(sha256(body))` of the raw bytes; for a body-less
  request it is the SHA-256 of the empty string,
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
* `unix_seconds` is the same value as in the header.
* `nonce` is the same value as in the header.

The signature is `Ed25519(device_signing_priv, the bytes above)`.

Worked example for `GET /v1/sync/pull?since=0&limit=200` with an empty body:

```
kestrel-sync/v1
GET
/v1/sync/pull?since=0&limit=200
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
1731686400
9f2c4a1b8e6d0f3a5c7b9d1e2f4a6b8c
```

The server rejects a request when:

| Condition | Status | `error` |
|---|---|---|
| header missing or unparseable | `401` | `unauthorized` |
| device id is not registered | `401` | `unknown_device` |
| signature does not verify | `401` | `bad_signature` |
| `abs(now - unix_seconds) > 300` | `401` | `stale_timestamp` |
| `(device_id, nonce)` was already used | `401` | `replay` |

Replay protection is an in-memory, bounded, per-device set of nonces. A nonce is
consumed only after its signature verifies, so a forged request cannot burn a
real one. The set is not durable: after a restart, a request captured within the
last 300 seconds could be accepted once. That residual window is stated here
rather than papered over; keep the timestamp window short and terminate TLS at
the proxy so captures are not trivial.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/accounts` | no | create an account and its first device |
| `POST` | `/v1/enroll/offer` | yes | existing device offers a code and sealed key to a new device |
| `POST` | `/v1/enroll/claim` | no | new device redeems the code, receives the sealed key |
| `POST` | `/v1/enroll/ack` | yes | existing device confirms the new device |
| `POST` | `/v1/sync/push` | yes | send local operations, receive conflicts |
| `GET` | `/v1/sync/pull` | yes | read operations after a sequence number |
| `GET` | `/v1/sync/state` | yes | account summary |
| `DELETE` | `/v1/devices/<id>` | yes | withdraw another device's access |

Every response carries `Content-Type: application/json`,
`Cache-Control: no-store` and `X-Kestrel-Protocol: 1`. Errors are
`{"error": "<code>", "message": "<human text>"}`; clients branch on `error`,
never on `message`. A route that exists but not for that method returns `405`
with an `Allow` header.

### `POST /v1/accounts`

Creates the account and its first device. Unauthenticated: this is the request
that creates the identity everything else is signed with. The account id and
device id are chosen by the client, so the server never has to invent an
identity for a device it cannot yet trust.

Request:

```http
POST /v1/accounts
Content-Type: application/json
X-Kestrel-Protocol: 1

{
  "account_id": "00112233445566778899aabbccddeeff",
  "device_id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "device_signing_pub": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "device_agreement_pub": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  "device_name": "Ana's laptop"
}
```

Response `201`:

```json
{
  "account_id": "00112233445566778899aabbccddeeff"
}
```

- `409 account_exists` — that `account_id` is registered already.
- `409 device_conflict` — that `device_id` is registered to another account.
- `403 account_limit` — the server's `KESTREL_SYNC_MAX_ACCOUNTS` is reached.
- `400 invalid_field` — an id, key or name failed validation. In particular
  `device_signing_pub` must be a valid, non-weak Ed25519 public key: the server
  verifies with `verify_strict`, so a small-order key could never authenticate,
  and storing one would create a device that is permanently broken.
- `400 invalid_body` — not a JSON object with exactly the fields above.

`device_agreement_pub` is stored as 32 opaque bytes; the server does not (and
cannot) check that it is a valid X25519 point. The client that seals the account
key is the one that cares.

### `POST /v1/enroll/offer`

An existing device of the account posts the hash of a short code and the sealed
account key for the new device. The code itself never reaches the server
(`code_hash = hex(sha256(code))`), so reading the database does not reveal it.

Request (authenticated, body as above):

```json
{
  "code_hash": "4a8eec4925826f4b60526d7ac3c0a9b61ef54ac19233bafce2f4a13eb49395d2",
  "sealed": "c2VhbGVkLWFjY291bnQta2V5",
  "expires_at": 1731687000,
  "new_device_id": "1a2b3c4d5e6f708192a3b4c5d6e7f809"
}
```

Response `200`:

```json
{}
```

- `expires_at` must be in the future and at most 3600 seconds from the server's
  clock; otherwise `400 invalid_field`.
- `sealed` is base64, non-empty, at most 64 KiB.
- `new_device_id` must not be the device making the offer.
- Re-posting an offer for the same `(account, new_device_id)` **replaces** the
  previous one and clears any unacknowledged claim: this is how a retry with a
  fresh code works after an expiry or a dropped connection.
- `409 already_enrolled` — that device is already a device of this account (or
  its offer was already acknowledged).

An offer is scoped to `(account_id, new_device_id)`: a claim must present both
the code hash and the device id, so a code cannot be redeemed by a device other
than the one the existing device named.

### `POST /v1/enroll/claim`

The new device redeems the code. Unauthenticated: it has no registered key yet,
and the code is its credential.

Request:

```json
{
  "code": "SCMD-EGZL-WINB-XGGC-26KW-JG6V-VSCW-BZA3-2ER2-6NFD-U4GQ-PE2P-UMDQ-O",
  "device_id": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
  "device_signing_pub": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  "device_agreement_pub": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  "device_name": "Ana's phone"
}
```

Response `200`:

```json
{
  "account_id": "00112233445566778899aabbccddeeff",
  "sealed": "c2VhbGVkLWFjY291bnQta2V5",
  "devices": [
    {
      "device_id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      "device_name": "Ana's laptop",
      "created_at": 1731686000
    }
  ]
}
```

- `sealed` is the base64 envelope exactly as it was stored, so the new device
  can unwrap it with `device_agreement_priv`. It is the only reason a claim is
  answered at all.
- `devices` lists the account's devices **at claim time, excluding the claiming
  device** — the new device is not a device yet.
- `400 invalid_code` — no unexpired offer for that `(code_hash, device_id)`.
- `400 expired_code` — the offer exists but `expires_at` has passed.
- `409 already_enrolled` — that device is already enrolled.

A successful claim does **not** create a device. Until `ack`, the new device's
public key is stored on the offer row and cannot authenticate anything. That
ordering is what makes an abandoned enrolment leave no half-device behind.

### `POST /v1/enroll/ack`

An existing device confirms the claim, which creates the device row.

Request (authenticated):

```json
{
  "new_device_id": "1a2b3c4d5e6f708192a3b4c5d6e7f809"
}
```

Response `200`:

```json
{}
```

- `400 unknown_offer` — no offer for that device in this account.
- `400 not_claimed` — the new device has not claimed the offer.
- `400 expired_code` — the offer expired; the enrolment must be restarted.
- Repeating a successful `ack` returns `200 {}` (idempotent retry).

After ack, the new device's Ed25519 key verifies requests and it appears in
`state` and in later claims' `devices` lists.

### `DELETE /v1/devices/<id>`

Withdraws one other device's access inside the caller's account. Authenticated
like every data route. `<id>` is 32 hex characters, lower-case on the wire.

Response `200`:

```json
{
  "device_id": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
  "revoked_at": 1731686000
}
```

- The device row is **kept** with `revoked_at` set. `devices` in `state` and in
  later `claim` responses report the timestamp; a live device omits the member.
  The row is the audit trail of what was enrolled and when its access ended.
- From then on every request signed by the revoked device — including
  `push`, `pull` and `state` — returns `403 device_revoked`. The signature is
  still verified first, so only a device that actually holds the key learns
  that it was revoked.
- Repeating the request is idempotent: `200` with the original `revoked_at`.
- `400 invalid_field` — the id is malformed, or the caller tried to revoke
  itself. No account may end up with no device that can sign.
- `404 not_found` — no such device in the caller's account. A device in another
  account is reported the same way, so the route is not an existence oracle.

**What this does not do.** The revoked device keeps the account key it was
given and every byte it already pulled. This endpoint stops new requests; it is
not a key rotation and it cannot erase a copy. The client UI says so on the
card, and account-key rotation remains separate work (`PLAN.md` phase 6).

### `POST /v1/sync/push`

Applies a batch of local operations atomically and reports conflicts.

Request (authenticated):

```json
{
  "ops": [
    {
      "item_id": "0123456789abcdef0123456789abcdef",
      "clock": { "0a1b2c3d4e5f60718293a4b5c6d7e8f9": 3 },
      "deleted": false,
      "ciphertext": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
  ]
}
```

Response `200`:

```json
{
  "applied": ["0123456789abcdef0123456789abcdef"],
  "conflicts": []
}
```

- `ops` must contain 1..=1000 operations. Every operation is validated before
  the transaction opens; one bad operation rejects the whole batch with
  `400 invalid_field` and writes nothing.
- A clock must have 1..=64 entries, keys must be device ids, values must be
  non-zero; zero counters are dropped and duplicate keys are merged by taking
  the maximum. An empty clock is `400 invalid_field`.
- A live operation (`deleted: false`) must carry a non-empty, even-length hex
  `ciphertext`. A tombstone (`deleted: true`) must carry an empty ciphertext;
  anything else is `400 invalid_field`.
- `applied` lists the item ids whose stored state now equals the pushed
  operation: newly inserted, updated, or already byte-identical (idempotent
  retry). It never lists an operation the server refused.
- `conflicts` lists the **stored** operations the server kept, unchanged, for
  items whose clock is concurrent with the pushed one (see
  [the merge rule](#the-merge-rule)). The client merges and pushes again with a
  clock that dominates both.

An operation whose clock is dominated by the stored clock is neither applied nor
conflicting: the sender is behind, and the newer operation is waiting in
`pull`. This is deliberate — returning the newer operation here would let a
client mistake ordering for a conflict.

The server does not check that a clock key names a device of the account. Any
device of the account can push any clock, and it can also create an item id; the
account is the trust boundary, and a compromised device of the account is a
compromised device. Verifying clock authorship would require the server to
understand the vault's writer rules, which it deliberately does not.

### `GET /v1/sync/pull?since=<u64>&limit=<n>`

Reads the change log after a sequence number.

Request (authenticated, no body):

```http
GET /v1/sync/pull?since=0&limit=2
```

Response `200`:

```json
{
  "ops": [
    {
      "seq": 1,
      "item_id": "0123456789abcdef0123456789abcdef",
      "clock": { "0a1b2c3d4e5f60718293a4b5c6d7e8f9": 3 },
      "deleted": false,
      "ciphertext": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
  ],
  "next_seq": 1,
  "has_more": false
}
```

- `since` defaults to `0`; it is exclusive (`seq > since`).
- `limit` defaults to `200` and is clamped to `1000`; `limit=0`, a negative value
  or a non-integer is `400 invalid_query`.
- `seq` is a per-account revision number, monotonically increasing across
  inserts, updates and tombstones. An updated item moves to the end of the log;
  it does not appear twice for the same `seq` range.
- `next_seq` is the last `seq` returned, or `since` when the page is empty —
  pass it as the next `since`. `has_more` says whether another page is waiting.

A tombstone is returned like any other operation, with `"deleted": true` and an
empty ciphertext. Tombstones are kept forever; the protocol has no garbage
collection, so a device that has been offline for a year still learns that an
item was deleted.

### `GET /v1/sync/state`

A summary for the settings screen. It contains no content and no per-vault
counts.

Request (authenticated, no body):

```http
GET /v1/sync/state
```

Response `200`:

```json
{
  "account_id": "00112233445566778899aabbccddeeff",
  "devices": [
    {
      "device_id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      "device_name": "Ana's laptop",
      "created_at": 1731686000
    },
    {
      "device_id": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
      "device_name": "Ana's phone",
      "created_at": 1731686500
    }
  ],
  "items": 1,
  "bytes": 32
}
```

`items` is the row count (tombstones included) and `bytes` the total ciphertext
size. Both are properties of rows the server legitimately holds; neither says
anything about how many fields an item has, because the server never sees
fields.

## The merge rule

Each item carries a version vector — a map from device id to a logical counter.
A device bumps its own counter every time it writes. When a push arrives for an
item that already exists, the server compares the incoming clock with the stored
one, and there are exactly four answers: if every counter in the incoming clock
is greater than or equal to the stored clock's and at least one is greater, the
incoming write is newer and replaces the stored row; if the stored clock
dominates the incoming one, the incoming write is older and is ignored (the
sender is simply behind and will find the newer operation on its next pull); if
the two clocks are identical and the content is identical too, nothing changes
and the operation is reported as applied, which makes retries harmless; and if
neither clock dominates the other, the two writes are concurrent — a genuine
conflict — so the server keeps the stored operation untouched, does not merge
anything, and returns the stored operation in `conflicts`. The client then
merges the two versions (field by field, with the user deciding anything that
both sides changed), pushes a clock that includes both counters, and that push
dominates, so it is applied. A delete is an operation with `deleted: true` and
an empty ciphertext; it follows the same rule, so a tombstone can be defeated
by a newer edit and a delete concurrent with an edit is reported as a conflict
rather than silently deciding which one wins. The server never uses a wall
clock to order anything, which is why a device with a wrong system time cannot
roll back a password.

## What the server can see

Stored, and therefore visible to whoever administers the server:

- the account id, device ids, device names, device public keys, device creation
  times;
- the hash of each enrolment code and the sealed envelope (both opaque), the
  offer's expiry and claim/ack times;
- item ids, version vectors (which device changed what, and how many times),
  tombstones, ciphertext sizes, per-item revision order and server timestamps;
- the number of items and the total bytes per account (`state`);
- traffic metadata: IP addresses, request timing, request sizes, connection
  patterns.

Never stored, and therefore not visible even to a full database dump:

- item titles, URLs, usernames, passwords, notes, categories, tags, field names
  or field counts;
- anything about the plaintext: item keys are derived on the client and the item
  body is one sealed blob;
- the enrolment code itself (only its SHA-256 is stored);
- the account key (only an envelope sealed to a device's X25519 key).

Residual leakage is stated rather than denied: sizes are not padded, so a
ciphertext's length is visible; change *timing* shows that something happened
even when its content does not; a version vector reveals which device wrote and
roughly how active it is; and the item count is visible. The client is expected
to pad and batch if it wants to hide more, and this protocol does not pretend
otherwise.

## Threat model

**Assumed.** The client device is honest and its private keys never leave it.
TLS between the device and the reverse proxy is intact. The server operator can
read the server's disk and its logs but does not hold any account or device
private key.

**Confidentiality.** An attacker with the database, the blob directory and
unlimited time learns the metadata above and nothing else. Decrypting an item
requires the account key; decrypting the sealed enrolment envelope requires the
new device's X25519 private key. There is no server-held key share and no
recovery escrow. A compromised server cannot read a vault.

**Integrity.** Every operation the server accepts is authenticated by an Ed25519
signature from a device of that account, bound to the method, path, body and a
timestamp. Another account, or a stranger, cannot write into an account. The
server can still *withhold* operations or refuse service; sync is not Byzantine
fault tolerant, and a client that suspects equivocation should compare `state`
across devices.

**Ordering.** The server does not invent order. It can only accept or reject a
client-supplied clock, so a compromised server cannot turn a new password into
an old one: a client must refuse an operation whose clock does not dominate what
it already has. That check belongs on the client; the server's conflict
response is a hint, not a proof.

**Replay.** Signatures are single-use within a 300-second window through a
bounded in-memory nonce set per device. The set is lost on restart, so a request
captured shortly before a restart can be replayed once. It would still have to
be a request for that device, within the window, and TLS is what stops an
attacker from capturing one in the first place.

**Enrolment.** The code is a bearer credential for a specific
`(account_id, new_device_id)` pair; the existing device's `ack` is the second
half of the flow. An attacker who guesses an enrolment code (32 random bytes, printed as 13 groups
of four base32 characters plus a checksum) also has to guess the
new device id (128 bits) within the offer's at most one hour, and the offer is
useless until the legitimate new device claims it. A stolen code plus a stolen
device id lets an attacker claim the sealed envelope, which is useless without
the new device's X25519 private key.

**Open registration.** `POST /v1/accounts` is unauthenticated by nature. A
public instance should either set `KESTREL_SYNC_MAX_ACCOUNTS` or rate-limit at
the proxy; otherwise anyone can create accounts and consume disk. The service
does not implement login, billing or per-account quotas.

**Transport.** The service speaks plain HTTP. Exposing port 8787 directly to the
internet would send signatures and metadata in the clear and would make the
replay window meaningful; terminate TLS at the proxy, and bind the service to a
private interface.

## Storage layout

One SQLite file (WAL mode) and one directory of blobs, both under the same
mounted volume.

```
accounts       (account_id PK, created_at)
devices        (device_id PK, account_id FK, signing_pub, agreement_pub, name,
                created_at, revoked_at)
enroll_offers  (account_id, new_device_id, code_hash, sealed, expires_at, created_at,
                claimed_at, claimed_signing_pub, claimed_agreement_pub, claimed_name,
                acked_at)                       PRIMARY KEY (account_id, new_device_id)
items          (account_id, item_id, seq, clock, deleted, blob, size, updated_at)
                                                PRIMARY KEY (account_id, item_id)
meta           (key PK, value)                  schema_version = 2
```

`devices.revoked_at` is `NULL` while the device may sign. Revocation updates the
row instead of deleting it: the account keeps the record of who was enrolled and
when their access ended. A v1 database gains the column in place when the
service opens it.

`items.clock` is the JSON encoding of the version vector. `items.blob` is the
hex SHA-256 of the ciphertext, or empty for a tombstone; the bytes themselves are
in `blobs/<first two hex characters>/<full hash>`, content-addressed so that
rewriting the same ciphertext is free and a blob can never be overwritten. A
blob is written and fsynced before the row that references it commits; a crash
in between leaves an unreferenced blob, which is harmless. Blobs are never
deleted automatically — a delete is a tombstone, not a file removal — so old
ciphertext stays on disk until the operator removes unreferenced blobs
deliberately.

## Self-host runbook

### Up

From the repository root:

```sh
docker compose -f deploy/docker-compose.yml up -d --build
```

That builds the image, starts one service, and creates one named volume. The
service listens on `127.0.0.1:8787` on the host; put a TLS proxy in front of it
(a Caddy example is in `deploy/docker-compose.yml`).

The image itself has not been built yet on the machine this was written on
(Docker is not installed there), so this runbook is the intended path, not a
tested one. The server binary has been run and driven over TCP by the crate's
integration tests; the container has not.

### Configuration

All configuration is environment variables; unset values use the defaults.

| Variable | Default | Meaning |
|---|---|---|
| `KESTREL_SYNC_ADDR` | `127.0.0.1:8787` | listen address, `<host>:<port>` |
| `KESTREL_SYNC_DB` | `kestrel-sync.db` | SQLite file |
| `KESTREL_SYNC_BLOBS` | `blobs/` beside the database | ciphertext directory |
| `KESTREL_SYNC_MAX_BODY` | `4194304` (4 MiB) | largest accepted request body, minimum 1024 |
| `KESTREL_SYNC_MAX_ACCOUNTS` | `0` | account cap; `0` means unlimited |

The container sets `KESTREL_SYNC_ADDR=0.0.0.0:8787`,
`KESTREL_SYNC_DB=/data/kestrel-sync.db` and `KESTREL_SYNC_BLOBS=/data/blobs`.

Exit codes: `0` clean shutdown, `2` invalid configuration, `3` the database or
the listener could not be opened.

### Backup

Stop the service, then copy the volume. Stopping first is what makes the copy
consistent: a running SQLite database has a `-wal` file whose contents are part
of the state.

```sh
docker compose -f deploy/docker-compose.yml stop
docker run --rm -v kestrel-sync-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/kestrel-sync-backup.tar.gz -C /data .
docker compose -f deploy/docker-compose.yml start
```

A backup is the database file **and** the blob directory together; neither is
useful alone. Treat the archive as sensitive: it holds ciphertext and metadata,
not plaintext, but it is the complete account state.

### Restore

Stop the service, replace the volume contents, start it.

```sh
docker compose -f deploy/docker-compose.yml stop
docker run --rm -v kestrel-sync-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/kestrel-sync-backup.tar.gz -C /data'
docker compose -f deploy/docker-compose.yml start
```

Do not restore a database without its blobs (items would fail to read) and do
not restore blobs without their database (they would be unreferenced). If both
are present, `GET /v1/sync/state` after a client login reports the expected
item count.

### Upgrade

```sh
docker compose -f deploy/docker-compose.yml up -d --build
```

The schema version is recorded in `meta`; a version bump is a migration the
release notes describe. Take a backup first — a running service will migrate in
place.

## Version negotiation

- A client **SHOULD** send `X-Kestrel-Protocol: 1` on every request.
- A missing header is treated as `1`, so `curl` and a health check do not have
  to negotiate.
- `1` and `1.<minor>` are accepted. Minor versions are additive: new optional
  request members, new response members, new endpoints. (This version rejects
  unknown request members, so a client must not send a member its server may not
  know; that is what a major version is for.)
- Any other major version is answered with `426 Upgrade Required` and
  `{"error":"unsupported_protocol"}`. The response still carries
  `X-Kestrel-Protocol: 1` so the client learns what to fall back to.
- Every response, including errors, carries `X-Kestrel-Protocol: 1`.
- Breaking changes require a new major version. The v1 endpoints are frozen:
  they keep their paths, their request shapes and their semantics. A future v2
  would live under `/v2/` and could run in the same process.

## Limits and error codes

| Limit | Value |
|---|---|
| request body | `KESTREL_SYNC_MAX_BODY` bytes (default 4 MiB); `413 body_too_large` |
| push batch | 1000 operations |
| clock entries | 64 |
| item id | 128 characters |
| device name | 128 characters |
| sealed envelope | 64 KiB decoded |
| offer lifetime | 3600 seconds |
| pull page | 1000 operations (`200` default) |
| timestamp skew | 300 seconds |
| nonces kept per device | 4096, pruned after 600 seconds |

A body over the limit is answered with `413` once the bytes have been drained
(up to twice the limit); beyond that the connection is closed. The limit is
checked before routing, so it applies to every request.

| Status | `error` | When |
|---|---|---|
| `400` | `invalid_body` | body is not JSON, has an unknown member, or a wrong type |
| `400` | `invalid_field` | a field failed validation (id, key, name, clock, code, expiry, ciphertext) |
| `400` | `invalid_code` | claim: no unexpired offer for that code hash and device id |
| `400` | `expired_code` | claim/ack: the offer expired |
| `400` | `unknown_offer` | ack: no offer for that device |
| `400` | `not_claimed` | ack: the new device has not claimed |
| `400` | `invalid_query` | pull: bad `since`/`limit` |
| `401` | `unauthorized` | Authorization missing or unparseable |
| `401` | `unknown_device` | the device id is not registered |
| `401` | `bad_signature` | the signature does not verify |
| `401` | `stale_timestamp` | the timestamp is outside the 300-second window |
| `401` | `replay` | this nonce was already used by this device |
| `403` | `account_limit` | `KESTREL_SYNC_MAX_ACCOUNTS` reached |
| `403` | `device_revoked` | the signing device was revoked by another device of the account |
| `404` | `not_found` | no such route, or no such device in the caller's account |
| `405` | `method_not_allowed` | route exists, method does not; `Allow` header names the method |
| `409` | `account_exists` | the account id is taken |
| `409` | `device_conflict` | the device id belongs to another account |
| `409` | `already_enrolled` | the device is (or was) already enrolled |
| `413` | `body_too_large` | body exceeds the configured limit |
| `426` | `unsupported_protocol` | `X-Kestrel-Protocol` major is not `1` |
| `500` | `internal` | storage or serialisation failure; the detail is in the server log |

## v1 is frozen

The eight endpoints above are the contract. A change to any of them — a new
field, a new route, a different status code — is a **v2**, negotiated through
`X-Kestrel-Protocol`, not an addition to v1. A server that does not speak the
client's version answers `426`, which is already implemented; that is what makes
the freeze real rather than a promise.

The one addition to the original seven was `DELETE /v1/devices/<id>`, and it is
documented here as part of v1 because both the reference server and the client
in this repository implement it together. It adds a response member
(`revoked_at`) and one error code; clients that predate it ignore both and keep
working, while a revoked device is refused. The limitation below still holds:
the endpoint stops new requests, it does not rotate the account key.

What v1 deliberately does not carry, and why:

| Missing | Why it is not here |
|---|---|
| Binary attachments | An attachment does not fit in an item body: the push cap is 4 MiB for the whole batch, and the change log would carry the bytes on every pull. A separate content-addressed channel is a v2. Until then attachments stay on the device that made them, and the app says so on each one. |
| Account-key rotation | Revocation stops new requests, but a revoked device keeps the account key it already holds and every byte it pulled. Real separation requires generating a new account key, re-sealing it to every remaining device and re-sealing every stored body — the sharing machinery in `DESIGN.md` §28 at account scope. That is phase 6 follow-up work, not this endpoint. |
| Sharing, administration, audit, emergency access, hosted billing | Designed in `DESIGN.md` §6, and each needs its own endpoints and its own key work. |

## v2 sketch — nothing here is implemented

Written down so the next wave starts from an agreed shape instead of an
invention. A v1 server refuses both routes with `404`.

### Blobs: `PUT /v1/blobs/<sha256>` and `GET /v1/blobs/<sha256>`

- `PUT` with the sealed bytes as the body, authenticated like every other call.
  The path hash must equal `sha256(body)`; a mismatch is `400 invalid_field`,
  which is what stops a client from poisoning a content address.
- `GET` returns the bytes, or `404 unknown_blob`. A repeated `PUT` of identical
  bytes is idempotent, so a lost response is retried without a second copy.
- The item body gains `attachments: [{ "hash": "<hex>", "size": <u64> }]`. The
  server still learns nothing but an opaque hash and a length.
- Limits: `KESTREL_SYNC_MAX_BLOB` (8 MiB by default) and a per-account cap the
  operator sets.

### Garbage collection, not `DELETE`

There is no delete endpoint. One device deleting an attachment another device
still references is a conflict the server cannot judge, and a client-side delete
would let any device of the account destroy data.

Instead the server runs a scheduled sweep. **The rule has two halves, and both
are required:** a blob is removed only when it is referenced by no item row
**and** it is older than a grace window (24 hours by default). The age half is
what protects an upload in flight: a client writes the blob before it pushes the
item that references it, and during that gap the blob is unreferenced by
definition. A sweep that ignored age would delete every attachment the moment it
was uploaded.

### Revocation: key rotation on top of the endpoint

v1 now has `DELETE /v1/devices/<id>`: it stops new signatures and keeps the row
as a revoked record. That alone does not take the account key away from the
revoked device. The remaining operation is: generate a new account key, re-seal
it to every remaining device (the enrolment envelope already exists), re-seal
every stored body under it, and only then treat the old key as dead for new
bodies. That is the same re-wrap machinery as §28, at account scope instead of
item scope — phase 6 follow-up work, not part of v1's endpoint.
