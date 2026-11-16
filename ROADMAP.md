# Kestrel — feature roadmap

Goal: the functional surface of a desktop password manager on Tauri 2 + React 19
+ a Rust core, with an independent visual language. The cryptography is public
standards (§Phase 1), and 1PUX interchange follows a published file format. No
third-party code, assets or icons are used; see `LICENSE` and `NOTICE`.

Legend: **done** — implemented and covered by tests · **designed** — UI and
interaction specified in `DESIGN.md` §6, with the backend work named; nothing
shipped · **next** — implementation work not started · **later** — needs a
server or OS-specific provider.

Capabilities 1–18 ship with a complete interface and core commands: every
control the renderer shows has a command behind it, and nothing is rendered
before it can be honoured. Of 19–31, items 19–25 are shipped; 26–30 are designed
in `DESIGN.md` §6 and 31 in §11, and none of those six runs yet.

## Phase 1 — vault core (done)

| # | Capability | Reference | Kestrel |
|---|---|---|---|
| 1 | Master password → Argon2id KDF | RFC 9106; 64 MiB, t=3, p=1, 16-byte salt | done (`crypto.rs`) |
| 2 | AEAD per object with bound AAD | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha), 24-byte nonce | done |
| 3 | Encrypted local SQLite (`data BLOB` rows) | SQLite; every sensitive byte inside the blob | done (`store/`) |
| 4 | Unlock / lock / auto-lock (Rust-side watchdog) | no timer in the renderer | done |
| 5 | Clipboard copy with timed wipe | OS clipboard, wipe only if the value is unchanged | done |
| 6 | Item CRUD, 18 categories, custom fields | one generic field model | done |
| 7 | Search that never matches secrets | plaintext projection, rebuilt on unlock | done |
| 8 | Favorites, tags, notes | item metadata | done |
| 9 | TOTP (RFC 6238, `otpauth://`) | RFC 6238 | done |
| 10 | Password + passphrase generator | CSPRNG (`OsRng`) | done |
| 11 | Master password rotation re-encrypting all items | new salt, every object re-sealed | done |

## Phase 2 — multi-vault and organisation

| # | Capability | Kestrel |
|---|---|---|
| 12 | Multiple vaults with independent keys | done — per-vault key `master.derive(vault_uuid)`, `vaults_list`/`vault_create`/`vault_switch`/`vault_rename`, the session re-scopes on switch, rotation re-encrypts every vault; `core/tests/vaults.rs` |
| 13 | Item history / restore | done — `item_versions` written on every save (50-version cap, AAD-bound), `history_list/get/restore`, rail in the detail pane; `core/tests/history.rs` |
| 14 | Attachments and documents | done — sealed blobs under the item key, 25 MiB cap, digest, save-as into Downloads, remove; `core/tests/attachments.rs` |
| 15 | Trash, restore, purge | done — `items.deleted_at`, list/count/trash/restore/purge/empty, purge also drops versions and attachments; `core/tests/trash.rs` |
| 16 | Import/export (1PUX, CSV, JSON) | done — preview → import report, password-gated export, 1PUX read/write via `zip`; `core/tests/portability.rs` |
| 17 | Security audit (weak, reused, breached) | done — offline weak/reuse plus k-anonymised HIBP range check from the core, values never leave it; `core/tests/audit.rs` |
| 18 | Quick-access palette (global hotkey) | done — second 420 px webview, `Ctrl+Shift+Space`, shares the session; `src-tauri/src/quick.rs` |

## Phase 3 — system integrations (done, OS-specific)

> See `DESIGN.md` §6 for the interaction and backend spec of each item.

| # | Capability | Notes |
|---|---|---|
| 19 | Browser extension bridge via named pipe | done — `kestrel-nmhost.exe` (native messaging) forwards to `\\.\pipe\kestrel-sdk` with a `Browser` token, per-origin rules in `browser_sites`, every reveal audited; `extension/` (MV3) |
| 20 | Autofill into Windows apps | done — `SetWinEventHook` + UI Automation observer, per-exe rules, `WS_EX_NOACTIVATE` picker anchored to the field, explicit `SetValue` only, elevated windows refused; `src-tauri/src/autofill/` |
| 21 | Passkey provider (WebAuthn) | done, one step unproven — `kestrel-passkey` (CBOR/COSE/CTAP2 + COM server), sealed credentials re-sealed on rotation; `WebAuthNPluginAddAuthenticator` returns `0x80090027` here, so Windows does not route passkeys yet (see DESIGN §6) |
| 22 | SSH agent + git signing | done — `\\.\pipe\openssh-ssh-agent`, user-only DACL, Ed25519 via `ssh-key`/`ed25519-dalek`, keys never leave the core |
| 23 | Windows Hello unlock | done — TPM-backed CNG key with `NCRYPT_UI_PROTECT_KEY_FLAG`; the prompt happens inside `NCryptDecrypt`; master password stays the fallback |
| 24 | MCP server for environment secrets | done — `kestrel-mcp.exe` over stdio, `list_secrets`/`get_secret` gated by `mcp_grants` set at pairing, every read audited; `src-tauri/mcp/`, `core/tests/mcp.rs` |
| 25 | CLI + SDK over a named pipe | done — `\\.\pipe\kestrel-sdk`, per-session token, `kestrel-cli` (`status`, `list`, `copy`, `run --env`) |

## Phase 4 — sync and accounts (partly built)

> The sync service (`kestrel-sync`), `PROTOCOL.md` and the account key hierarchy
> exist; the client engine, sharing, admin and the hosted service do not. Each
> row says which half it is. See `DESIGN.md` §6 for the specification and §11 for
> the extension API.

| # | Capability | Status |
|---|---|---|
| 26 | Account sign-in, device enrolment, key transfer | **done offline** — Secret Key + Account Key hierarchy, per-item keys (v9, lazy backfill), device keypairs (v10), code + envelope, joining a device without a network; the HTTP claim and device revocation ship with 27 |
| 27 | Vault sync with conflict resolution | **done for items** — `kestrel-sync` implements `PROTOCOL.md` over real TCP, and the client half ships: `kestrel-engine` pulls/merges/pushes with per-field vector clocks, the store keeps a v11 sync row per item, Settings → Sync configures the server, the titlebar shows the state, and a conflict review screen resolves one item at a time. Background sync ships too, once it is switched on: a timer with a backoff that only ever waits longer, a debounced run after a write, and a locked vault skipped without an error. **v1 is frozen at the eight endpoints in `PROTOCOL.md`, including `DELETE /v1/devices/<id>`.** Still unbuilt, and planned as v2: binary attachment transfer (content-addressed blobs with a scheduled server-side sweep that requires *both* no reference and an age window, so an upload in flight is never collected), account-key rotation on top of device revocation (with 28), and the hosted service |
| 28 | Sharing: vault permissions, per-item links | designed — item key re-wrapped to each recipient, server routes envelopes it cannot open, revoke re-keys. **Device revocation now stops new signatures and keeps the row as an audit record, but the key rotation is still here:** revoking a device of the account must rotate the account key and re-seal every stored body, which is the same re-wrap machinery at account scope. The endpoint alone is honest about not erasing a copy, and the UI says so |
| 29 | Family/team administration, audit log | designed — roles, access matrix, hash-chained device-signed entries the server can verify but not read |
| 30 | Recovery kit (paper only); emergency access unbuilt | **local half done** — a printed recovery code wraps the master key, the gate unlocks with it, a forced password change re-keys everything and the old code dies; trusted contacts and waiting periods stay designed-only |
| 31 | Extension API (out-of-process, signed manifests) | designed — `Plugin` scope on the existing pipe, per-field grants, audit row per read, importers/exporters/generators/palette actions/events, no storage; no renderer JavaScript, ever |

Deployment: self-host is one Docker image with SQLite and blobs on a mounted
volume; S3/MinIO is a backup target only, because object storage has no
cross-object transaction and a client-side merge over it reintroduces stale-item
and rolled-back-password failures. There is no free sync tier: the local app is
free forever, and hosted sync, sharing, administration and emergency access are
the paid product.

## Non-goals

- Telemetry, feature-rollout services, and remote config — decisions ship in the
  binary.
- Any secret leaving the device in the clear.
