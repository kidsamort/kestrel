# Refactor before Phase 3 — audit and plan

Goal: make the existing codebase maintainable and predictable **without changing
behaviour and without adding features**. Every item below is either measured here
or produced by a read-only audit pass; nothing is "we should probably".

## Baseline (measured, 2026-11-13)

| Metric | Value |
|---|---|
| Rust lines | 5 036 — `portability.rs` 1087, `store.rs` 860, `audit.rs` 411, `session.rs` 389 |
| TypeScript lines | 8 761 — `VaultShell` 762, `ItemDetail` 556, `QuickAccess` 534, `Settings` 461 |
| CSS lines | 5 201 — `app.css` 3 215 |
| IPC commands registered | 41 (`generate_handler!`), while `src/api.ts` still says "the 17 frozen commands" |
| Core tests | 68 across 8 files; **frontend: 0**, no test runner installed |
| `unwrap`/`expect` outside tests | 43 (incl. startup `expect` on store open) |
| Error mapping in the renderer | 7 regexes over English `String` errors |
| `cargo fmt --check` | 57 diffs — formatting is not enforced |
| Dead CSS selectors (static scan) | 27; several are dynamic (`btn-${variant}`, `swatch-${accent}`) and are false positives |

Longest functions: `one_password_to_item` 145, `change_password` 119, `split_csv`
115, `default_fields` 96, `migrate` 83.

## Rules

1. Behaviour is frozen: the 68 core tests stay green, the seven Phase 2 features
   are re-checked by hand at the end, no UX changes.
2. One owner per file. Shared contracts (`store.rs`, `session.rs`, `api.ts`,
   `VaultShell.tsx`, `app.css`) change in one slice at a time.
3. No rewrite-from-scratch, no new features, no "while we are here".
4. Each slice ends with `cargo clippy -- -D warnings`, `cargo fmt --check`,
   `tsc --noEmit`, and the relevant tests.
5. Documentation ships with the code that changes it.

## Waves

| Wave | Contents |
|---|---|
| 0 | Five read-only audits: core, features, shell/IPC, UI, tooling/docs |
| 1 | Typed error contract · `Store` split + migration runner · command tree + honest docs · bytes over number arrays · frontend test runner · error boundary + CI |
| 2 | Indexed summaries/counts · session vault cache + lock/unlock events · virtualisation guarantee · vault deletion + orphan sweep · a11y pass |
| 3 | CSS split + dead selector sweep · `VaultShell` decomposition · ADRs · docs refresh |

## Step 1–2 result (done)

| Item | Status | Evidence |
|---|---|---|
| C1 atomic rotation | done | `core/tests/hardening.rs`: abort trigger mid-rotation → DB still opens with the old password, items and history intact |
| F4 atomic save | done | abort trigger on `items` → `item_versions` unchanged |
| C4 vault-scoped delete + PK rebuild | done | same uuid in two vaults: delete in A leaves B intact; schema v3 rebuild test |
| C2 AAD role split | done | copy of an `item_versions` blob into `items` at the same version → `Crypto(Decrypt)` |
| C6 key-version marker | done, and **corrected during review** | the first implementation marked every v2 row as derived-sealed, which would have locked out vaults created before per-vault keys; the resolver now tries derived → master once for unversioned rows and records 2 |
| C5 live, scoped item count | done | `live_count` + `state()`; trash no longer counts |
| U1–U5, U7 | done, runtime-verified | Ctrl+L asks before discarding; Ctrl+E after selection; roving focus matches the highlight; filter clears a stale selection; Escape does not reopen the dialog |
| U6, U8 | done, code-verified | the IPC instrumentation needed for fault injection could not be installed (WebView2 isolated world), so the failure paths were not simulated at runtime; the counters and one-toast-per-version logic are covered by reading only |
| Trash refresh | fixed during review | restore/purge now bump the shell's refresh, so the sidebar count returns without a reload |

Independent verification: **75 core tests green**, `cargo check` clean, `tsc` clean, and the
real v2 vault copy migrated to schema 3 with `key_version = 1` preserved (resolved at unlock)
and all 5 items / 6 versions intact.

## Execution order (owners and gates)

| Step | Slice | Owner | Gate |
|---|---|---|---|
| 1 | Store hardening: C1 atomic rotation, F4 atomic save, C4 vault-scoped delete + PK migration, C2 AAD role split, C6 key-version marker | one agent, `store.rs` only | migration tests v1→v3, rotation-failure test, 68 tests green |
| 2 | UI correctness: U1–U7 (lock guard, Ctrl+E deps, list focus, filter selection, Escape, poll errors, TOTP effect) | one agent, `src/**` | regression test per bug where pure logic allows; manual checklist |
| 3 | Typed error contract (S1, S5) + command tree (S2) | one agent, all `commands*` + `api.ts` | every code has a phrase; no prose regex left |
| 4 | Import/export safety (F1, F2, F3) | one agent, `portability.rs` | CSV injection test, size-cap test, batch-failure test |
| 5 | IPC bytes + dead code (S3, F5, F7) | one agent | 5 MiB roundtrip, `grep` shows the removed symbols |
| 6 | Test runner, CI, error boundary (T2, T3, U8) | one agent | pipeline green from a clean clone |
| 7 | Performance: C7 summary index, C8 vault cache, C5 counts, F9 repo layer | after 1–6 | bench before/after, counts agree |
| 8 | Structure: portability split, `VaultShell` split, `app.css` split, tsconfig strictness, dead CSS/tokens | parallel, disjoint files | visual diff unchanged, `wc -l` targets |

Steps 1 and 2 can run in parallel (disjoint files). Step 3 must follow 1. Steps 4 and 5 are disjoint from 3 except `commands_portability.rs`, which step 3 touches — sequence 4 after 3.

## Runtime verification checklist (steps 1–2)

Run against a throwaway vault (back up `%APPDATA%\app.kestrel.vault`, create a
scratch vault, restore the backup afterwards). Debug builds load the Vite dev
server on `:5273` and can be driven over CDP (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222`).

| # | Check | How |
|---|---|---|
| U1 | Lock while editing asks first | edit a title, press Ctrl+L → the discard dialog appears; "Keep editing" keeps the draft |
| U2 | Ctrl+E after selecting an item | click a row, press Ctrl+E → editor opens |
| U3 | Roving focus matches the highlight | ArrowDown/End on a 5-row list → `document.activeElement` is the row that is highlighted |
| U4 | Filter drops a stale selection | open a login, switch to Favorites → detail pane clears |
| U5 | Escape does not reopen the dialog | edit, Esc (dialog opens), Esc again → dialog still open, not re-triggered |
| U6 | Dead core is visible | patch `__TAURI_INTERNALS__.invoke` to reject `vault_state`, wait 3 polls → error screen + one toast |
| U7 | TOTP is fetched once per cycle | wrap `invoke` with a counter before opening an item with TOTP → no duplicate `item_totp` per 30 s |
| U8 | List/count failures surface | patch `invoke` to reject `trash_count` → one toast, not a silent zero |
| S1 | Rotation survives a failure | core test with an abort trigger: DB still opens with the old password |
| S2 | History replay rejected | copy `item_versions.data` into `items` at the same version → `get()` fails |

## Refactor wave — landed so far

| Slice | Result | Evidence |
|---|---|---|
| UI primitives | `src/ui/PaletteRow.tsx` (81) and `src/ui/EmptyState.tsx` (75) replace duplicated row/empty markup; the row skeleton and the two headings now exist once | `grep "palette-glyph\|Nothing matches\|The vault is empty"` → one hit each |
| List arithmetic | `ItemList.tsx` has one index formula (`:86`) used by both the selection effect and `focusIndex` | same grep for `index - start + spacer` → one hit |
| Settings split | `Settings.tsx` 461 → 81; five cards in `src/vault/settings/` (66–128 each) | `wc -l` |
| Move data split | `MoveData.tsx` 450 → 39; `ImportFlow` 191, `ExportFlow` 139, `ImportViews` 154, `formats.ts` 22 | `wc -l` |
| Poll dedup | `src/lib/use-core-poll.ts` (51) replaces two near-identical intervals in `App.tsx` | `grep useCorePoll src/App.tsx` → two call sites, no `setInterval` for state |
| Test runner | vitest + jsdom + testing-library, 30 tests over `format`, `catalog`, `navigation`, `generator`, `api-portability`, `errorText`, boundary | `npm test` → 30/30 |
| Error boundary | `src/ui/ErrorBoundary.tsx`, wrapped around `App` and `QuickAccess`; one test proves the fallback renders and the error does not escape | `npm test` |
| CI | `.github/workflows/ci.yml`: frontend (npm ci, tsc, test, build) + core (fmt, clippy -D warnings, tests) | workflow file; not executed (no remote) |
| Rust split | `store.rs` 1095 → six modules (67–309), `portability.rs` 1087 → five modules (104–393); `migrate` and `change_password` decomposed; CSV parser proven equivalent on 437 277 inputs | `cargo test` 75/75, `clippy -D warnings` clean, `fmt --check` clean |
| Shell split | `VaultShell.tsx` 827 → 290; hooks `useVaultData` 135, `useSelection` 287, `useShellPanels` 158, `useTitlebarSlots` 27 + `logic`/`hotkeys`/`session` helpers; 14 new tests | `tsc`, `npm test` 44/44, `npm run build` |

Two defects found during the parent's runtime pass and fixed on the spot:
import did not refresh the sidebar counts, and the vault switcher kept the
counts it read at mount. Both now refresh on change/open (verified live).

## Wave A verification (after the four refactor slices)

Static gates: `cargo test -p kestrel-core` (75 + new), `cargo clippy -p kestrel-core -- -D warnings`,
`cargo fmt --all -- --check`, `tsc --noEmit`, `npm test`, `npm run build`.

Runtime, on a throwaway vault (back up `%APPDATA%\app.kestrel.vault` first):

| Surface | Check |
|---|---|
| Command palette (Ctrl+K) | opens, arrows move, Enter selects, click selects, empty query lists everything |
| Quick palette | opens from Settings, search filters, username/password copy shows the check and the clipboard hint |
| List | Home/End/arrows keep focus on the highlighted row; a search with no hits shows the shared empty state |
| Settings | all five cards render, autolock changes, theme/accent apply, quick-access status still shows the taken chord |
| Move data | import CSV → preview → report; export JSON downloads a file |
| Core loss | kill the app → error boundary / fatal screen shows, no blank window |
| Vault switcher | menu lists vaults with counts, creating a vault switches to it |

## Acceptance

- `clippy -D warnings`, `fmt --check`, `tsc`, `npm test` all clean in CI.
- 68 existing tests + ≥ 40 frontend tests + migration and IPC-byte tests.
- Largest module ≤ 400 lines; no function over 60 lines.
- `list_items` no longer decrypts the whole vault per query; `state()` no longer
  decrypts every vault name every 10 s.
- Docs match the real command count; four ADRs (errors, migrations, vault scope,
  IPC payloads).

## Findings

Wave 0 ran five read-only audits. Rows below are accepted only after the parent
re-checked the code; severity is the parent's, not the scout's.

### P0 — correctness or data-loss risk

| # | Evidence | Problem | Fix | Verify |
|---|---|---|---|---|
| C1 | `core/src/store.rs:530-604` | `change_password` writes the new salt/verifier **before** destroying data, then commits the deletes in one transaction and inserts rows outside any transaction. A crash in between loses the vault or leaves it unopenable by either password | One `BEGIN IMMEDIATE` around salt, verifier, deletes and inserts | Reopen after rotation: `unlock(new)` + non-empty `list()`; failure-injection test between phases |
| C2 | `core/src/store.rs:110-112`, `:801-812` | Archived versions keep the AAD of a **live** item (`kind = "item"`), so a history row copied into `items` at the same version decrypts — rollback of item content is not detected | Separate AAD roles (`item` vs `item-history`), schema v3 with re-encryption at unlock | Copy an `item_versions` blob into `items` with the same version → `get()` must fail |
| C3 | `src-tauri/src/lib.rs:30` | `VaultState::open(...).expect("vault store opens")` panics before any window exists: a corrupt/locked DB means the app dies with no message | Open the store fallibly, keep the error in state, render a recovery screen with the path and a "reveal in explorer" action | Point the app at a corrupted DB → window opens with the error, no panic |
| C4 | `core/src/store.rs:831-839`, `core/src/session.rs:264`, schema `:163,:170` | `save_item` accepts a renderer-supplied id, `delete_item` deletes by `item_uuid` only, and `item_versions`/`attachments` primary keys omit `vault_uuid` — the same id in two vaults collides and a delete in one vault can hit the other | Scope every statement by `vault_uuid`; rebuild the two tables with `(vault_uuid, item_uuid, version)` / `(vault_uuid, attachment_uuid)` keys | Seed the same id in two vaults, delete in A, assert B is intact |

### P1 — measurable fragility

| # | Evidence | Problem | Fix |
|---|---|---|---|
| C5 | `core/src/session.rs:110`, `store.rs:841` | `state().item_count` counts every row in the DB (all vaults, trash included); the vault switcher counts live items per vault — the two numbers disagree | Count `WHERE vault_uuid = ?1 AND deleted_at IS NULL` |
| C6 | `core/src/store.rs:298-316` | The legacy name fallback keeps the master key valid for that AAD forever and mutates the DB from a read path, untransacted | Record `key_version` on the row, migrate once at unlock, then never fall back |
| C7 | `core/src/store.rs:648` | `list()` decrypts every item of the vault per query; sidebar counts and the audit do the same | Encrypted summary index (title/url/tags/username + counts) maintained on save/trash/purge |
| C8 | `core/src/session.rs:110` | `state()` decrypts **every vault name** on every call (10 s poll + each action) | Cache summaries in the session, invalidate on create/rename/switch |
| C9 | 43 `Result<_, String>` signatures; 38 `errorText(...)` sites; `src/api.ts:51-63` | Errors cross IPC as English prose and the UI pattern-matches it | `CommandError { code, message }`, one mapping table on the renderer |
| C10 | `src/lib/api-attachments.ts` (`toByteArray`), `commands_attachments.rs` | Attachments travel as JSON number arrays (a 25 MiB file becomes a ~90 MB array) | `tauri::ipc::Response` / raw bytes for add/read |
| C11 | `src/**` | No error boundary; 14 `catch(() => undefined)` sites; no frontend tests | Boundary around `Root`, a test runner, cover pure logic first |
| C12 | workspace | No CI, `cargo fmt --check` shows 57 diffs, no `clippy -D warnings` | Pipeline: fmt → clippy → tsc → tests → build |
| C13 | `src/styles/app.css` (3 215 lines) | One file for every surface; 27 statically unused selectors (some dynamic, verified) | Split by surface, delete real dead rules |
| C14 | `src/api.ts:12`, `README.md` | Docs say "17 frozen commands"; there are 41 | Generate the list from `generate_handler!`, update the docs |

### P0/P1 from the features audit (verified in code)

| # | Evidence | Problem | Fix |
|---|---|---|---|
| F1 | `core/src/portability.rs:636-643` | CSV export does not neutralise `= + - @` prefixes: values from an imported (untrusted) file become formulas in Excel/Sheets | Prefix `'` when the first char is a formula trigger; test with `title = "=1+1"` |
| F2 | `core/src/portability.rs:646-669` | No import size limit; 1PUX `export.data` is read with `read_to_end` — a 1 KB zip can expand to gigabytes (zip bomb) | `MAX_IMPORT_BYTES` checked before parsing, `entry.size()` + `Read::take` for 1PUX |
| F3 | `core/src/portability.rs:141-152` | Import writes one `save_item` per row (4 autocommits each) while holding both mutexes; a crash leaves a half-imported vault with no record | Parse before taking the session lock, write in batches inside one transaction, keep the per-row report |
| F4 | `core/src/store.rs:668-706` | `save_item` archives the version and writes the item in two separate autocommits — a crash leaves history describing a save that never happened | One transaction around archive + write |
| F5 | `core/src/attachments.rs:239-249`, `store.rs:847-858`, `commands_attachments.rs:38-44` | Dead code and an unused IPC path: `purge_item_attachments`, `raw_blob_prefix`, and `attachment_read` (the only command returning decrypted bytes to the renderer, with no caller) | Delete all three, plus the `attachments.read` wrapper |
| F6 | `core/tests/rekey.rs:1-4` vs body | The test header claims attachments are re-encrypted on rotation; no test creates one — a bug in that branch would silently lose files | Add attachment to the rotation test, read it back after reopen |
| F7 | `core/src/attachments.rs:82-91` | Attachment name has no length cap (a 10 MB name is stored, then `save_as` fails with `ENAMETOOLONG`), MIME is unvalidated, and the 25 MiB limit is duplicated in TS | Cap the name at 255 chars, allowlist MIME prefixes, expose the limit through `vault_state` |
| F8 | `core/src/audit.rs:268-299` | On a partial HIBP failure the report still adds `breached` findings while `breachChecked` is false — "partially checked" and "found" are mixed | Only add breach findings when the range check succeeded; iterate prefixes in a stable order |
| F9 | `core/src/history.rs:25-48`, `attachments.rs:46-79`, `trash.rs:21-42` | Four independent copies of "does this item exist / is it trashed" and three copies of the attachment SELECT, each with its own decryption | One crate-private `repo` layer; `history`/`attachments`/`trash` stop calling `store.conn()` |

### P0/P1 from the UI audit (re-checked in code)

| # | Evidence | Problem | Fix |
|---|---|---|---|
| U1 | `VaultShell.tsx:522,602,719` | Lock (sidebar, Settings, palette, Ctrl+L) bypasses the unsaved-edit guard: an open dirty editor is discarded with no dialog | Route every lock through `guard(onLock)`; test: edit → Ctrl+L → dialog appears |
| U2 | `VaultShell.tsx:458` vs deps `:486` | The shortcut handler reads `selectedId` but the effect does not depend on it, so Ctrl+E keeps seeing `null` after a selection | Add `selectedId` to the dependency list (or read it from a ref) |
| U3 | `ItemList.tsx:74,95,111,118` vs `:227` | Roving focus indexes `children[i + 1]`, assuming a spacer is always first — but the spacer only renders when virtualising past row 0. Arrow/End focus the wrong row or nothing | Index from `start` or always render a zero-height spacer |
| U4 | `VaultShell.tsx:241-253` | Changing the filter does not clear the selection: the list can be empty while the detail pane still shows a decrypted item | Clear `selectedId` when it is no longer in `summaries` |
| U5 | `ItemEditor.tsx:128-144` | Escape ignores an open dialog and `defaultPrevented`, so closing the discard dialog immediately reopens it | Bail out when a dialog is open or the event was already handled |
| U6 | `App.tsx:224-239,251-262` | Both state polls swallow errors: a dead core looks like a live vault | Count consecutive failures, surface once, then fall back to the error screen |
| U7 | `ItemDetail.tsx:497-508` | `load()` runs inside a `setRemaining` updater — a side effect in a reducer, doubled by StrictMode | Move the refetch into its own effect |
| U8 | `src/**` (14 sites) | `catch(() => undefined)` hides list/count/palette failures | Report once per version through the existing toast channel |

### P0/P1 from the shell/IPC audit (re-checked)

| # | Evidence | Problem | Fix |
|---|---|---|---|
| S1 | `src/api.ts:51-64`, `QuickAccess.tsx:231`, `AttachmentsSection.tsx:147` | Errors cross IPC as English prose; three regex tables decide what to say, and one `item not found` covers item, attachment **and** vault uuid — the UI gives the wrong advice | `IpcError { code, message }` + `impl From<VaultError>`; renderer switches on `code`; prose regexes deleted |
| S2 | `src-tauri/src/lib.rs:45-91`; `src/api.ts:12`; `src/vault/Settings.tsx:416`; `README.md:94`; `DESIGN.md:5` | The command list is duplicated by hand and four places claim **17** commands (one of them is user-visible in Settings), while the real number is **46** (41 `commands::*` + 5 `quick::*`) | One `commands/` tree, a test asserting the count, and a single exported constant the UI/README quote |
| S3 | `commands_attachments.rs:25-45`, `commands_portability.rs:24-42` | Binary payloads travel as JSON number arrays (~94 MB of JSON for a 25 MiB file); `export_1pux` already shows the right pattern (`tauri::ipc::Response`) | Raw bytes in, raw bytes out |
| S4 | `quick.rs:229-247`, `Settings.tsx:300-304` | `quick_open`/`hide`/`focus_main` report failures into `QuickStatus.error`, but Settings renders that field only when the hotkey is **not** registered — after a successful registration, window failures are invisible | Separate "window error" from "hotkey error" and surface both |
| S5 | 7 `commands_*.rs` | `fn err` copy-pasted seven times | One `crate::error::err`, deleted copies |
| S6 | `README.md:16,40` | "no network" is true for the renderer but the core performs one HTTPS call (HIBP) | State the boundary explicitly in README and DESIGN |

### P2 — maintainability

Longest functions: `one_password_to_item` 145 (`portability.rs:701`), `change_password` 119, `split_csv` 115, `default_fields` 96, `migrate` 83. `portability.rs` mixes three formats; `VaultShell` mixes data, shortcuts, portals and dialogs; six `commands_*.rs` repeat `fn err`; `store.rs` mixes crypto, SQL, policy and migration.
