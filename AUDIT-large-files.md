# Large-file audit (≥ 440 lines)

Read-only pass over every file that approaches or exceeds 500 lines. Each claim
below was checked in the source; nothing was changed. Thresholds: a file is
"large" at ≥ 440 lines, a function is "long" at ≥ 60 lines.

Method: line counts (`wc -l`), function spans computed by brace depth, hook
inventory by `grep`, dead props/exports by cross-referencing identifiers across
`src/**`, dead CSS by matching selectors against every `className` in the
codebase, duplicate blocks by comparing the rendered markup of sibling
components.

## Status after the debt pass

Every finding below was closed. The inventory stays as written: it is the
record of what the pass found, not a description of the tree today.

| File | Was | Now | How |
|---|---|---|---|
| `src-tauri/core/src/store.rs` | 1096 | 6 modules, largest 312 (`store/rotation.rs`) | split by responsibility: `mod`/`migrate`/`items`/`query`/`rotation`/`vaults`/`attachments`; `raw_row_count`/`raw_blob_prefix` deleted |
| `src/VaultShell.tsx` | 827 | 296 | `vault/shell/` hooks (`useVaultData`, `useSelection`, `useEditing`, `useSearch`) |
| `src/vault/ItemDetail.tsx` | 563 | 197 | `vault/detail/`: header, fields, notes, TOTP, delete dialog |
| `src/QuickAccess.tsx` | 534 | 132 | `quick/`: row, header, results, footer, locked, three session hooks |
| `src/vault/Settings.tsx` | 461 | 85 | `vault/settings/` cards |
| `src/vault/MoveData.tsx` | 450 | 39 | `portability/` flows |
| `src-tauri/core/src/session.rs` | 398 | 444 | unchanged in shape; the debt pass added `counts`/`list` over SQL |
| `src/App.tsx` | 365 | 337 | the modality effect was deleted with the focus rewrite; the two overview fetches stay separate on purpose (one is the filtered list, the other the whole-vault overview) |

## Inventory

| File | Lines | Longest functions | Verdict |
|---|---|---|---|
| `src-tauri/core/src/store.rs` | 1096 | `migrate` 151, `change_password` 126, `migrate_encrypted` 55 | three responsibilities in one type + two dead functions |
| `src-tauri/core/src/portability.rs` | 1088 | `one_password_to_item` 145, `split_csv` 115 | three formats + two exporters in one file |
| `src/VaultShell.tsx` | 827 | one component: 25 `useState`, 6 `useRef`, 11 `useEffect`, 15 `useCallback` | six responsibilities in one component |
| `src/vault/ItemDetail.tsx` | 563 | component 343, `TotpCard` 102, `FieldRow` 77 | long component, clean helpers |
| `src/QuickAccess.tsx` | 534 | component 492 | long component, duplicated row markup |
| `src/vault/Settings.tsx` | 461 | component 434 | five cards inlined |
| `src/vault/MoveData.tsx` | 450 | component 389, 10 `useState` | two flows (import, export) in one component |
| `src/vault/ItemList.tsx` | 441 | component 268, `EmptyList` 91, `Row` 51 | duplicated index arithmetic |
| `src-tauri/core/src/audit.rs` | 411 | `audit_check_breaches` 33, `check_breaches` 31 | fine |
| `src-tauri/core/src/session.rs` | 398 | `state` 35, `change_password` 23 | fine |
| `src/App.tsx` | 365 | `Root` 328 | two near-identical poll effects |
| `src-tauri/src/quick.rs` | 361 | `init` 40, `build_window` 33 | fine |

Feature stylesheets are clean: `history`, `trash`, `audit`, `portability`,
`attachments`, `quick` have no unused classes. The dead weight is in
`app.css` (3 215 lines), already tracked separately.

## Findings

### store.rs — 1096 lines, 42 functions

**Dead code (safe to delete):**
- `raw_row_count` (`:1076`) and `raw_blob_prefix` (`:1082`) have no callers in
  `core/src`, `src-tauri/src`, `core/tests` or `src`. `state()` moved to
  `live_count` during the hardening step, which orphaned the first; the second
  was already dead before it.

**Responsibilities mixed in one type:**
| Block | Lines | Contents |
|---|---|---|
| schema + migration | 146–345 | `migrate`, `has_column`, `pk_columns`, meta key/value |
| vaults | 390–586 | AAD helpers, name encode/decode, list/create/rename/exists |
| unlock + rotation | 587–810 | `meta_identity`, `unlock`, `change_password`, `migrate_encrypted` |
| items + versions + attachments | 811–1075 | load/list/get/save/archive/delete/live_count |

`migrate` at 151 lines is the largest function in the codebase: it both decides
the schema version and rewrites four tables. It is correct (single transaction,
tested) but it is the hardest function to change safely.

**Recommendation:** split into `store/{mod,vaults,items,rotation}.rs` keeping the
public API and the tests as the guard. Move the schema rewrite into
`store/migrate.rs` with one function per version step.

### portability.rs — 1088 lines, 29 functions

Not garbage: names are precise, the CSV parser and the 1PUX reader each have a
single job, and the error model (`ImportReport` with per-row reasons) is shared.
The problem is scale: three importers, two exporters, two category tables and
four shared helpers in one file.

**Recommendation:** `portability/{mod,json,csv,pux}.rs` with `mod` keeping
`Format`, `Parsed`, the `VaultState` methods and the shared `build_item`.
`one_password_to_item` (145 lines) splits into title/notes, urls, tags,
login fields and section fields.

### VaultShell.tsx — 827 lines, 25 state values

The component owns, at once (25 `useState`, 6 `useRef`, 11 `useEffect`, 15 `useCallback`): data loading (two list fetches + one item fetch),
debounce, sorting, selection, editor lifecycle, unsaved-edit guard, titlebar
portals (search, timer, vault switcher), keyboard map, wizard and palette
dialogs, viewport compaction, trash badge and the vault-change reset.

**Concrete smells:**
- `selectedId`, `selectedIdRef` and `itemRequest` all describe the same
  selection; the ref exists only because the list response needs the current
  value inside a closure.
- `filterCheckPending` is a third flag in the same flow.
- `guardedLock` is a one-line wrapper created only to pass through `guard`.

**Recommendation:** four hooks — `useVaultData` (summaries, allItems, counts,
refresh), `useSelection` (selectedId/item/editing/dirty/focus), `useShellPanels`
(filter/panel/query/sort/palette/wizard/compact), `useTitlebarSlots` — leaving
the component with layout and wiring (~250 lines). Do this after the frontend
test runner exists (step 6), otherwise the refactor is unverifiable.

### ItemDetail.tsx — 563 lines

The 343-line component renders eight independent blocks (header, actions,
TOTP card, fields, attachments, websites, tags, notes, footer, delete dialog).
`TotpCard` and `FieldRow` are already extracted and readable.

**Recommendation:** extract `DetailHeader`, `DetailSections` (fields +
websites + tags + notes) and `DeleteDialog`. Medium payoff, low risk.

### QuickAccess.tsx — 534 lines

The 492-line component holds three mutually exclusive surfaces (locked door,
unavailable door, search + rows) plus its own event wiring.

**Duplication with `CommandPalette`:** the row markup —
`palette-row` + `palette-glyph` + `palette-copy` + title + `secondaryText` +
active state — is repeated at `QuickAccess.tsx:420-470` and
`vault/CommandPalette.tsx:232-275`. A shared `<PaletteRow>` primitive removes
~40 duplicated lines and keeps aria/keyboard behaviour identical across the two
palettes.

**Duplication with `ItemList`:** the empty states are copy-pasted —
`Nothing matches “{query}”.` at `QuickAccess.tsx:402` and `ItemList.tsx:369`,
`The vault is empty.` at `QuickAccess.tsx:410` and `ItemList.tsx:421`. A shared
`<EmptyState>` with a `variant` removes four blocks.

### Settings.tsx — 461 lines

Five cards are inlined in one 434-line component (security `:144`, rotation
`:215`, quick access `:281`, appearance `:329`, about `:393`) plus the
`MoveData` card.

**Recommendation:** one component per card. This is mechanical and each card
already has its own state and copy.

### MoveData.tsx — 450 lines

Two independent flows in one 389-line component, 10 `useState` values, two
format tables. `IMPORT_FORMATS` and `EXPORT_FORMATS` are separate constants that
duplicate the same three ids.

**Recommendation:** `<ImportFlow>` and `<ExportFlow>` sharing one format table
and one `busy` contract.

### ItemList.tsx — 441 lines

The virtualisation window and the roving focus now agree, but the index
arithmetic `index - start + spacer` appears twice (`:90` and `:103`) and the
scroll-into-view fallback is written twice (`:92-96`, `:105-126`).

**Recommendation:** one `domIndex(index)` helper and one `revealRow(index, id)`
used by both the selection effect and `focusIndex`. Small, removes a class of
off-by-one bugs.

### App.tsx — 365 lines

Two interval effects (`:210-227`, `:261-269`) share the same shape: call
`api.state()`, reset `coreHealth` on success, `coreFailed` on error, stop when
`boot !== "ready"`. They differ only in the callback and the period.

**Recommendation:** `useCorePoll(periodMs, onState)`; removes ~20 duplicated
lines and the risk of one poll forgetting the health reset.

### Housekeeping found on the way

- `src/vault/Audit.tsx:65` carries `// eslint-disable-next-line
  react-hooks/exhaustive-deps`, but the project has no ESLint. It is a false
  signal; either install the linter or drop the comment.
- 11 `icon-btn` copy buttons and 19 `<Dialog>` call sites repeat the same
  aria/confirm patterns; a `<CopyButton>` and a `<ConfirmDialog>` would remove
  the repetition. Lower priority than the above.

## What is *not* garbage — do not touch

- `lib/catalog.ts` (`secondaryText`, `metaFor`, category metadata): one source
  of truth, used by the list, both palettes and the detail pane.
- `api-*.ts` wrappers: thin, typed, no logic; splitting them further would only
  add indirection.
- Portability's `ImportReport`/`ImportFailure` model and the CSV resync logic.
- Store's AAD helpers (`version_aad`, `history_aad`, `attachment_aad`) and the
  schema-version transaction — recently hardened and covered by tests.
- The feature stylesheets: no dead selectors.

## Status (after the refactor wave)

| # | Action | Status |
|---|---|---|
| 1 | Delete `raw_row_count`, `raw_blob_prefix` | **done** — `rg` finds only this document |
| 2 | Shared `PaletteRow` + `EmptyState` | **done** — `src/ui/PaletteRow.tsx` (81), `src/ui/EmptyState.tsx` (75); one copy of each heading |
| 3 | `Settings` → cards, `MoveData` → two flows | **done** — 461 → 81 and 450 → 39; cards 66–128, flows 139/191 |
| 4 | `domIndex`/`revealRow`, `useCorePoll` | **done** — one index formula in `ItemList.tsx:86`; `src/lib/use-core-poll.ts` (51) replaces both intervals |
| 5 | Split `store.rs` and `portability.rs` | **done** — `store/{mod,migrate,vaults,rotation,items,attachments}.rs` (67–309), `portability/{mod,json,csv,pux,common}.rs` (104–393) |
| 6 | Decompose `VaultShell` into hooks | in progress — hooks under `src/vault/shell/`, component target ≤ 300 lines |

`migrate` and `change_password` are no longer the longest functions: the split
produced `add_deleted_at`, `add_key_version`, `rebuild_item_versions`,
`rebuild_attachments`, `collect_payloads`, `install_new_key`, `reinsert_payloads`
and the CSV parser was proven equivalent by a 437 277-input differential run.

## Priority

| # | Action | Payoff | Risk |
|---|---|---|---|
| 1 | Delete `raw_row_count`, `raw_blob_prefix` | removes dead API surface | none |
| 2 | Shared `PaletteRow` + `EmptyState` | −80 lines, one behaviour for two palettes | low |
| 3 | Split `Settings` into cards, `MoveData` into two flows | −150 lines of nesting | low |
| 4 | `domIndex`/`revealRow` in `ItemList`, `useCorePoll` in `App` | removes duplicated arithmetic | low |
| 5 | Split `store.rs` and `portability.rs` by responsibility | largest maintainability win | medium — tests are the guard |
| 6 | Decompose `VaultShell` into four hooks | largest structural win | high until frontend tests exist |

Items 1–4 are safe now; 5 is safe because 75 core tests cover the behaviour; 6
should wait for step 6 (test runner + error boundary).
