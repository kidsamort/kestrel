# Kestrel — design specification

> The interface is a viewing instrument for a vault it cannot decrypt. Everything
> in this document is either marked **implemented** (in `src/`, exercised against
> the real command surface in `src-tauri/`) or **design-only** (a specification
> with no shipped UI). There is no third category: the app never renders a
> control it cannot honour.

---

## 1. Direction

**Graphite.** A neutral instrument: white and slate grounds by day, graphite by
night, hairline structure, and **one accent the user chooses** from six presets.
The accent is a system colour — not a brand, not a semantic. It marks the
primary action, the current selection and the live one-time code; errors,
success and warnings keep their own independent colours.

- **Named material.** Neutral stocks, not "backgrounds": `ground`, `list`,
  `sidebar` and one raised `surface`, separated by hairlines. Only menus,
  dialogs and the palette carry elevation. There is no texture, no gradient
  decoration, no glass.
- **Density.** Compact but airy: 47 px list rows, 27 px navigation rows, 13 px
  UI type, 11.5 px meta, 10.5 px uppercase eyebrows. A 1180 × 760 window shows
  all 18 categories, the list and a complete item without scrolling the shell.
- **Typographic voice.** **Inter at 400/500/600 only**, vendored locally. No
  display face: hierarchy comes from size, weight and letter-spacing, not from a
  second family. Cascadia Mono is kept for secrets, codes and numerals, because
  it is a machine voice, not a decoration.
- **Motion character.** Quiet and directional: 90 ms state, 140 ms surfaces,
  200 ms layers, two easings, no bounce. Values animate in place; panes never
  slide. `prefers-reduced-motion` collapses all of it.
- **What this makes the product.** Clear: every field, count and state is a
  record. Calm: one accent at a time, chosen by the person. Predictable: panels
  never move, selection never rearranges the shell, and security actions are
  immediate and labelled.

### Rejected alternatives

| Direction | Why rejected |
|---|---|
| **Paper ledger with a serif display face** (previous pass) | A second family and a warm paper metaphor put literature ahead of the tool; the product owner rejected any serif outright. |
| **One fixed chestnut brand accent** (previous pass) | Reads as branding, not instrumentation; the accent must be a user preference and pass contrast in six variants. |
| **Frosted glass / translucent panels** (Arc-style) | Hides hierarchy behind blur, weakens text contrast, and makes a trust product look like a demo. |
| **Dark-first "hacker terminal"** (mono everywhere) | Signals hostile tooling; the product is for normal people storing passports. |
| **Branded blue cards, one card per field** | Imitation, and card-per-field adds elevation noise to a page that should read as a record. |
| **Category colour coding** (18 hues) | A rainbow destroys a single-accent system and fails colour-blind users; category is carried by icon + label + count. |

---

## 2. Tokens

All values live in `src/styles/tokens.css`; fonts in `src/styles/fonts.css`.
Nothing outside those files invents a colour, radius, shadow or duration.

### 2.1 Colour — neutral grounds

Every surface token is achromatic (equal R/G/B) in the default blue accent;
non-blue accents tint these same slots — see §2.4.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--ground` | `#f6f6f6` | `#000000` | window ground, detail page |
| `--surface` | `#ffffff` | `#101010` | cards, field table, raised stock |
| `--sidebar` | `#efefef` | `#080808` | navigation column |
| `--list` | `#f8f8f8` | `#0a0a0a` | item list |
| `--sunken` | `#e9e9e9` | `#161616` | editor bars, inset chrome |
| `--input` | `#ffffff` | `#121212` | input fields |
| `--ink` | `#12151a` | `#e8ecf2` | primary text |
| `--ink-2` | `#3c4450` | `#b6bfcc` | values, secondary text |
| `--ink-3` | `#5d6673` | `#8d97a6` | labels, meta, empty values |
| `--line` | `#e4e4e4` | `#222222` | hairlines |
| `--line-strong` | `#cdcdcd` | `#303030` | control borders |
| `--hover` | `#eeeeee` | `#181818` | hover washes |
| `--selected` | `#e7e7e7` | `#1e1e1e` | selected rows/nav |
| `--danger` / `--danger-soft` | `#b42318` / `#fef3f2` | `#f97066` / `#3a1d1b` | destructive, errors |
| `--ok` / `--ok-soft` | `#067647` / `#ecfdf3` | `#75e0a7` / `#10241a` | success, strength 4 |
| `--warn` / `--warn-soft` | `#b54708` / `#fffaeb` | `#fdb022` / `#2b2114` | unsaved changes, pre-lock |
| `--scrim` | `rgb(16 20 26 / .32)` | `rgb(0 0 0 / .60)` | modal backdrop |

Status colours are **not** derived from the accent and never change with it.

### 2.2 Colour — accent presets

Six presets, each declared per `[data-accent]` for both themes. The accent token
set is: `--accent`, `--accent-hover`, `--accent-pressed`, `--accent-soft`,
`--accent-line`, `--on-accent`, plus `--selected-bar` (the 2 px nav ribbon). The
focus ring is derived (`--focus-ring: 0 0 0 1px var(--ground), 0 0 0 3px
var(--accent)`), as is the inset variant used on rows.

| Preset | Light accent | hover / pressed | soft / line | on-accent |
|---|---|---|---|---|
| Blue | `#1d4ed8` | `#1a46c2` / `#173ead` | `#e4eafa` / `#a9bcf0` | `#ffffff` |
| Teal | `#0f766e` | `#0e6a63` / `#0c5e58` | `#e2efee` / `#a4cbc8` | `#ffffff` |
| Green | `#166534` | `#145b2f` / `#12512a` | `#e3ede7` / `#a6c4b2` | `#ffffff` |
| Amber | `#92400e` | `#833a0d` / `#75330b` | `#f2e8e2` / `#d6b6a3` | `#ffffff` |
| Rose | `#be123c` | `#ab1036` / `#980e30` | `#f7e3e8` / `#e6a5b5` | `#ffffff` |
| Violet | `#6d28d9` | `#6224c3` / `#5720ae` | `#ede5fa` / `#c8adf1` | `#ffffff` |

| Preset | Dark accent | hover / pressed | soft / line | on-accent |
|---|---|---|---|---|
| Blue | `#93b4ff` | `#9ebcff` / `#84a2e6` | `#2d3648` / `#4f5f84` | `#0b1220` |
| Teal | `#5eead4` | `#6eecd8` / `#55d3bf` | `#243f40` / `#377871` | `#06201d` |
| Green | `#86efac` | `#92f1b4` / `#79d79b` | `#2b4039` / `#497a5f` | `#052e16` |
| Amber | `#fcd34d` | `#fcd75f` / `#e3be45` | `#403b28` / `#7e6d34` | `#241403` |
| Rose | `#fda4af` | `#fdadb7` / `#e4949e` | `#40333a` / `#7f5860` | `#260812` |
| Violet | `#c4b5fd` | `#cabcfd` / `#b0a3e4` | `#363648` / `#656083` | `#150a2a` |

Default accent is Blue, in both themes. The choice is stored under
`kestrel.accent` and applied to `<html data-accent>` before React mounts.

### 2.3 Measured contrast per preset

WCAG 2.1 relative-luminance formula over the shipped hex values. Requirements:
`on-accent` on `accent` ≥ 4.5; accent used as text/icon on `surface` ≥ 4.5;
accent text on `accent-soft` ≥ 4.5 (segmented controls); focus ring (the accent)
against `surface` ≥ 3 (satisfied by the accent/surface ratio).

| Preset | Theme | on-accent / accent | accent / surface | accent on accent-soft |
|---|---|---|---|---|
| Blue | light | 6.70 | 6.70 | 5.57 |
| Teal | light | 5.47 | 5.47 | **4.64** |
| Green | light | 7.13 | 7.13 | 5.95 |
| Amber | light | 7.09 | 7.09 | 5.88 |
| Rose | light | 6.29 | 6.29 | 5.12 |
| Violet | light | 7.10 | 7.10 | 5.82 |
| Blue | dark | 9.11 | 8.48 | 5.89 |
| Teal | dark | 11.52 | 11.78 | 7.63 |
| Green | dark | 10.62 | 12.41 | 7.89 |
| Amber | dark | 12.38 | 12.09 | 7.77 |
| Rose | dark | 9.86 | 9.22 | 6.34 |
| Violet | dark | 10.26 | 9.44 | 6.40 |

The tightest pair in the product is teal on its own tint in light mode at
**4.64:1**; every filled button, accent icon and focus ring clears its
threshold in both themes.

Neutral pairs (measured, same formula): ink/ground 16.92 · ink-2/ground 9.10 ·
ink-3/ground 5.37 · ink-3/sidebar 5.13 · danger/ground 6.08 (light) and
ink-3/ground 6.40 · danger/ground 6.78 (dark). Status text on its soft ground:
warn 5.20, ok 5.40 (light); warn 8.58, ok 10.06 (dark).

### 2.4 Surface temperature

Two rules, both machine-generated so they cannot drift:

1. **The default (blue) accent keeps a strictly achromatic stack.** Every surface
   token has equal R/G/B channels, so the dark theme's ground is `#000000`
   (OLED pixels stay off) and the layers above it lift in grey steps:
   `#000000` → `#080808` → `#0a0a0a` → `#101010` → `#121212` → `#161616` →
   `#181818` → `#1e1e1e`, with lines at `#222222` / `#303030`.
2. **Every other accent tints the stack, never the default.** The tint keeps the
   neutral layer's lightness and borrows the accent's hue, taking only a fraction
   of its saturation (`--saturation × factor` in HSL). Lightness is preserved by
   construction, so contrast cannot regress and only temperature moves.

| Layer | Light factor | Dark factor |
|---|---|---|
| ground | 0.16 | 0.00 (stays `#000000`) |
| surface / input | 0.09 / 0.08 | 0.05 / 0.04 |
| list / sidebar | 0.18 / 0.22 | 0.06 / 0.08 |
| sunken / hover | 0.26 / 0.26 | 0.09 / 0.09 |
| selected | 0.34 | 0.12 |
| line / line-strong | 0.30 / 0.38 | 0.09 / 0.14 |

`tools/gen-surface-tints.py` reads `tokens.css`, resolves each accent per theme
and writes `src/styles/tints.css` (imported after `tokens.css`). Blue declares no
overrides, so switching back to it restores the neutral ramp by cascade. Status
colours (`danger`, `ok`, `warn`) never take the accent.

Measured after tinting (`token_audit.py`, 12 theme × accent pairs): text on
ground 15.93–17.71:1, accent on ground 5.09–14.96:1, on-accent 5.47–12.38:1 —
all above 4.5:1.

### 2.5 Typography

One family. **Inter** 400/500/600, latin subset, vendored:

| File | Weight | Size |
|---|---|---|
| `src/assets/inter/inter-latin-400-normal.woff2` | 400 | 23.66 kB |
| `src/assets/inter/inter-latin-500-normal.woff2` | 500 | 24.27 kB |
| `src/assets/inter/inter-latin-600-normal.woff2` | 600 | 24.45 kB |

`@font-face` uses `font-display: block` and the three files are preloaded from
`index.html`; they are local app assets, so text is painted in Inter rather than
briefly in a fallback. No remote request (strict CSP, no network in the renderer).
Weights are real: no synthetic bolding, no italic face.

| Role | Size / line-height | Weight | Tracking |
|---|---|---|---|
| Gate headline | 34 / 1.12 | 600 | −0.03em |
| Page/dialog heading | 22–24 / 1.25 | 600 | −0.02em |
| Item detail title | 19 / 1.25 | 600 | −0.02em |
| List title | 15 | 600 | −0.015em |
| Empty-state title | 15 / 1.35 | 600 | −0.01em |
| Editor title | 21 | 600 | −0.02em |
| Body / values | 13 / 13.5 | 400 | 0 |
| Field labels, meta | 11.5 | 500/400 | 0 |
| Eyebrow | 10.5, uppercase | 600 | +0.12em |
| Secrets, codes, numerals | 12–27 | mono | 0 |

**Mono stays** (Cascadia Mono → Consolas) for passwords, keys, TOTP codes,
website URLs and numeric chrome (counts, timers). It is a machine voice, not a
display face.

### 2.6 Space, radii, elevation, icons, motion

- **Space** — 4 px grid: 2/4/6/8/12/16/20/24/32.
- **Radii** — 2 px badges, 4 px controls/rows, 6 px cards/menus, 10 px
  dialogs/palette, pill for counts, tags, switches and accent chips.
- **Elevation** — flat surfaces with hairlines; two shadows only
  (`--shadow-pop`, `--shadow-dialog`).
- **Icons** — Lucide, 1.5 px stroke: 15–16 px rows/nav, 13–14 px inline actions,
  22 px detail header, 12 px hints. Every icon-only control has an `aria-label`.
- **Motion** — 90/140/200/320 ms, `cubic-bezier(.2,.7,.3,1)` and
  `cubic-bezier(.4,0,.2,1)`; no bounce, no parallax. Reduced motion clamps all
  durations.

### 2.7 Focus contract

Exactly **one** focus indicator per control, keyboard-only, never clipped:

| Surface | Owner | Rule |
|---|---|---|
| `input-shell`, `search`, `select-shell` | the wrapper | `[data-modality="keyboard"] .input-shell:focus-within { box-shadow: var(--focus-ring) }`; the inner `input`/`select` sets `box-shadow: none` (and never draws its own) |
| `textarea`, editor field inputs, editor title, tag input, URL input, palette input | the control | modality-gated `:focus` rule with `var(--focus-ring)`; no border-colour change |
| buttons, links, switches, tooltip/menu/dialog triggers | the control | global `:focus-visible { box-shadow: var(--focus-ring) }` |
| list rows, sidebar rows, menu items, window controls, field-row icon buttons, accent chips, tags, segmented controls | the control | `--focus-inset` (a 2 px inset accent ring) so a ring is never clipped by scroll containers or `overflow: hidden` |
| palette rows | not focusable | the combobox input owns the indicator; the active row is marked with `aria-selected` + a background ribbon |

`data-modality` is set to `keyboard` on any `keydown` and `pointer` on any
`pointerdown` (capture phase, once at app root). Text fields therefore show a
ring for keyboard entry and not for mouse clicks, which native `:focus-visible`
cannot distinguish. Composite wrappers only ever draw the outer ring; the inner
field is explicitly zeroed, which removes the double ring.

---

## 3. Component inventory

| Component | States |
|---|---|
| **WindowBar** | locked (brand only), unlocked (vault label, auto-lock meter, Lock), window hover/pressed, close hover (danger fill) |
| **Mark** | typographic K in a squared stock with a 3.5 px accent seal dot |
| **Gate** | first run, locked, manual lock, idle lock, busy (derive/decrypt), inline error, caps-lock hint, strength segments 0–4, mismatch, reveal on/off |
| **Button** | primary / secondary / ghost / danger / quiet × sm/md/lg, icon-only, block, disabled (neutral surface, not faded accent), focus |
| **TextField** | label, hint, error, leading icon, trailing action, quiet label (sr-only), invalid, focus |
| **TextArea** | bordered, resizable, hinted |
| **Switch** | off/on/disabled/focus |
| **Segmented control** | selected (accent-soft + accent border + bold), unselected, pressed, keyboard ring (inset) |
| **Accent chip** | unselected, hover, selected (accent border + accent-soft + check), focus (inset ring) |
| **InputSearch** | idle, focus, filled + clear, empty result |
| **Nav item** | normal, hover, active (ribbon + stock), zero-count (muted), compact rail |
| **List row** | normal, hover, selected (stock + ribbon + glyph border), favorite star, TOTP badge, focus, virtualised spacing |
| **List header** | title + count, New item menu trigger, sort menu, filter chip |
| **Detail** | idle, loading, loaded, TOTP live/expiring/failed, empty field, masked → revealed, copied (1.4 s check), favorite |
| **Field table** | single-line, multiline (keys), masked, empty, actions at 55 % until hover/focus |
| **TOTP card** | code, seconds badge (accent → danger ≤ 5 s), copy, fetch error |
| **Editor** | clean, dirty, saving, save error, generated value applied, TOTP-invalid, discard guard, new item rollback |
| **Generator** | password mode, passphrase mode, invalid class selection, regenerating, copied, dialog variant with "Use password" |
| **Settings** | auto-lock saving, clipboard fixed value, rotate (idle/busy/success/error), theme system/light/dark, accent presets, about, keyboard map |
| **Palette** | empty query (commands first), query (items first), no match, active row, scrolled results |
| **Notice** | success, danger, neutral, warn; stacked max 3; lifts above the pre-lock bar |
| **Dialog** | standard, alert (destructive), palette, scrim, entrance |
| **Menu** | item, disabled, danger, separator, checkbox, submenu, 2-column category grid |
| **Tooltip** | label + optional chord, ink on ground |
| **Pre-lock bar** | countdown > 0, at 0 ("Locking the vault…"), "Stay unlocked" |
| **States** | boot, core-unreachable (fatal), locked, unlocking/deriving, empty vault, empty category, no results, load error |

---

## 4. Interaction

### 4.1 Keyboard map (implemented)

| Chord | Action |
|---|---|
| `Ctrl K` | Command palette (toggle) |
| `Ctrl F` | Focus search (switches to the vault view) |
| `Ctrl N` | New login, opened in the editor |
| `Ctrl E` | Edit the open item |
| `Ctrl S` | Save while editing |
| `Ctrl G` | Generator |
| `Ctrl ,` | Settings |
| `Ctrl L` | Lock vault (immediate, from any unlocked surface) |
| `Ctrl 1` / `Ctrl 2` | All items / Favorites |
| `↑` `↓` | Move the item selection (list or palette) |
| `Home` / `End` | First / last item in the list |
| `Enter` | Open the active palette row; submit unlock/create; activate a row |
| `Esc` | Close a dialog/menu; clear search; cancel the editor (with discard guard) |
| `Alt R` | Regenerate in the generator |
| `Tab` / `Shift Tab` | Standard order; skip link appears on first focus |

### 4.2 Focus order

Titlebar (Lock, window controls) → skip link → sidebar (All, Favorites, 18
categories, Generator, Settings, Lock) → list header (New item, search, sort) →
rows (roving tabindex: the selected row is the only tab stop; arrows move focus
and selection) → detail actions (star, Edit, more) → detail content (reveal,
copy, tags) → pagination-free footer. Dialogs trap focus and restore it on
close. After selecting an item the detail is not focused automatically, so the
list keeps keyboard momentum; `Ctrl E` and the Edit button are the explicit
way in.

### 4.3 Security interaction

- **Auto-lock warning.** The Rust watchdog is the authority. The renderer mirrors
  its clock from real input events, pings `touch_vault` at most every 8 s, and
  warns when half the timeout remains (capped at 30 s). "Stay unlocked" calls
  `touch_vault` and resets the local clock; the countdown then restarts. At zero
  the bar reads "Locking the vault…" and the core's next watchdog tick (≤ 5 s)
  emits `vault://locked`, which the UI follows by clearing all decrypted state.
- **Copy feedback.** All copies go through the core (`copy_field` / `copy_text`)
  so the wipe timer starts in Rust. The toast states the real interval
  ("Clears from the clipboard in 30 seconds") and the control shows a check for
  1.4 s. Failure (clipboard busy) is a danger toast.
- **Reveal.** Secrets reveal one field at a time and hide on window blur,
  document hide, item change, or lock. There is no reveal-all.
- **Lock is immediate.** Manual lock does not ask to save a draft; a vault never
  negotiates with a lock request. The editor marks unsaved work continuously so
  the risk is visible before it happens.

### 4.4 Command palette

`Ctrl K` opens a dialog-combobox over real data (`list_items` summaries, which
by contract never contain secret values) and the commands that exist: go to
items/favorites, Generator, Settings, Lock, and "New <category>" for all 18
categories. Empty query → commands first, then three items; typing → items
first, then matching commands. `aria-activedescendant` tracks the active row.
No command is listed that the core cannot execute.

---

## 5. Screens (implemented)

### 5.1 First run · create vault — **implemented** (rendered; see §9 honesty note)
Two-stock gate: an intro column (eyebrow "Local vault · this device only",
display "One password, kept nowhere.", Argon2id / XChaCha20 / SQLite / network
facts, core-automation footer) and a door column with the form.

**A vault is a file the person names and places.** The form asks for a vault name
(default `personal`, saved as `<name>.db`), a folder (prefilled with
`Documents/Kestrel`), the password twice, and an optional **password hint** —
plaintext by design, shown on the lock screen, stored unsealed in the vault's own
`meta` table so it travels when the file is moved. A name that already exists in
that folder is refused with "a vault with this name is already in that folder"
and nothing is overwritten; a path that is not absolute is refused, because a
relative one would resolve against whatever directory the app started from.

Fields: new password, confirm, asymmetric reveal, strength estimate (bits ×
character classes, labelled "estimate"), ≥ 10-character rule, mismatch on blur,
Argon2id pause copy. Errors: weak/mismatch inline; core failure as a callout.
Keyboard: autofocus, `Tab` to confirm, `Enter` submits. Edge: app is locked while
the KDF runs (button reads "Deriving key…", disabled).

The gate has two more states, both honest about a vault nobody can open without
its password: **locked** (hint, file name, "Show in folder", and an expandable "I
don't remember the password" panel that says the file is untouched and offers a
recovery code or a new vault elsewhere) and **missing** (a remembered file that
is gone; the app never recreates it and never silently replaces it).

### 5.2 Unlock — **implemented**
Same geometry as create. Eyebrow "Locked", "Welcome back.", sub-line depends on
why: manual ("Encrypted at rest · auto-lock N"), idle ("The vault locked itself
after inactivity. Your work is saved."). Wrong password → callout "That master
password cannot decrypt this vault.", field marked invalid, value selected for
retyping. Caps Lock detected and named. The native WebView reveal eye is
suppressed in favour of the labelled control.

### 5.3 Vault shell — **implemented**

Row commands: the detail header keeps only the favourite indicator and the
overflow menu; "Edit item", "History" and the favourite toggle live in the
overflow. Right-clicking a row opens the same commands (Open, Edit, favourite,
Move to trash) as a context menu, so a list item can be acted on without
selecting it first.
Sidebar: All items with count, Favorites with count, 18 categories with counts
(real, derived from a full summary list), Generator, Settings, Lock. Active row
uses stock + 2 px accent ribbon + accent icon. Under 1080 px the rail
collapses to icons with tooltips and aria-labels; all 18 still reachable.

List pane: title + live count, "New item" menu (all 18 categories, two columns),
search, sort (Title / Recently updated, client-side over real `updatedAt`),
filter chip with clear. Rows show category glyph, title, secondary value
(username → host → category), TOTP badge, favorite star. Virtualised above 80
rows (fixed 47 px height, overscan 6) so no per-render style work scales with
vault size. States: loading skeleton, empty vault onboarding, empty category
(with a real create action), no results (explains that secrets are excluded from
search).

Detail: category glyph, eyebrow, item title, edited-time and favorite meta,
star, Edit, overflow (Copy notes, Edit, Delete). Quick-copy strip for the
primary secret and username; TOTP card; grouped Details; Websites; Tags
(clickable → search); Notes; created/edited footer with "Sealed with the vault
key". Empty fields render as "—" except empty URL fields into a URL block.

### 5.4 Editor (18 categories) — **implemented**
Full-pane takeover with a status bar ("Editing" / "Unsaved changes"), inline
title, field table (label, kind picker, value, per-field actions: generate for
password-like kinds, secret toggle, remove), dashed "Add field" row, notes,
and two organisation cards (favorite + tags; websites + TOTP secret with base32
validation). Save/Cancel in the header and `Ctrl S`/`Esc`; the footer repeats
the chords and counts. `create_item` returns a draft the core has not stored, so
cancelling a brand-new item simply drops it: there is no row to roll back and no
"Untitled" husk. Switching away with a dirty draft opens the discard dialog.

Two field kinds carry their own behaviour. `seedPhrase` is a wallet recovery
phrase: multiline, monospace, whitespace-normalised on save, masked until
Reveal, with a word-count chip (12/15/18/21/24) that warns rather than blocks,
and it is excluded from `search_text` by kind as well as by the sensitive flag —
an imported item that cleared the flag still cannot get a seed phrase into the
index. `date` renders a relative hint when the label mentions expiry
("expires in 12 days", "expired 3 days ago"), which is the same data the
Expiry rules read. The Wallets and API Credentials templates ship with
these fields (address/network/derivation path/phrase/spending password, and
provider/base url/client id/client secret/token/expires at).

### 5.5 Generator — **implemented**
Standalone page and inline dialog. Live value from `generate_password`, bits
from the generator's own alphabet and length, mode switch, length 8–64 (core
clamps 8–128), class switches, ambiguity filter, passphrase words 3–12 and
separator. Invalid (no class) disables copying and explains that the core would
silently fall back to lowercase. Copy uses the core wipe path. `Alt R`
regenerates.

### 5.6 Settings — **implemented**
Security: auto-lock select (1/5/15/30/60 min, 8 h) calling `set_autolock`;
clipboard interval shown read-only with the reason; Lock now. Master password:
current/new/confirm with rotation warnings, real `change_password`, success
state. Appearance: theme System / Light / Dark and six accent presets as keyboard-
reachable chips (`aria-pressed`, check + tinted stock for selection), both
persisted under `kestrel.theme` / `kestrel.accent` and applied before first
paint. About: `app_meta` name/version/format, item count, renderer facts,
keyboard map.

### 5.7 States & system — **implemented**
Boot ("Opening vault…"), core unreachable (honest error with Retry and an
explanation that the renderer has no keys), manual lock, idle lock, delete
confirmation (no undo, no trash yet), discard guard, pre-lock bar, toasts, and
responsive layouts at 900–1600 px.

---

## 6. Capability specs (1–31)

Legend: each item is marked **done** (implemented end-to-end: command, UI and
core test) or **designed, not built** (a specification the code cannot yet
serve). Items 1–11 live in `ROADMAP.md`; 12–25 are done; 26–30 are designed.

### Phase 2 — organisation

> **Status:** 12–18 are implemented (commands, UI, tests). 12 lands as a session
> scope rather than a new command surface: `vault_switch` re-points the session,
> and every existing command reads the active vault's ciphertext unchanged.

**12 · Multiple vaults — done.** The toolbar's vault label is the switcher:
menu of vaults with counts, "New vault…", "Manage vaults…" (rename). Switching
re-scopes the session; the palette labels its results with the active vault.
Original spec: Sidebar gains a vault switcher in the titlebar:
vault name + chevron, listing vaults with item counts, "New vault…" and
"Manage". Creating a vault is the same create-vault door as first run, inside a
dialog. The list/detail panes stay identical; every view is scoped to the
active vault. States: one vault (plain label), switching (session re-key, brief
lock), unavailable vault (locked badge). Copy: "Vaults are separate keys, not
folders." Edge: cross-vault search is never silent — the palette scopes to the
active vault and labels results. Backend: `list_vaults`, `create_vault(name)`,
`switch_vault`, per-vault sessions; `list_items` gains a vault scope.

**13 · Item history / restore — done.** Detail overflow → "History". The rail is a
340 px drawer **over** the detail pane, not a third column: opening history must
not narrow the item being read. A read-only
rail of versions with timestamp, editor (device name later), and a diff-style
field list; "Restore this version" writes a new version and shows a toast. The
current version is marked "Current". No destructive purge from this screen.
Backend: version rows are already stored; needs `list_versions(item)`,
`get_version(item, version)`, `restore(item, version)`.

**14 · Attachments / documents — done.** Drop zone inside the Documents category
and an "Attachments" block on every item: filename, size, checksum prefix, add
via picker, save-as, remove. Files inherit the item's key; previews are never
rendered inline (no HTML/PDF surface). States: empty, uploading (sealed before
write), too large (size limit shown), missing blob. Backend: content-addressed
blob table, `add_attachment`, `read_attachment`, `remove_attachment`; core-side
streaming.

**15 · Trash, restore, purge — done.** Sidebar gains "Trash" under Favorites with a
count. List rows show deleted-at and "Restore"; detail is read-only with a
danger "Delete permanently" (type the title to confirm). Empty trash is a
separate action with its own confirmation. Copy: "Trash keeps the ciphertext;
purge removes the row." Edge: purged items leave broken links in later sharing
— link state becomes "removed". Backend: `deleted_at`, `trash_item`,
`restore_item`, `purge_item`, `empty_trash`; `list_items` filter.

**16 · Import / export — done.** Settings → "Move data": import (1PUX, CSV, JSON)
as a three-step flow — choose file, map columns/categories with a real preview
of the first rows, then a sealed import report (imported/skipped/failed with
reasons). Export is JSON or 1PUX behind the master password, written with an
explicit warning that the file is plaintext when decrypted. Edge: duplicate
titles are imported, not merged; attachments require 1PUX. Backend: importer
crate, export command with progress events.

**17 · Audit (weak, reused, breached, expiring) — done.** A "Security audit" view
under a new sidebar section: three counter cards (weak, reused, breached) and an
expiry header that keeps `expired` and `expiring` apart, all computed offline for
reuse; breach checks require a k-anonymized HIBP range query *from the core*,
never the renderer. Each finding lists the affected items with the specific
field, and a "Fix" action opens the editor on that field with the generator
preloaded. Copy is careful: "Checked on this device" vs "Checked against a
breach range; the password never leaves the core." Edge: no network → the
breach panel says "Offline — reuse and strength still checked". The expiry rules
read a `date` field whose label mentions expiry: `expiring` inside 30 days,
`expired` in the past, and a missing or unparseable date is **skipped** rather
than reported as expired, because a false alarm on a token that never had a date
trains people to ignore the report. Backend: `audit_report`, HIBP client behind
the core, passwords never serialized.

**18 · Quick access palette (global hotkey) — done.** Implemented as a second
420 px webview that shares the core session; the palette unlocks the main window
and vice versa. When another application already owns `Ctrl+Shift+Space`, the
registration failure is surfaced in Settings (with the system error), the
palette stays reachable from there, and `Ctrl+Shift+K` opens it from the main
window. Original spec: A compact always-available
window (Ctrl+Shift+Space via Tauri global-shortcut): search, item rows,
copy username/password, open in main window. It must unlock independently
(biometric or password) and never shows secrets until unlocked. Design: 420 px
surface card, same glyphs, no sidebar. Edge: focus stealing, lock state, multi-
monitor placement. Backend: `tauri-plugin-global-shortcut` plus a second window that shares the
session (`src-tauri/src/quick.rs`).

### Phase 3 — system integrations

**19 · Browser-extension bridge — done.** Settings → "Browser": connection status
(pipe name, extension version), enable/disable, per-site autofill policy. In
the browser, an inline suggestion chip opens a native confirmation (item +
domain shown). The app never silently fills. Edge: pipe unavailable, version
mismatch, locked vault (prompt in-app). Backend: named pipe `\\.\pipe\kestrel`,
MV3 extension, origin binding; no secrets cross IPC — the core writes the
clipboard/autofill payloads.
**Shipped** — `kestrel-nmhost.exe` is Chrome/Edge's native-messaging child: it
speaks length-prefixed JSON on stdin/stdout and forwards each request to
`\\.\pipe\kestrel-sdk`, so there is still one automation surface, not a second
one. The bridge authenticates with a `Browser`-scoped token minted when the user
installs the host and kept in a user-only `bridge.token` file next to the vault;
that file is a secret at rest, which is why the card says so and why uninstall
deletes it. The token deliberately survives a lock: while the vault is locked
every browser op answers `locked`, so the file alone reveals nothing, and
revoking it on every lock would break the bridge after each auto-lock. The
session tokens (CLI, MCP) do die on lock; the browser one is the exception, and
that exception is the whole reason it lives on disk. Origins are canonicalised
(`https://Example.COM:443` is one origin) and a rule in `browser_sites`
(`fill`/`ask`/`off`, missing = `ask`) decides whether a reveal is allowed; every
granted reveal appends a `browser:<origin>` row to `mcp_audit`. The MV3
extension shows a chip on a login page and fills only after the in-page
confirmation — no value is stored in `chrome.storage` or logged.
One correction to the sentence above: a value **does** cross the native-messaging
channel, because that is what filling a page requires. What does not happen is a
value reaching the renderer, a log, or any network.
Verified live: the compiled host was spawned and driven over stdin/stdout with
Chrome framing, read the real token file, and served `browser.items` and
`browser.reveal` from a real unlocked vault over the real pipe — including the
`off`-origin refusal and the audit row. Not verified: the extension was
syntax-checked and its id pinned but not loaded into a browser, and the Tauri
command boundary was exercised through the module rather than a Settings click.

**20 · Autofill into Windows apps — done.** An overlay picker anchored to the
focused field (UI Automation): search, recent for the app's executable, item
rows; "Fill" is explicit. Settings lists per-app rules. Edge: elevated windows
(must refuse and explain), no matching item, secure desktop. Backend:
UI Automation provider + Win32 focus hooks; requires signed binaries.
**Shipped** — one observer thread runs `SetWinEventHook(EVENT_OBJECT_FOCUS)` and
resolves the focused element through `IUIAutomation`: control type, `IsPassword`,
automation id, class, screen rect and the owning image name, with a per-focus
debounce. A rule per executable (`fill`, `ask`, `off`; a missing row is `ask`)
decides whether the picker may open on focus or only on `Ctrl+Shift+F`. The
overlay is a `WS_EX_NOACTIVATE` webview anchored below the field and clamped to
the monitor work area, so it never takes the caret from the application. Fill is
always a press: `IUIAutomationValuePattern::SetValue` and nothing else — no
synthesised keystrokes — the value is resolved inside the core and never enters
the overlay's state, the rule is re-read at the moment of the write so `off`
wins, and the focused element's key is re-checked so a moved caret refuses.
A target at a higher integrity level is refused with the reason on screen; this
binary is unsigned, so that refusal is the honest behaviour, not a gap. The
window is `WS_EX_NOACTIVATE` so appearing never takes the caret, and that style
is what makes it unfocusable — so a click inside the picker clears it for the
typing part (`autofill_take_input`) and hiding puts it back, with a test that
reads the bit back from a real window.
Verified live against a Win32 probe dialog: with `fill` set, focusing the
password field opened the picker beside it, the rows rendered, and `Fill
password` wrote the vault value into the field. The elevated-window refusal and
the anchor geometry are unit tests; no live elevated target was exercised.

**21 · Passkey provider — done, one step unproven.** Detail of a login gains a
"Passkeys" block (credential id, rpId, created, last used; "Remove").
Registration/assertion UI is a system dialog with Kestrel branding, showing the
site and account before approval. Settings → "Passkeys" explains the COM registration state. Backend:
WebAuthn provider + COM server, CBOR/CTAP handling.
**Shipped, with one step unproven** — `kestrel-passkey` holds the wire format
(minimal CBOR, COSE ES256/P-256, authenticatorData flags and signCount,
attestation `none`, CTAP2 `makeCredential`/`getAssertion`, `authenticatorGetInfo`)
and a hand-written `IPluginAuthenticator` COM server; the shell runs a user-only
pipe whose CTAP2 service creates a login on registration and signs assertions
from the unlocked session. Keys are sealed under the item key with the AAD
`kestrel/v1|passkey|account|vault|credential`, re-sealed on password rotation and
purged with the item — `core/tests/passkeys.rs` proves the old password can no
longer open a credential and the new one can. The block appears only for
`login`, because a credential is bound to an rpId.
What is *not* proven: `WebAuthNPluginAddAuthenticator` returns
`0x80090027` (NTE_INVALID_PARAMETER) on this machine, so Windows does not route
passkeys here yet. The class is registered per user and the WebAuthn broker may
require a machine-wide (HKLM) registration — an elevated step this build does not
perform — or the CBOR `getInfo` payload is wrong; neither is established, and the
card says so instead of claiming success. COM activation of the DLL itself works
and the registration round trip is a live test. Assertions are gated in the app, not by the pipe: nothing in the protocol proves
the person asked, and the pipe's DACL only proves the caller is this user, so
`get_assertion` emits an approval request, blocks for an answer, and sets the
user-presence flag only after an explicit Approve (a denial, a timeout, or no
window to ask in refuses the signature). That is presence, not verification: the
provider still performs no PIN or biometric check (`uv: false`), does not verify
Windows' per-request signature, and no browser ceremony was completed — that
needs a signed binary and a real gesture.
The system dialog is Windows-owned; Kestrel supplies only its name and AAGUID.

**22 · SSH agent + git signing — done.** SSH key items show "Agent" status (loaded,
fingerprint, expires) with Load/Unload, plus git signing configuration copy.
Sockets/pipe paths are surfaced honestly. Edge: agent already running, key
passphrase. Backend: `\\.\pipe\openssh-ssh-agent` server, Ed25519 sign, agent
protocol; keys must never leave the core. **Shipped** — the pipe carries a
user-only DACL (verified from the kernel), refuses a second owner, and serves
`sshKey` items through the session, so locking the vault revokes it.

**23 · Windows Hello unlock — done.** Gate adds "Unlock with Windows Hello" as a
secondary action when enrolled; Settings → Security shows enrolment state and
"Remove Hello unlock". The master password always remains a fallback. Copy
explains what is stored. Edge: Hello unavailable/changed, TPM absent.
**Shipped** — a TPM-backed CNG key (`Microsoft Platform Crypto Provider`) with
an `NCRYPT_UI_PROTECT_KEY_FLAG` UI policy wraps the vault key, so the gesture
happens inside `NCryptDecrypt` and the stored blob is useless without it.
Passport KSP was probed and rejected (it cannot create keys without a WHfB
container); DPAPI was probed and rejected as the mechanism — it answers any
process running as the same user, so consent would be the only gate and not
enforced by crypto. Enrolment is recorded per vault in `hello.mechanism` and
dropped on password change.

**24 · MCP server for environment secrets — done.** Settings → "Developer" shows
MCP server state, the pipe path, and a per-scope allowlist of items/environment
variables. A confirmation is required for every new client; an audit list shows
which client read which secret and when. Never expose secret values in the
renderer. Backend: MCP over stdio/named pipe with tools (`list_secrets`,
`get_secret`) gated by explicit grants.
**Shipped** — `kestrel-mcp.exe` is its own crate with no vault code in it: it
speaks MCP over stdio and is a client of `\.\pipe\kestrel-sdk`, exactly like
the CLI, with the token from `KESTREL_TOKEN`. Two tools: `list_secrets` (ids,
titles, field ids — no values) and `get_secret`. **Pairing is the consent**: the
checklist in Settings → Developer lists items and fields, the ticked boxes become
`mcp_grants` rows and an `Mcp` token, so there is no modal and no per-request
prompt — the list is fixed before a token exists. Scopes are a ceiling in both
directions: an `Mcp` token may call `secrets.list`/`items.reveal` and **not**
`items.list`/`items.copy`/`run`, while a `Cli` token is refused `items.reveal`
with `forbidden` (not `unauthorized` — its pairing is fine, its permission is
not). Every granted read appends to `mcp_audit` before the value leaves, and the
card shows who read which field and when. A value is printed only to the MCP
client's own stdout.
Verified live: a real MCP session against the built app — `initialize`,
`tools/list`, `list_secrets`, a granted `get_secret` returning the vault value,
an ungranted read refused with `not_granted`, an unknown tool answered with
`-32602` — plus the audit row rendered in Settings and a CLI token refused while
its `items.list` still worked.

**25 · CLI / SDK over named pipe — done.** Settings documents the pipe and
permissions; a CLI reference page lists commands (`kestrel item list`,
`kestrel copy`, `kestrel run --env`). Long-running commands stream progress;
auth is per-session with a short-lived token issued after an in-app approval.
**Shipped** — `\\.\pipe\kestrel-sdk`, JSON per line, ops `status`, `items.list`
(metadata only), `items.copy` (the value goes to the clipboard, never to the
response) and `run` (the server spawns the child with vault values in its
environment and returns only the exit code and capped output). Pairing mints a
32-byte token shown once in Settings → Developer; only its SHA-256 stays in
memory, a lock revokes it, and the pipe carries a user-only DACL. The threat
model is stated where it matters: a paired token can read any item while the
vault is unlocked — `run` is a command the user asked for, and a child that
prints its environment discloses it — so pairing is a deliberate grant of full
read access for one session, never a per-request approval. The `kestrel-cli`
crate speaks it.
Backend: `\\.\pipe\kestrel-sdk`, JSON-RPC, token issuance UI.

### Phase 4 — sync and accounts

> **Status: two halves exist, the rest is specification.** In the tree: the
> `kestrel-sync` service with `PROTOCOL.md`, the account key hierarchy with
> per-item keys (schema v9), and the enrolment code plus sealed envelope
> (items 26 and 27). Not in the tree: the client sync engine, the device keypair
> store, blob transfer, sharing, admin and the hosted service — the renderer has
> no network endpoint and the core still opens only a local SQLite file. Each
> item below marks which half it is.
>
> **Four decisions are fixed.**
>
> 1. **Self-host is one container.** A single Docker image runs the sync service
>    with SQLite as its database and blobs as files on a mounted volume next to
>    it. One process, one filesystem, one backup target. There is no cluster, no
>    queue and no object-store dependency.
> 2. **Object storage is a backup target, never the sync engine.** S3/MinIO is
>    supported only as a place to put an encrypted whole-vault snapshot. A
>    bucket has no cross-object transaction, so a sync engine built on one would
>    have to merge independently written objects on the client — which is
>    precisely where the failures a password manager cannot survive come from: a
>    stale item resurrected over a newer one, a password rollback, a half-written
>    share. Sync writes go through SQLite transactions; backups are opaque blobs
>    that are never merged.
> 3. **Recovery is paper, for now.** A printable recovery code, generated on the
>    device. No server-held key share, no trusted contacts. Emergency access is
>    specified below and stays unbuilt.
> 4. **There is no free sync tier.** The local app is free forever, and an
>    encrypted backup to storage the user already owns costs the project
>    nothing. Hosted sync, sharing, administration/audit and emergency access are
>    the paid product: 30-day trial without a card, then $3/month or $30/year per
>    user, $5/month for a family of five. Nothing in the paid tier adds a
>    capability to the free app that the free app's local vault needs.

**26 · Account sign-in, device enrolment and key transfer — the local half is
shipped.** Settings → Account creates an account on this device: a 32-byte
**Secret Key** printed in the recovery-kit format and shown once, and an
**Account Key** derived as `HKDF-SHA256(Secret Key, salt = account_id,
info = "kestrel/v1/account")` — deliberately not master-derived, so a password
change cannot strand a device that already holds the account key. Both rows are
sealed under the master key with the existing `object_aad` construction, so a
stolen database yields neither. The card shows the account id, the creation
date, the device count and whether a Secret Key is set; `account_secret_key`
re-opens the row to *verify* it and never re-displays the key.
Enrolment is the code plus an envelope: `sealed = sender_agreement_pub(32) ||
nonce(24) || ciphertext(64) || tag(16)`, where the key is
`HKDF-SHA256(X25519(sender_sk, receiver_pub), salt = sha256(canonical printed
code), info = "kestrel-sync/v1/enroll")` and the sender keypair is ephemeral.
Low-order shared secrets are refused. The envelope is what the sync service
relays; it cannot open it.
**Devices and the receiving half are shipped too.** Every device holds two
independent keypairs — Ed25519 for request signing, X25519 for key agreement —
with the private halves sealed under the master key and the public halves in the
`devices` row (schema v10 adds the two wrapped columns; `account.secret_key` is
nullable, because a device that joined an account holds the account key but never
the paper Secret Key). The envelope's plaintext is
`account_id(32 ASCII hex) || account_key(32)`, so the joining device learns which
account it belongs to without the service telling it. A device with no account
can join: it shows its agreement public key, the other device mints the code and
the envelope, and the joining device opens it offline. A wrong code, a tampered
envelope and a wrong sender key all produce the same message on purpose.
Still unbuilt in 26: the six-digit verification code compared out of band (which
defeats a malicious relay), revocation, and every network call — the client crate
exists but the engine that uses it does not.

**27 · Vault sync with conflict resolution — shipped for items.** `kestrel-sync` is one binary: `hyper` +
SQLite for metadata, ciphertext in content-addressed files beside the database,
config from five environment variables, `PROTOCOL.md` at the repository root,
and `deploy/` with a Dockerfile and a compose file. Its schema holds account and
device ids, public keys, item ids, vector clocks, sizes, timestamps and
tombstones — no title, URL, username, category or field name, and `state`
returns only counts. Requests are signed per device with Ed25519 over
`method\npath\nbody-hash\ntimestamp\nnonce`, with a 300-second skew window and
a bounded replay set; `push` applies an op only when its clock dominates the
stored one and returns the stored op as a conflict otherwise, so the client can
merge and push a dominating clock. The integration tests drive a real socket.
The client half is `kestrel-engine`: it pulls, merges field by field and pushes,
the titlebar carries the state, Settings → Sync holds the server and the
counters, and a conflict review screen resolves one item at a time. A run is
automatic **once the user turns it on**: a background thread syncs on the chosen
interval (5 minutes, 15 minutes or an hour) and after a write, debounced, with a
backoff that only ever waits longer — a failing service is never polled more
often than a healthy one. A locked vault is skipped without recording an error.

One cost, stated plainly: a run holds the vault's store and session locks for the
length of the exchange, because `sync_once` needs the master key and the store for
the whole merge. A healthy server makes that milliseconds; a hung one makes it as
long as the client's connect and read timeouts, and during that window item reads
and the auto-lock check wait. A per-run deadline or a key snapshot would remove
the wait; neither is built.

`PROTOCOL.md` freezes v1 at its eight endpoints. The device-revocation route
stops new signatures but does not rotate the account key, so a revoked device
keeps the copy it already has; account-key rotation is separate work. Not built,
and planned as v2: blob transfer from the app — attachments stay on the device
that made them, and the UI says so on each one — plus the hosted infrastructure.
The sweep that will eventually collect unreferenced blobs must require **both**
that no item references a blob and that it is older than a grace window, or it
would delete every upload in flight. `deploy/` was built and run once with
Podman 6.1.4 on WSL2 (12.3 MB image, `401` on `/v1/sync/state`, uid 10001, a
read-only root filesystem, the database and blobs on the volume); the compose
path itself has not been executed.

### What is still designed, not built

Device keys are a pair per device — Ed25519 for request signing, X25519 for key
agreement — with the private halves stored sealed under the master key and the
public halves registered with the service. Enrolment ends with a six-digit
verification code compared *out of band* between the two devices: without it a
malicious service could hand device B its own envelope and read everything B
later receives. The key hierarchy that ships today is the one above (account key
from the Secret Key, item keys wrapped by the vault key); the design below
describes the sync-facing shape, where item keys are additionally wrapped for
the account so a ciphertext can travel without the vault key.

```
master key   = Argon2id(master password, 16-byte salt, 64 MiB, t=3, p=1)
vault key    = HKDF-SHA256(ikm = master key, salt = vault id,
                           info = "kestrel/v1/items")
account key  = HKDF-SHA256(ikm = Secret Key, salt = account id,
                           info = "kestrel/v1/account")
item key     = 32 random bytes, wrapped by the vault key today and by the
               account key for anything that leaves the device
```

Edge cases still open: a revoked device that already holds ciphertext, a second
device without the Secret Key, an enrolment envelope that expires unused, and a
service that answers with the wrong account. Each is named here so the interface
does not promise a flow the code cannot serve.

### The sync client is built; blobs and hosting are not

What exists: `kestrel-engine` pulls, merges field by field and pushes; the
titlebar carries a status pill (synced / syncing / offline / conflict / error)
that answers while the vault is locked; Settings → Sync holds the server URL and
the counters; and a conflict review screen shows mine vs theirs with explicit
choices ("keep mine", "keep theirs", "keep both" creates a duplicate). Sync never
merges silently. A run happens on the timer, after a write, or when someone
presses "Sync now"; a failing service backs off instead of hammering it, and a
locked vault is left alone. Attachments are not transferred yet — an item syncs
its fields, not its blobs.

The rule is **per-field last-writer-wins, resolved by a vector clock, never by
the wall clock**:

- Each item carries a version vector `{device id → counter}` plus a per-field
  logical counter. A write bumps its own device's counter.
- If one vector dominates the other, that side wins outright and the merge is
  silent because it is not a conflict — the loser's change is genuinely older.
- If neither dominates, the merge is field by field: a field changed on one side
  only takes that change; a field changed on both sides is **marked conflicting
  and surfaced**, never averaged, never guessed from a timestamp.
- Deletion is a tombstone row with its own vector. A tombstone applies only when
  it dominates the item it deletes; a delete concurrent with an edit is a
  conflict that offers "restore" and "delete", because losing a password to a
  merge rule is not a recoverable kind of bug.
- The AAD already binds a stored object to `id` and `version` (`object_aad` in
  `crypto.rs`), so a merge that writes an old body under a new version number is
  rejected by the AEAD rather than trusted.

Edge cases: clock skew (irrelevant — counters, not timestamps; server time is
recorded for diagnostics only), deleted-vs-edited (above), schema upgrade
(client refuses to write a newer item schema and says so instead of dropping
unknown fields), a device that has been offline for months (its vector is behind,
so its stale fields lose silently and only genuine concurrent edits surface).

**28 · Sharing and per-item links — designed, not built.** A share sheet on an
item: people and roles, expiry, "can view / can copy", and a link whose secret
travels in the URL fragment (never sent to the server). Sharing re-wraps the
**item key** to each recipient's X25519 public key — the server routes envelopes
it cannot open and never holds the item key. Revoking or changing a recipient
re-keys the item and re-wraps for the remaining recipients; a revoked recipient
keeps whatever plaintext they legitimately saw and the UI says so. Shared items
carry a "Shared" badge in list and detail, and the permissions are shown before a
copy. Edge cases: recipient without an account (link + passphrase, the passphrase
is the only thing the fragment secret does not cover), expired link, offline
(reads what is cached, queues nothing secret).

**29 · Family/team administration and audit log — designed, not built.** Admin
view: members, roles, a vault access matrix, pending invitations, and an
append-only audit log (who opened, shared or changed what, when). Log entries are
signed by the acting device and hash-chained, so the server can prove the chain
was not rewritten without learning what the entries describe — the description
stays in the sealed body, visible only to administrators holding the vault key.
Destructive actions need a second confirmation and are logged. Edge cases:
last-owner protection (the last owner cannot be removed or demoted), a removed
member with cached ciphertext (access ends, cached plaintext cannot be recalled;
the UI says this before the removal), an audit gap (a broken chain is surfaced as
an alarm, not as a repair).

**30 · Recovery kit — the local half is shipped; emergency access stays
unbuilt.** Settings → Recovery prints a one-page kit: a 32-byte code in 13 groups
of four characters with a trailing checksum, the vault name and the date, and the
instructions that say plainly that the code opens this vault on its own and must
be stored offline. The row stores only the master key sealed under a key derived
from the code (HKDF-SHA256, its own info string, AAD-bound to the vault), so the
database never contains the code; the code itself is shown once, at creation.
The unlock gate gains "I have a recovery code": the code unwraps the master key,
and the session then opens only far enough to **force a new master password**.
That rotation re-keys every item, version, attachment and passkey, re-seals the
row under the new key, and shows the new code once. The old code
is dead from that moment, and a manual password change clears the row — a printed
code that silently stopped working would be worse than none.
Design-only and explicitly unbuilt: designated contacts with waiting periods, a
"request access" flow, and server-side timers with encrypted key hand-off. Their
edge cases (contact unavailable, cancellation mid-wait, a kit already used) are
named here so the interface does not promise a flow the server cannot yet serve.
Verified live on a built binary: create a kit → lock → unlock with the code →
forced password change → the vault opens with the new password and the old code
is refused. The print sheet itself is CSS only and was not photographed.

---

## 7. Backend requests

Closed in the debt pass unless the row says otherwise.

| # | Request | Status |
|---|---|---|
| R1 | `open_url(url)` in the core | **done** — `commands::open_url` validates an http/https allowlist (`Empty`/`Malformed`/`Scheme` errors) and hands the URL to `ShellExecuteW`; the renderer never navigates. Website rows have an Open action. |
| R2 | `TotpDto.period` | **done** — the core parses `period` from `otpauth://` (default 30) and the ring is a true cycle again. |
| R3 | `create_item` draft/commit | **done** — `create_item` returns a draft the core has not stored; saving upserts it, so an abandoned editor and a cancelled wizard need no compensating delete. `delete_item` left the command surface with it. |
| R4 | `set_clipboard_clear(seconds)` | **done** — clamped to `0..=300`, returns the accepted state; Settings has a select. |
| R5 | Paged `list_items` + counts + `search` | **done** — `Store::list_page` (LIMIT/OFFSET + COUNT), `Store::counts` (one grouped query) and a plaintext `search_text` projection that never contains passwords, sensitive fields or TOTP secrets; schema v4, backfilled on unlock. |
| R6 | Trash/version/attachment commands (§6, 13–15) | **done** — shipped with those screens. |
| R7 | `app_meta` vault path / device name | **done** — `vaultPath` and `deviceName` in About. |
| R8 | Absolute auto-lock deadline | **done** — `VaultStateDto.lock_at`; the meter counts down to the core's instant instead of the renderer's estimate. |

---

## 8. Libraries and bundle

| Choice | Justification |
|---|---|
| **React 19 + TypeScript strict** | Given by the stack; strict mode catches contract drift against the Rust command types. |
| **lucide-react** | One consistent real line-icon set at 1.5 px; tree-shaken, no custom fake glyphs. |
| **Radix Dialog / DropdownMenu / Tooltip / Switch** | Focus trapping, escape/outside handling, aria wiring and portal layering are security-adjacent correctness, not polish. Radix exposes `data-state` for token-driven motion. |
| **@fontsource Inter (files vendored)** | Three latin woff2 files (23.66/24.27/24.45 kB) copied into `src/assets/inter`; `@font-face` is local, preloaded and CSP-safe. No runtime font network request, no synthetic weights. |
| **Hand-authored CSS with variables** | Zero runtime style computation (required for long lists), one token file, six accent blocks. Tailwind was rejected: it would duplicate the token layer without buying anything for a UI this small. |
| **No animation library** | CSS transitions cover the motion spec. |
| **No cmdk** | The palette's combobox semantics are small enough to own and audit. |

Production bundle (final `npx vite build`): **451.69 kB JS / 137.45 kB gzip**,
47.99 kB CSS / 9.16 kB gzip, plus three local woff2 files (72.38 kB total). The
JS budget (≤ 500 kB gzip) is met. Fonts are preloaded assets, not JS.

## 9. Honesty notes

- The first-run **create** screen is reachable (fresh database), but the submit
  step could not be driven by the synthetic keystroke harness in this session,
  so neither the submit nor the empty-vault state has a current capture. The
  vault is left at its documented 6-item demo state.
- Accent evidence (`artifacts/accent-*-light/dark.png`) is captured on the
  Settings · Appearance screen, where the swatch row and the accent state are
  both visible, rather than on the vault; `accent-violet-vault.png` additionally
  shows the accent applied to item content. The same tokens drive both screens.
- Focus evidence is captured for a wrapped input, a wrapped select, an accent
  chip and the palette. Menu items, dialog controls and window chrome use the
  same inset/outer rules but were not photographed individually.
- No FOUT was measured instrumentally: the guarantee is structural (three local
  woff2 files, `font-display: block`, preloaded in `index.html`), not a trace.
- All **18 categories** share one generic renderer driven by the core's default
  field sets; the real app was exercised with login, note, credit card, SSH key
  (list) and API credential (list). Date fields are shown as stored text.
- Virtualisation above 80 rows is implemented but not exercised (demo vault).
- The core-unreachable state is implemented but was not captured in a browser
  build during this session.
- Copy-with-wipe feedback and clipboard clearing were not exercised; the code
  path is the real `copy_field`/`copy_text` and the toast states the core's 30 s
  interval.
- Phase 2 (13–18) is implemented and covered by core tests; the HIBP check was
  exercised against the live range API once, and it degrades to an explicit
  offline banner when the network is unavailable.
- Multi-vault (12) is implemented — `commands_vaults.rs`, `core/tests/vaults.rs`
  and `src/vault/VaultSwitcher.tsx`; items never move between vaults.

---

## 11. Extension API

> **Status: designed, not built.** There is no extension host, no manifest
> loader and no `Plugin` token in the tree today. This section is the contract
> phase 4 will implement; nothing in the shipped product changes because of it.

### 11.1 The renderer is not an extension platform

Kestrel will **never** load third-party JavaScript into the renderer. A renderer
plugin would run inside the webview that holds the unlocked session, and that
webview can call `invoke` — so a single injected line could read every field of
every item while the vault is open, and the user's only defence would be
reviewing minified code. Everything the interface relies on for security
(the session lock, the audit trail, the AAD binding) lives on the other side of
that boundary and would be bypassed by construction.

Extensions are therefore **out-of-process clients of the pipe protocol that
already exists** (`\\.\pipe\kestrel-sdk`, one JSON object per line, per-session
token, user-only DACL — §6 item 25). The core stays the only holder of keys; an
extension is a program that asks the core for things and can be told no.

### 11.2 The `Plugin` scope

`Scope` in `sdk/protocol.rs` today has three variants: `Cli`, `Mcp { client,
grants }` and `Browser`. Phase 4 adds a fourth:

```
Plugin { id: String, grants: Vec<Grant>, allow: Vec<ExtensionPoint> }
```

A scope is decided when the token is minted and never widens afterwards — the
existing rule, already enforced by the protocol tests: re-pairing replaces a
token, it does not extend it. An extension's token is minted when the person
installs it and re-minted only when they approve a widened manifest (11.5).

### 11.3 Manifest and grants

An extension is a directory with a `manifest.json`:

```json
{
  "id": "org.example.csv-importer",
  "name": "CSV importer",
  "version": "1.2.0",
  "publisher": { "name": "Example Org", "key": "<ed25519 public key>" },
  "signature": "<detached signature over manifest + payload hash>",
  "points": ["importer"],
  "grants": []
}
```

- **Signed.** The payload hash and the manifest are signed by the publisher key;
  the host refuses an unsigned extension and refuses a payload that does not
  match the signed hash. An update is a new signed manifest, not a patch to a
  running one.
- **Per-field grants.** A grant is `(item uuid, field id)` — the same shape the
  MCP path already uses. Grants are ticked by the person in Settings, one field
  at a time; there is no "all items" grant, no "all logins" grant and no
  wildcard. A grant naming a field that does not exist is rejected, so an
  allowlist can never outlive the field it named.
- **Capability ceiling.** `points` is a closed set (11.4). An extension that
  declares no grants can still import, export, generate and register palette
  actions; it simply cannot read the vault.

### 11.4 Extension points, v1

| Point | What the extension does | Vault access |
|---|---|---|
| **importer** | receives the file the person chose, returns a proposed item set; the core validates and seals it, and the person sees the import report before anything is written | none — file in, proposal out |
| **exporter** | receives a decrypted export package the person explicitly requested, returns bytes | none beyond that one package |
| **generator** | is asked for a value of a requested shape and returns a string; the core validates length and character class before use | none |
| **palette action** | registers commands with a title and an argument shape; appears in the command palette | none; acting on an item still goes through a granted read |
| **event subscription** | receives `vault.locked`, `vault.unlocked`, `item.saved`, `item.expiring` | none — payloads carry item ids and timestamps only, never field values |

**There is no storage extension point.** An extension never gets a key, never
gets a row of its own inside the vault, and can never write ciphertext. A secret
lives in an item; the only way an extension touches one is a grant to read one
field. This is deliberate: an extension with its own encrypted store becomes a
second, unaudited vault inside the product, with its own rotation and its own
recovery story, and neither exists.

Events are delivered on the same pipe after the extension subscribes, and the
core drops a subscription when the token is revoked or the vault locks — a
`vault.locked` event is the last one a session receives.

### 11.5 Every read is one audit row

The read path is the one that already exists for MCP clients, unchanged:
grant check → decrypt → **append the audit row** → return the value, all under
one session lock (`Session::mcp_reveal` in `core/src/session.rs`). A read that
fails the grant check touches nothing; a read that passes is recorded *before*
its value exists outside the core, so there is no window in which a value was
handed out without a row. The extension id takes the place of the client name,
and the row records extension, item, field and time. Settings → Extensions shows
the same history the MCP grants card shows, newest first, which is what makes
"what did this thing read" a question with an answer.

### 11.6 Supply chain

The risk is not a malicious extension at install — the person chose it and can
read its declared grants. The risk is the extension that was fine at version 1.2
and reads one more field at version 1.3; the update arrives months later, signed
by the same key, and a person clicking "Update" is not reading a diff.

Mitigations, all three required:

1. **Grants are the ceiling, not a suggestion.** A token cannot ask for a field
   it was not granted; the refusal is `not_granted`, the same coded refusal the
   MCP path returns.
2. **Every read is audited**, so a widened extension is visible as rows it did
   not produce before — and revoking is one click, immediate, because the token
   is memory-only.
3. **An update that widens permissions re-consents.** The host diffs the new
   manifest against the installed one; any added grant, added extension point or
   publisher-key change stops the update, disables the extension, and asks the
   person to approve the specific new capability — named, one line per addition.
   A silent widening is not possible because the manifest is the only thing that
   confers capability, and it must be re-signed to change.

Two things this does not fix, stated rather than hidden: a granted read is a real
plaintext read, so a malicious extension with grants can exfiltrate what it was
given — grants must be narrow and revocable, not reviewed once; and publisher
key compromise is indistinguishable from a legitimate update, which is why the
re-consent diff exists and why a key change is treated as a new publisher.
