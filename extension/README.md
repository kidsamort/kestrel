# Kestrel browser bridge (MV3)

Plain JavaScript, no build step. It talks to `kestrel-nmhost.exe` over Chrome's
native messaging protocol (4-byte little-endian length + UTF-8 JSON) and never
holds a token.

## Install

1. In Kestrel: **Settings → Browser → Install**. This writes
   `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.kestrel.bridge` and the
   Edge equivalent, the host manifest, and `bridge.token` next to the vault.
2. In Edge or Chrome: open `edge://extensions` / `chrome://extensions`, enable
   **Developer mode**, choose **Load unpacked**, and select this `extension/`
   directory.
3. Reload an `http(s)` login page.

The extension id is fixed by the `key` in `manifest.json`:

```
ippcgmeddpnhhbjllfkknhlilnaneclk
```

`allowed_origins` in the host manifest names exactly that id. A different build
(or a copy with the `key` removed) gets a different id and is refused by the
browser.

## What it does

- On a page with a visible password field it asks the host for
  `browser.items { origin }`.
- The chip is a suggestion, not a fill. Clicking it opens an in-page
  confirmation that names the item and the origin.
- Only the **Fill** press asks for `browser.reveal { origin, id, field }`, once
  per username/password field. Values live in the content script's closure for
  one fill and are dropped; there is no `chrome.storage`, no `localStorage` and
  no value in a log.
- A locked vault shows a chip that explains it and offers **Open Kestrel**.
- `off` hides the chip; `ask` shows it but refuses to release a value until the
  origin is changed to `fill` in Kestrel.

## The token file

`%APPDATA%\app.kestrel.vault\bridge.token` is a secret at rest: the browser
starts the host, so the host has to read the token from disk. Kestrel writes it
with a protected DACL containing one full-access ACE for the current Windows
user, and deletes it on uninstall. It grants only `browser.*`; while the vault
is locked every call answers `locked`, so the file alone reveals nothing.

The host overwrites any `token` field supplied by the extension. The extension
cannot choose its own scope.
