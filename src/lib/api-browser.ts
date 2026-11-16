/**
 * Browser bridge — mirrors `src-tauri/src/browser/mod.rs` (`browser_*`
 * commands).
 *
 * This surface installs and removes the per-user native messaging host and
 * edits the per-origin rule table. It never returns a token and never returns a
 * field value: the extension asks the app over the pipe, and the one op that
 * releases a value (`browser.reveal`) is answered there, not here.
 */
import { invoke } from "@tauri-apps/api/core";

/** What the bridge may do on one origin. `ask` is the default for no row. */
export type BrowserMode = "fill" | "ask" | "off";

/** One explicit `browser_sites` row. */
export interface BrowserRule {
  origin: string;
  mode: BrowserMode;
  /** Unix seconds. */
  updatedAt: number;
}

/** Non-secret snapshot for the card. */
export interface BrowserStatus {
  /** A browser registration points at an existing manifest and binary. */
  installed: boolean;
  /** Native messaging host name (`com.kestrel.bridge`). */
  hostName: string;
  /** Absolute path of the host manifest. */
  manifestPath: string;
  /** `kestrel-nmhost.exe` next to the Kestrel executable. */
  hostBinary: string;
  hostBinaryPresent: boolean;
  /** Fixed by the extension's `key`, so the manifest can name it up front. */
  extensionId: string;
  allowedOrigin: string;
  /** `bridge.token` next to the vault. */
  tokenPath: string;
  tokenPresent: boolean;
  /** Explicit rules only; a missing row is `ask`. */
  rules: number;
  chromeRegistered: boolean;
  edgeRegistered: boolean;
  firefoxRegistered: boolean;
}

export const browser = {
  status: () => invoke<BrowserStatus>("browser_status"),
  /** Register the host for Chrome and Edge and mint the token file. */
  install: () => invoke<BrowserStatus>("browser_install"),
  /** Remove both registrations, the manifest and the token file. */
  uninstall: () => invoke<BrowserStatus>("browser_uninstall"),
  rules: () => invoke<BrowserRule[]>("browser_rules"),
  setRule: (origin: string, mode: BrowserMode) =>
    invoke<BrowserRule[]>("browser_set_rule", { origin, mode }),
  /** Delete the row; the origin falls back to `ask`. */
  resetRule: (origin: string) =>
    invoke<BrowserRule[]>("browser_reset_rule", { origin }),
};
