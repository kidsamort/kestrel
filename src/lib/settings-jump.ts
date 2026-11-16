/**
 * "Take me to this settings section."
 *
 * Two callers need it and neither can scroll by itself: the command palette
 * lives outside the panel, and the sync pill lives outside the shell. Both can
 * only ask — the Settings page owns the scroll, and it consumes the request on
 * mount so a second mount does not replay it.
 *
 * The request is a plain module value rather than an event: the panel may not be
 * mounted yet when the ask arrives, and an event fired into nothing is lost.
 */

export type SettingsSection =
  | "security"
  | "rotation"
  | "recovery"
  | "agent"
  | "sdk"
  | "mcp"
  | "passkeys"
  | "account"
  | "sync"
  | "quick-access"
  | "autofill"
  | "browser"
  | "data"
  | "appearance"
  | "about";

/** Anchor id for one section: `#settings-<section>`. */
export function settingsAnchor(section: SettingsSection): string {
  return `settings-${section}`;
}

/** Fired on `window` when a jump is asked for while Settings is already open. */
export const SETTINGS_JUMP_EVENT = "kestrel:settings-jump";

let pending: SettingsSection | null = null;

/**
 * Ask the Settings page to scroll to `section`.
 *
 * Two delivery paths, because the panel may or may not be mounted: the value
 * survives for a page that is about to mount, and the event reaches a page that
 * is already on screen. A page consumes the value when it handles either, so a
 * jump never replays on a later mount.
 */
export function requestSettingsSection(section: SettingsSection): void {
  pending = section;
  window.dispatchEvent(new Event(SETTINGS_JUMP_EVENT));
}

/** Take the pending request, if any. Reading it clears it. */
export function consumeSettingsSection(): SettingsSection | null {
  const value = pending;
  pending = null;
  return value;
}
