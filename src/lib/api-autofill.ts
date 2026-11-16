import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ItemSummary } from "../types";

/**
 * Typed surface for the Windows application autofill picker
 * (`src-tauri/src/autofill`).
 *
 * Filling goes through the core: `fill(itemId, field)` names an item and a
 * field kind, and the Rust side decrypts the value and writes it into the
 * focused field with UI Automation. No value is ever an argument or a return
 * value here, so it cannot end up in this renderer's state.
 */

export type AutofillMode = "fill" | "ask" | "off";

/** Result of `autofill_status`: the master switch and shortcut state. */
export interface AutofillStatus {
  enabled: boolean;
  shortcut: string;
  registered: boolean;
  /** Why the shortcut or the observer is unavailable, when known. */
  error: string | null;
}

/** One explicit `autofill_apps` row. A missing row means `ask`. */
export interface AutofillRule {
  exe: string;
  mode: AutofillMode;
  updatedAt: number;
}

/** A field rectangle in physical screen pixels. */
export interface AutofillRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** What the picker knows about the focused field. Never a secret. */
export interface AutofillTarget {
  exe: string;
  pid: number;
  isPassword: boolean;
  controlType: string;
  automationId: string;
  className: string;
  rect: AutofillRect;
  /** The rule in force for `exe`. */
  mode: AutofillMode;
  /** Non-null when the target may not be filled; shown instead of rows. */
  refused: string | null;
}

/** Rows for the overlay: recent fills plus search hits, summaries only. */
export interface AutofillSuggest {
  recent: ItemSummary[];
  matches: ItemSummary[];
}

/** Event the shell emits with the current {@link AutofillTarget}. */
export const AUTOFILL_TARGET_EVENT = "autofill://target";

export const autofill = {
  status: () => invoke<AutofillStatus>("autofill_status"),
  /** Turn the observer and the shortcut offers on or off. */
  setEnabled: (enabled: boolean) =>
    invoke<AutofillStatus>("autofill_set_enabled", { enabled }),
  /** Rebind the offer chord. The backend releases the old one first. */
  setShortcut: (chord: string) =>
    invoke<AutofillStatus>("autofill_set_shortcut", { chord }),
  /** Explicit rules only; applications without a row are `ask`. */
  rules: () => invoke<AutofillRule[]>("autofill_rules"),
  setRule: (exe: string, mode: AutofillMode) =>
    invoke<AutofillRule[]>("autofill_set_rule", { exe, mode }),
  /** Delete the row; the application falls back to `ask`. */
  resetRule: (exe: string) =>
    invoke<AutofillRule[]>("autofill_reset_rule", { exe }),
  /** The target the overlay was last shown for (it may mount late). */
  target: () => invoke<AutofillTarget | null>("autofill_target"),
  suggest: (query: string) =>
    invoke<AutofillSuggest>("autofill_suggest", { query }),
  /**
   * Fill one field of one item into the focused field. `field` is the field
   * *kind*; the value is resolved and written by the Rust side.
   */
  fill: (itemId: string, field: "username" | "password") =>
    invoke<void>("autofill_fill", { itemId, field }),
  /** Hide the overlay. Escape, focus loss and blur also do this. */
  dismiss: () => invoke<void>("autofill_dismiss"),
  /**
   * Activate the overlay so its search field accepts typing. The window is
   * `WS_EX_NOACTIVATE`, so merely appearing never steals focus.
   */
  takeInput: () => invoke<void>("autofill_take_input"),
};

/** Listen for "the target changed" (a new field, or the same one again). */
export function onAutofillTarget(
  handler: (target: AutofillTarget) => void,
): Promise<UnlistenFn> {
  return listen<AutofillTarget>(AUTOFILL_TARGET_EVENT, (event) =>
    handler(event.payload),
  );
}

/** Listen for "the vault was locked elsewhere" (watchdog or main window). */
export function onVaultLocked(handler: () => void): Promise<UnlistenFn> {
  return listen("vault://locked", () => handler());
}
