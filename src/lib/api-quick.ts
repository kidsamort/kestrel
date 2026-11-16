import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/**
 * Typed surface for the quick-access palette window (`src-tauri/src/quick.rs`).
 *
 * These commands only exist in the desktop shell: the palette window is created
 * by the Rust side, so nothing here is reachable from the browser build.
 */

/** Result of `quick_status`: whether the OS gave us the chord. */
export interface QuickStatus {
  /** The user's preference: keep the chord bound. */
  enabled: boolean;
  registered: boolean;
  shortcut: string;
  /** Registration failure reason, e.g. another app owns the chord. */
  error: string | null;
}

/** Payload of `quick://open-item`. */
export interface QuickOpenItem {
  id: string | null;
}

/** Name of the event the palette emits to the main window. */
export const QUICK_OPEN_ITEM_EVENT = "quick://open-item";
/** Name of the event the shell emits to the palette each time it appears. */
export const QUICK_SHOWN_EVENT = "quick://shown";

export const quick = {
  /** Build (first time) or raise the palette window. */
  open: () => invoke<void>("quick_open"),
  /** Hide the palette; the webview stays alive for the next open. */
  hide: () => invoke<void>("quick_hide"),
  /** Hotkey registration state, for Settings and for the palette footer. */
  status: () => invoke<QuickStatus>("quick_status"),
  /**
   * Bind or release the chord. The preference lasts for the session: a restart
   * starts with the hotkey on, like the auto-lock timer.
   */
  setEnabled: (enabled: boolean) =>
    invoke<QuickStatus>("quick_set_enabled", { enabled }),
  /** Rebind the palette chord. The backend releases the old one first. */
  setShortcut: (chord: string) =>
    invoke<QuickStatus>("quick_set_shortcut", { chord }),
  /**
   * Raise the main window, ask it to select `itemId` (or nothing), and hide the
   * palette. Called when a row is opened or Enter is pressed.
   */
  focusMain: (itemId?: string | null) =>
    invoke<void>("quick_focus_main", { itemId: itemId ?? null }),
  /**
   * Copy a login's username or password. The core resolves the field, so the
   * password is never serialized into this renderer.
   */
  copyLogin: (itemId: string, field: "username" | "password") =>
    invoke<void>("quick_copy_login", { itemId, field }),
};

/** Listen for "the vault was locked elsewhere" (watchdog or main window). */
export function onVaultLocked(handler: () => void): Promise<UnlistenFn> {
  return listen("vault://locked", () => handler());
}

/** Listen for "select this item in the main window". Returns an unlisten fn. */
export function onQuickOpenItem(
  handler: (itemId: string | null) => void,
): Promise<UnlistenFn> {
  return listen<QuickOpenItem>(QUICK_OPEN_ITEM_EVENT, (event) =>
    handler(event.payload?.id ?? null),
  );
}

/** Listen for "the palette was just shown" (hotkey or `quick_open`). */
export function onQuickShown(handler: () => void): Promise<UnlistenFn> {
  return listen(QUICK_SHOWN_EVENT, () => handler());
}
