import { invoke } from "@tauri-apps/api/core";
import type {
  AppMeta,
  Counts,
  GenerateOptions,
  HelloStatus,
  Item,
  ItemSummary,
  Page,
  Totp,
  VaultState,
} from "./types";

/**
 * The core's command surface, in one place. Everything the UI can do is here;
 * anything not listed does not exist as far as the interface is concerned.
 */
export const api = {
  state: () => invoke<VaultState>("vault_state"),
  unlock: (password: string) => invoke<VaultState>("unlock_vault", { password }),
  /** Enrolment state only; the wrapped key material never crosses the bridge. */
  helloStatus: () => invoke<HelloStatus>("hello_status"),
  /** Wraps the live master key behind a Windows Hello prompt. */
  helloEnroll: () => invoke<HelloStatus>("hello_enroll"),
  helloDisable: () => invoke<HelloStatus>("hello_disable"),
  /** Unlocks with the wrapped key; raises the Windows Hello prompt. */
  helloUnlock: () => invoke<VaultState>("hello_unlock"),
  lock: () => invoke<VaultState>("lock_vault"),
  touch: () => invoke<void>("touch_vault"),
  setAutolock: (seconds: number) =>
    invoke<VaultState>("set_autolock", { seconds }),
  setClipboardClear: (seconds: number) =>
    invoke<VaultState>("set_clipboard_clear", { seconds }),
  /** Ask the core to hand an allowlisted http(s) URL to the system browser. */
  openUrl: (url: string) => invoke<void>("open_url", { url }),

  list: (query: string, category: string | null, favoritesOnly: boolean) =>
    invoke<ItemSummary[]>("list_items", { query, category, favoritesOnly }),
  listPage: (
    query: string,
    category: string | null,
    favoritesOnly: boolean,
    limit: number,
    offset: number,
  ) =>
    invoke<Page>("list_items_page", {
      query,
      category,
      favoritesOnly,
      limit,
      offset,
    }),
  /** Sidebar badges: one grouped query instead of a pass over the item list. */
  counts: () => invoke<Counts>("item_counts"),
  get: (id: string) => invoke<Item>("get_item", { id }),
  createItem: (category: string) => invoke<Item>("create_item", { category }),
  save: (item: Item) => invoke<Item>("save_item", { item }),
  totp: (id: string) => invoke<Totp>("item_totp", { id }),
  copyField: (itemId: string, fieldId: string) =>
    invoke<void>("copy_field", { itemId, fieldId }),
  copyText: (text: string) => invoke<void>("copy_text", { text }),

  generate: (options: GenerateOptions) =>
    invoke<string>("generate_password", { options }),
  changePassword: (oldPassword: string, newPassword: string) =>
    invoke<VaultState>("change_password", { oldPassword, newPassword }),
  meta: () => invoke<AppMeta>("app_meta"),
};

/** True only inside the Tauri window; the browser build has no core. */
export function hasCore(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Map core errors to sentences a person can act on. */
export function errorText(e: unknown): string {
  const raw =
    typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
  if (/authentication failed/i.test(raw))
    return "That master password cannot decrypt this vault.";
  if (/vault is locked/i.test(raw))
    return "The vault is locked. Unlock it to continue.";
  if (/at least 10 characters/i.test(raw))
    return "A master password needs at least 10 characters.";
  if (/vault is not initialised/i.test(raw))
    return "No vault exists on this device yet. Create one to begin.";
  if (/crypto error: key derivation/i.test(raw))
    return "Key derivation failed. Try again.";
  if (/clipboard/i.test(raw))
    return "The clipboard is busy. Close other apps and try again.";
  if (/item not found/i.test(raw))
    return "That item is no longer in the vault.";
  return raw || "Something went wrong.";
}
