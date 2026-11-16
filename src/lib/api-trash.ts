import { invoke } from "@tauri-apps/api/core";
import type { ItemSummary } from "../types";

/**
 * A trashed item: the normal summary plus the moment it was moved to the
 * trash. `ItemSummary` is the frozen core contract and may already carry
 * `deletedAt`; the intersection keeps this file correct either way.
 */
export type TrashSummary = ItemSummary & { deletedAt?: number };

/**
 * The trash command surface. Names match the `commands_trash` module in the
 * Tauri shell; every call is scoped to the unlocked vault on the Rust side.
 */
export const trashApi = {
  /** Trashed items, newest deletion first. */
  list: () => invoke<TrashSummary[]>("trash_list"),
  /** Move a live item to the trash. Idempotent. */
  trash: (id: string) => invoke<void>("trash_item", { id }),
  /** Bring a trashed item back into the vault. */
  restore: (id: string) => invoke<void>("restore_item", { id }),
  /** Permanently delete one trashed item. Refuses live items. */
  purge: (id: string) => invoke<void>("purge_item", { id }),
  /** Permanently delete every trashed item; returns the item rows removed. */
  empty: () => invoke<number>("empty_trash"),
};
