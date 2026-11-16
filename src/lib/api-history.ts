import { invoke } from "@tauri-apps/api/core";
import type { Item } from "../types";

/** One archived version of an item, as listed by the core. */
export interface VersionSummary {
  version: number;
  archivedAt: number;
  title: string;
  fieldCount: number;
}

export function historyList(itemId: string): Promise<VersionSummary[]> {
  return invoke<VersionSummary[]>("history_list", { itemId });
}

export function historyGet(itemId: string, version: number): Promise<Item> {
  return invoke<Item>("history_get", { itemId, version });
}

export function historyRestore(itemId: string, version: number): Promise<Item> {
  return invoke<Item>("history_restore", { itemId, version });
}
