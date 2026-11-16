/**
 * Vault bridge — mirrors `src-tauri/src/commands_vaults.rs`.
 *
 * A vault is its own key derived from the master password, so switching never
 * asks for the password again: the core re-points the session at another uuid
 * and every later read decrypts that vault's rows.
 */
import { invoke } from "@tauri-apps/api/core";
import type { VaultState } from "../types";

export interface VaultSummary {
  uuid: string;
  name: string;
  itemCount: number;
}

export const vaults = {
  /** Every vault in the account with its live item count. */
  list: () => invoke<VaultSummary[]>("vaults_list"),
  create: (name: string) => invoke<VaultSummary>("vault_create", { name }),
  /** Re-scope the session; returns the new state snapshot. */
  switch: (uuid: string) => invoke<VaultState>("vault_switch", { uuid }),
  rename: (uuid: string, name: string) =>
    invoke<void>("vault_rename", { uuid, name }),
};
