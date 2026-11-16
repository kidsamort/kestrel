/**
 * Recovery kit bridge — mirrors `src-tauri/src/commands_recovery.rs`.
 *
 * The code crosses this bridge exactly twice in its life: once out, when the
 * kit is minted, and once in, when the vault is opened with it. Nothing here
 * caches it: callers hold it in component state only while it is on screen, and
 * it is never written to storage, a toast or an error string.
 */
import { invoke } from "@tauri-apps/api/core";
import type { VaultState } from "../types";

export interface RecoveryStatus {
  /** Whether this vault has a kit at all. */
  enrolled: boolean;
  /** Unix milliseconds of the current row, `null` when there is none. */
  createdAt: number | null;
}

export interface RecoveryKit {
  /** Printed on the sheet, so a stack of paper names the vault it opens. */
  vaultName: string;
  /** 13 groups of four base32 characters, then the checksum character. */
  code: string;
  createdAt: number;
}

export interface RecoveryOpen {
  /** Which vault the code opened; the forced-change screen names it. */
  vaultName: string;
}

export interface RecoveryCompletion {
  /** Which vault the rotation re-keyed. */
  vaultName: string;
  /**
   * The new code, handed over exactly once. `null` only when the rotation
   * committed but the new row could not be stored: the password is live and the
   * user has to mint a kit from settings.
   */
  kit: RecoveryKit | null;
}

export const recovery = {
  /** Kit presence, answerable while locked. */
  status: () => invoke<RecoveryStatus>("recovery_status"),
  /** Mint a new code from the unlocked session; replaces any previous row. */
  create: () => invoke<RecoveryKit>("recovery_create"),
  /** Unwrap the key; it opens the forced-change screen, not the vault. */
  unlock: (code: string) => invoke<RecoveryOpen>("recovery_unlock", { code }),
  /** Re-key the whole account under a new password and mint a new code. */
  complete: (newPassword: string) =>
    invoke<RecoveryCompletion>("recovery_complete", { newPassword }),
  /** Acknowledge the new code; only this opens the session. */
  /** Ask where to save the kit, write the PDF there, return the path. */
  savePdf: (args: { vaultName: string; code: string; createdAt: number }) =>
    invoke<string | null>("recovery_save_pdf", args),
  /** Pick a saved kit and read the code off it. `null` when cancelled. */
  readKit: () => invoke<string | null>("recovery_read_kit"),
  finish: () => invoke<VaultState>("recovery_finish"),
};
