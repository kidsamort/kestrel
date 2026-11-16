/**
 * Vault location bridge — mirrors the core's vault-location commands.
 *
 * A vault is a file the person names and places. This module is the only
 * renderer code that knows that: it asks where the last vault is, creates a new
 * file at a chosen path, and points the core at an existing one. The password
 * and the hint cross this bridge only on create; reading them back is the
 * job of the lock screen's own commands.
 */
import { invoke } from "@tauri-apps/api/core";
import { errorText } from "../api";
import type { VaultState } from "../types";

export interface VaultLocation {
  /** The selected vault file, or `null` before one is chosen. */
  path: string | null;
  /** The optional, user-written hint; plaintext by design. */
  hint: string | null;
  initialized: boolean;
  locked: boolean;
  /** Suggested folder for a new vault. */
  defaultDir: string;
}

/** The typed failures the core returns for the location commands. */
export type VaultErrorCode =
  | "already_exists"
  | "invalid_path"
  | "weak_password"
  | "not_found"
  | "no_vault";

const CODES: VaultErrorCode[] = [
  "already_exists",
  "invalid_path",
  "weak_password",
  "not_found",
  "no_vault",
];

function rawText(error: unknown): string {
  return typeof error === "string"
    ? error
    : error instanceof Error
      ? error.message
      : String(error);
}

/**
 * The typed code behind a failure, or `null` for the core's plain messages.
 * Tauri hands `Err(String)` back as a bare string; a code may arrive alone or
 * with a detail suffix, so only the prefix is matched.
 */
export function vaultErrorCode(error: unknown): VaultErrorCode | null {
  const value = rawText(error).trim().toLowerCase();
  return (
    CODES.find(
      (code) =>
        value === code ||
        value.startsWith(`${code}:`) ||
        value.startsWith(`${code} `),
    ) ?? null
  );
}

/**
 * Map a vault failure to a sentence. The three the person can act on have
 * fixed wording; everything else keeps the core's own message through the
 * shared formatter, so a new error is never replaced by a reassuring guess.
 */
export function vaultErrorText(error: unknown): string {
  switch (vaultErrorCode(error)) {
    case "already_exists":
      return "A vault with this name is already in that folder. Pick another name or another folder.";
    case "weak_password":
      return "A master password needs at least 10 characters.";
    case "not_found":
      return "This file is not here any more.";
    case "invalid_path":
      return "That path cannot hold a vault file. Choose a folder and a file name.";
    case "no_vault":
      return "No vault is selected yet. Create one or open an existing file.";
    default:
      return errorText(error);
  }
}

/**
 * Join the two fields the create form collects. Returns `null` for a name that
 * would escape the chosen folder or is not a file name at all; the core still
 * checks the path, but the renderer must never compose a traversal from input.
 */
/** Pick an existing vault file. `null` when the person cancels. */
export async function pickVaultFile(): Promise<string | null> {
  return invoke<string | null>("vault_pick_file");
}

/** Open a folder in the file manager. Errors when it is not there. */
export async function revealFolderPath(path: string): Promise<void> {
  await invoke("folder_reveal", { path });
}

/**
 * The native folder picker. Returns `null` when the person cancels; an error
 * string when the dialog itself fails (a machine without the Shell API).
 */
export async function pickFolder(start: string | null): Promise<string | null> {
  return invoke<string | null>("vault_pick_folder", { start });
}

export function vaultFilePath(folder: string, name: string): string | null {
  const dir = folder.trim();
  const file = name.trim();
  if (!dir || !file) return null;
  if (file === "." || file === "..") return null;
  if (/[\\/:*?"<>|]/.test(file)) return null;
  const separator = dir.includes("\\") || /^[a-z]:/i.test(dir) ? "\\" : "/";
  return `${dir.replace(/[\\/]+$/, "")}${separator}${file}`;
}

/** The name shown under the lock screen; the full path stays in `title`. */
export function vaultFileName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

export const vault = {
  /** Where the last vault lives, its hint, and the folder to suggest. */
  location: () => invoke<VaultLocation>("vault_location"),
  /** Create a new vault file and open it unlocked. */
  createAt: (path: string, password: string, hint: string | null) =>
    invoke<VaultState>("vault_create_at", { path, password, hint }),
  /** Point the core at an existing vault file. */
  openAt: (path: string) => invoke<VaultState>("vault_open_at", { path }),
  /** Open the system file manager at the vault's folder. */
  revealFolder: () => invoke<void>("vault_reveal_folder"),
};
