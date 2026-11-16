/**
 * Passkey bridge — mirrors `src-tauri/src/passkeys/mod.rs`.
 *
 * Only metadata crosses this boundary: the public credential id, RP id and
 * timestamps. The private key is opened inside the core for one assertion and
 * is never part of a command response. `register` and `unregister` are the only
 * commands that touch the registry, and they never run at install time.
 */
import { invoke } from "@tauri-apps/api/core";

/** Snapshot returned by `passkeys_status`. */
export interface PasskeyStatus {
  /** The HKCU CLSID key exists and names an `InprocServer32` DLL. */
  registered: boolean;
  /** The path read back from the registry, if any. */
  registeredPath: string | null;
  clsid: string;
  /** Where this build expects `kestrel_passkey.dll`. */
  dllPath: string;
  dllPresent: boolean;
  /** `\\.\pipe\kestrel-passkeys`, the plugin's route to the vault. */
  pipe: string;
  /** The pipe server is running in this process. */
  pipeRunning: boolean;
  /** Windows' view: 0 disabled, 1 enabled; null when not queryable. */
  windowsState: number | null;
  /** The HRESULT from the add/remove call this command made. */
  windowsHresult: number | null;
  /** Why the Windows plugin API is unavailable, when it is. */
  windowsError: string | null;
  /** A registration or pipe error that makes the state incomplete. */
  error: string | null;
}

/** One credential attached to an item. The private key is not present. */
export interface PasskeyInfo {
  /** Public identifier, lower-case hex. */
  credentialId: string;
  itemId: string;
  rpId: string;
  /** Unix seconds. */
  createdAt: number;
  /** Unix seconds, or null before the first assertion. */
  lastUsedAt: number | null;
}

export const passkeys = {
  status: () => invoke<PasskeyStatus>("passkeys_status"),
  /** Write HKCU, start the pipe, and register with Windows. Explicit only. */
  register: () => invoke<PasskeyStatus>("passkeys_register_plugin"),
  /** Stop the pipe, remove the CLSID tree, and unregister from Windows. */
  unregister: () => invoke<PasskeyStatus>("passkeys_unregister_plugin"),
  /** Metadata for one item's credentials. */
  forItem: (itemId: string) =>
    invoke<PasskeyInfo[]>("passkeys_for_item", { itemId }),
  /** Remove one credential; it cannot be recovered. */
  remove: (itemId: string, credentialId: string) =>
    invoke<void>("passkeys_remove", { itemId, credentialId }),
  /**
   * Answer a pending assertion. `false` also covers "the request is gone":
   * a late click must not approve whatever is waiting now.
   */
  answer: (id: number, allow: boolean) =>
    invoke<boolean>("passkeys_answer_approval", { id, allow }),
};

/** Shorten a public credential id for the row while keeping it copyable. */
export function shortCredentialId(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}
