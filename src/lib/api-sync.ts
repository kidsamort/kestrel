/**
 * Sync bridge — mirrors the `sync_*` commands in the Tauri shell.
 *
 * The renderer never holds key material for sync. Every field that leaves this
 * device is already sealed by the core, so a status or conflict query returns
 * metadata and rendered strings only: the server address, the account and
 * device ids, counters, and the two sides of a conflict the core has already
 * decrypted locally. Nothing here can read the server, and nothing here can
 * merge two versions.
 *
 * The window-bar pill and the Settings card are in different trees. They meet
 * through two window events instead of a shared store: `SYNC_CHANGED_EVENT`
 * tells every mounted reader to re-read `sync_status`, and `SYNC_VIEW_EVENT`
 * asks the shell to show Settings → Sync (the shell owns the panel state, see
 * `VaultShell`'s wiring of `requestSyncView`).
 */
import { invoke } from "@tauri-apps/api/core";

/** Where the client stands; `idle` is a healthy, fully-synced device. */
export type SyncState = "idle" | "syncing" | "offline" | "conflict" | "error";

export interface SyncStatus {
  /** A server is set. Without one the client has nothing to talk to. */
  configured: boolean;
  /** The base URL the client was configured with, e.g. `http://127.0.0.1:8787`. */
  server: string | null;
  /** 32 lower-case hex characters once the vault joined an account. */
  accountId: string | null;
  /** 32 lower-case hex characters for this device's sync identity. */
  deviceId: string | null;
  /** Unix seconds of the last completed exchange; null if it never ran. */
  lastSyncAt: number | null;
  state: SyncState;
  /** The last failure in words, or null; never a stack trace or key material. */
  error: string | null;
  /** Local edits still waiting for the next push. */
  pendingPush: number;
  /** Items with at least one field both sides changed. */
  conflicts: number;
  /** Automatic sync is on. The timer only runs while the vault is unlocked. */
  auto: boolean;
  /** Seconds between automatic runs; `0` means off. */
  intervalSecs: number;
}

export interface ConflictField {
  /** `"title"`, `"notes"`, `"fields.<id>"` or `"deleted"`. */
  path: string;
  /** Human label, taken from the local body. */
  label: string;
  /** Rendered local value; empty when this side has no value. */
  local: string;
  remote: string;
  /** Mask both sides until the user reveals them, as the editor does. */
  sensitive: boolean;
}

export interface ConflictView {
  itemId: string;
  title: string;
  /** Unix seconds of the local edit (or milliseconds; the screen accepts both). */
  localUpdatedAt: number;
  /** The device that wrote the other side. */
  remoteDevice: string;
  fields: ConflictField[];
}

/** The whole-item decision; there is deliberately no per-field merge. */
/** What the hosting device reads out to the joining one. */
export type InviteResult = {
  code: string;
  sealed: string;
  senderAgreementPub: string;
};

export type ResolveChoice = "mine" | "theirs" | "both";

export const sync = {
  /** Current state; safe to ask without making any network call. */
  status: () => invoke<SyncStatus>("sync_status"),
  /** Run one exchange now and report the state that resulted from it. */
  now: () => invoke<SyncStatus>("sync_now"),
  /**
   * Set the automatic period, or turn it off with `0`. The core stores the
   * setting; the timer itself lives in the shell and only runs unlocked.
   */
  setAuto: (args: { intervalSecs: number }) =>
    invoke<SyncStatus>("sync_set_auto", args),
  /** Point this device at a sync server; the core validates the address. */
  configure: (server: string) =>
    invoke<SyncStatus>("sync_configure", { server }),
  /**
   * Register this device's signing key with the service. Idempotent: running
   * it again re-publishes the same device, so a card may offer it as "again".
   */
  register: () => invoke<SyncStatus>("sync_register"),
  /**
   * Join an account another device already owns, with the three values that
   * device printed: its code, the sealed account key and its agreement key.
   */
  invite: (args: { guestDeviceId: string; guestAgreementPub: string }) =>
    invoke<InviteResult>("sync_invite", args),
  approve: (args: { guestDeviceId: string }) =>
    invoke<void>("sync_enroll_ack", args),
  acceptEnrollment: (args: {
    code: string;
    sealed: string;
    senderAgreementPub: string;
  }) => invoke<SyncStatus>("sync_enroll_accept", args),
  /**
   * Drop the server address and the sync cursor. The cursor is what makes the
   * next run incremental, so forgetting it makes the next run re-read the
   * whole log; local items are untouched.
   */
  forget: () => invoke<SyncStatus>("sync_forget"),
  /** Every item waiting for a decision, one entry per item. */
  conflicts: () => invoke<ConflictView[]>("sync_conflicts"),
  /** Resolve one item; returns the state after the write. */
  resolve: (itemId: string, choice: ResolveChoice) =>
    invoke<SyncStatus>("sync_resolve", { itemId, choice }),
};

/** Fired after any sync command so every mounted reader re-reads the status. */
export const SYNC_CHANGED_EVENT = "kestrel:sync-changed";

export function announceSyncChange(): void {
  window.dispatchEvent(new Event(SYNC_CHANGED_EVENT));
}

/** Fired by the window-bar pill; the shell's panel hook answers by opening Settings. */
export const SYNC_VIEW_EVENT = "kestrel:sync-view";

/**
 * Set while Settings is not mounted yet. The pill can be clicked from the
 * vault, so the request has to survive until Settings mounts and can scroll to
 * the card. It expires: a request made while the vault is locked has no shell
 * to open, and must not scroll a Settings page opened minutes later.
 */
const VIEW_REQUEST_MS = 5000;
let pendingViewAt = 0;

/** Ask for Settings → Sync. The shell's listener opens the panel. */
export function requestSyncView(): void {
  pendingViewAt = Date.now();
  window.dispatchEvent(new Event(SYNC_VIEW_EVENT));
}

/** True exactly once per `requestSyncView`, for a Settings page that mounts late. */
export function consumeSyncView(): boolean {
  const pending =
    pendingViewAt !== 0 && Date.now() - pendingViewAt < VIEW_REQUEST_MS;
  pendingViewAt = 0;
  return pending;
}
