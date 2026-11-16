/**
 * CLI/SDK bridge — mirrors `src-tauri/src/sdk/mod.rs`.
 *
 * The automation surface is a named pipe served by the Rust side. This module
 * can only read its state and mint a pairing token; it cannot enumerate items,
 * copy a field or run a command. Those go through the pipe, authenticated with
 * the token that `pair` returns exactly once.
 */
import { invoke } from "@tauri-apps/api/core";

/** Snapshot returned by `sdk_status`. Contains no secret. */
export interface SdkStatus {
  /** The pipe exists and its accept loop is running. */
  running: boolean;
  /** Always `\\.\pipe\kestrel-sdk`. */
  pipe: string;
  /** A token is valid for this session. A vault lock revokes it. */
  paired: boolean;
  unlocked: boolean;
  /** Why the pipe could not be created, if it could not. */
  error: string | null;
}

/** Returned by `sdk_pair`. The token is readable only in this response. */
export interface SdkPairing {
  pipe: string;
  token: string;
}

export const sdk = {
  status: () => invoke<SdkStatus>("sdk_status"),
  /** Mint a new token; any previous token stops working immediately. */
  pair: () => invoke<SdkPairing>("sdk_pair"),
};
