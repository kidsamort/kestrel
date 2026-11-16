/**
 * SSH agent bridge — mirrors `src-tauri/src/agent/mod.rs`.
 *
 * The agent is served by the Rust side on the OpenSSH named pipe; this module
 * only reports its state. Nothing here can start, stop or reconfigure it: the
 * pipe's lifetime is the app's, so a renderer cannot open a vault or export a
 * key through it.
 */
import { invoke } from "@tauri-apps/api/core";

/** An `sshKey` item the agent refuses to serve, and why. */
export interface SkippedKey {
  title: string;
  reason: string;
}

/** Snapshot returned by `agent_status`. */
export interface AgentStatus {
  /** The pipe exists and its accept loop is running. */
  running: boolean;
  /** Always `\\.\pipe\openssh-ssh-agent`; surfaced so the copy stays honest. */
  pipe: string;
  /** Keys the unlocked vault currently offers (0 while locked). */
  keyCount: number;
  locked: boolean;
  skipped: SkippedKey[];
  /** Why the pipe could not be created, e.g. another agent owns the name. */
  error: string | null;
}

export const agent = {
  /** Pipe name, running state, served key count and skipped-key report. */
  status: () => invoke<AgentStatus>("agent_status"),
};
