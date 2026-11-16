/**
 * Settings → SSH agent. Reports the pipe Kestrel serves, whether it is live and
 * how many vault keys it can sign with, plus the exact Windows copy for
 * pointing `ssh`/`git` at it. There is no toggle: the pipe's lifetime is the
 * app's, so a switch here could only lie.
 */
import { useEffect, useState } from "react";
import { KeyRound, TerminalSquare } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import { agent, type AgentStatus } from "../../lib/api-agent";
import type { VaultState } from "../../types";
import "../../styles/agent.css";

const SSH_AUTH_SOCK = String.raw`\\.\pipe\openssh-ssh-agent`;
const GIT_SSH_COMMAND = '"C:/Windows/System32/OpenSSH/ssh.exe"';

export default function AgentCard({ state }: { state: VaultState }) {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Re-read on lock/unlock: the key count and the "answers with failure while
  // locked" line change with the session, and the card must not show a stale
  // number for a vault that is now closed.
  useEffect(() => {
    let live = true;
    agent
      .status()
      .then((value) => {
        if (live) {
          setStatus(value);
          setError(null);
        }
      })
      .catch((reason) => {
        if (live) setError(errorText(reason));
      });
    return () => {
      live = false;
    };
  }, [state.locked, state.vaultUuid]);

  const running = status?.running ?? false;
  useSettingsStatus(
    "agent",
    status
      ? { tone: running ? "on" : "off", label: running ? "Serving" : "Stopped" }
      : null,
  );
  const locked = status?.locked ?? state.locked;
  const endState = error
    ? "Unavailable"
    : !status
      ? "Checking…"
      : running
        ? locked
          ? "Running · vault locked"
          : "Running"
        : "Not running";

  return (
    <section className="card" aria-labelledby="agent-title">
      <div className="card-head">
        <h2 className="card-title" id="agent-title">
          <KeyRound size={15} aria-hidden /> SSH agent
        </h2>
        <span
          className={`agent-state ${running ? "is-on" : "is-off"}`}
          aria-live="polite"
        >
          {endState}
        </span>
      </div>

      <p className="card-copy">
        Kestrel serves Ed25519 keys from this vault over the OpenSSH agent pipe,
        so <code>ssh</code> and <code>git</code> sign without a key ever leaving
        the vault. The agent reads through the unlocked session: while the vault
        is locked every request is answered with <code>SSH_AGENT_FAILURE</code>.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>Pipe</span>
          <span className="setting-hint">
            {status?.error
              ? status.error
              : running
                ? "Owned by Kestrel for this user only; no other account can connect."
                : "Kestrel could not create the pipe; another SSH agent may own it."}
          </span>
        </div>
        <code className="agent-pipe">{status?.pipe ?? SSH_AUTH_SOCK}</code>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Keys served</span>
          <span className="setting-hint">
            {locked
              ? "Vault is locked, so no key is offered."
              : `${status?.keyCount ?? 0} Ed25519 ${
                  status?.keyCount === 1 ? "key" : "keys"
                } from sshKey items, listed by their item name.`}
          </span>
        </div>
        <span className="agent-count">{locked ? "0" : (status?.keyCount ?? 0)}</span>
      </div>

      {status && status.skipped.length > 0 ? (
        <div className="agent-skipped" role="note">
          <span className="setting-hint">Not served:</span>
          <ul>
            {status.skipped.map((key) => (
              <li key={key.title}>
                <strong>{key.title}</strong> — {key.reason}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="agent-copy">
        <span className="agent-copy-title">
          <TerminalSquare size={13} aria-hidden /> Point your tools at the pipe
        </span>
        <p className="setting-hint">
          Windows has no Unix socket. The Windows OpenSSH client already uses
          this pipe, so <code>ssh-add -l</code> and <code>git</code> work as-is
          unless your shell exports a socket from Git Bash/Cygwin — override it:
        </p>
        <pre className="agent-code">
          <code>export SSH_AUTH_SOCK=&apos;{SSH_AUTH_SOCK}&apos;</code>
          <code>{`$env:SSH_AUTH_SOCK = '${SSH_AUTH_SOCK}'`}</code>
        </pre>
        <p className="setting-hint">
          To make Git use the Windows OpenSSH binary (which finds the pipe
          itself) instead of the bundled one:
        </p>
        <pre className="agent-code">
          <code>GIT_SSH_COMMAND={GIT_SSH_COMMAND}</code>
        </pre>
      </div>

      {error ? (
        <p className="agent-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
