/**
 * Settings → Developer. The CLI/SDK card reports the automation pipe, whether
 * a client is paired and the token the user must copy exactly once. There is no
 * toggle here: the pipe's lifetime is the app's, and pairing is the only
 * control, because a token is the only thing a client needs.
 */
import { useEffect, useState } from "react";
import { Check, Copy, TerminalSquare, Trash2 } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import { sdk, type SdkStatus } from "../../lib/api-sdk";
import { access, type CliToken } from "../../lib/api-access";
import { relativeTime } from "../../lib/format";
import { Button } from "../../ui/Button";
import { Dialog } from "../../ui/Overlay";
import type { VaultState } from "../../types";
import "../../styles/sdk.css";

const PIPE = String.raw`\\.\pipe\kestrel-sdk`;

const COMMANDS = [
  "kestrel-cli status",
  "kestrel-cli --token <token> list",
  "kestrel-cli --token <token> copy --id <item> --field <field>",
  "kestrel-cli --token <token> run --env <item>:<field>=<VAR> -- <command...>",
];

export default function SdkCard({ state }: { state: VaultState }) {
  const [status, setStatus] = useState<SdkStatus | null>(null);
  // Not a switch, so no dot: the pipe is raised by the app. What the rail can
  // say is whether a CLI can use it - amber until a token is paired.
  useSettingsStatus(
    "sdk",
    status
      ? !status.running
        ? { tone: "attention", label: "Not running" }
        : status.paired
          ? { tone: "on", label: "Paired" }
          : { tone: "attention", label: "Not paired" }
      : null,
  );
  const [error, setError] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);
  /** Present only between "Pair a CLI" and "Done": it is never re-readable. */
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  /** Live CLI tokens, from the session authority rather than the grant rows. */
  const [tokens, setTokens] = useState<CliToken[]>([]);
  const [revoking, setRevoking] = useState<CliToken | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  async function refreshTokens() {
    try {
      setTokens(await access.cliTokens());
    } catch (reason) {
      setError(errorText(reason));
    }
  }

  // Re-read when the session changes: pairing state and the locked line both
  // depend on it, and a token from a previous session must not look valid.
  useEffect(() => {
    let live = true;
    sdk
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
    if (!state.locked) {
      access
        .cliTokens()
        .then((value) => {
          if (live) setTokens(value);
        })
        .catch((reason) => {
          if (live) setError(errorText(reason));
        });
    }
    if (state.locked) {
      // The core revokes the token on lock; drop the visible copy with it.
      setToken(null);
      setCopied(false);
      setTokens([]);
      setRevoking(null);
    }
    return () => {
      live = false;
    };
  }, [state.locked, state.vaultUuid]);

  const running = status?.running ?? false;
  const paired = status?.paired ?? false;
  const endState = error
    ? "Unavailable"
    : !status
      ? "Checking…"
      : running
        ? paired
          ? "Running · paired"
          : "Running · not paired"
        : "Not running";

  async function pair() {
    setPairing(true);
    setError(null);
    try {
      const pairing = await sdk.pair();
      setToken(pairing.token);
      setCopied(false);
      setCopyError(null);
      // The token is valid even if this read fails; report only the pair
      // failure as a failure.
      sdk.status().then(setStatus).catch(() => undefined);
      await refreshTokens();
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setPairing(false);
    }
  }

  async function revoke() {
    if (!revoking) return;
    setRevokeBusy(true);
    setRevokeError(null);
    try {
      await access.revokeCli(revoking.client);
      // There is one CLI slot, so any revoke invalidates the one-time panel
      // that may still be showing the previous token.
      setToken(null);
      setCopied(false);
      setRevoking(null);
      sdk.status().then(setStatus).catch(() => undefined);
      await refreshTokens();
    } catch (reason) {
      setRevokeError(errorText(reason));
    } finally {
      setRevokeBusy(false);
    }
  }

  async function copyToken() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setCopyError(null);
    } catch (reason) {
      setCopyError(errorText(reason));
    }
  }

  function dismissToken() {
    setToken(null);
    setCopied(false);
    setCopyError(null);
  }

  return (
    <section className="card" aria-labelledby="sdk-title">
      <div className="card-head">
        <h2 className="card-title" id="sdk-title">
          <TerminalSquare size={15} aria-hidden /> CLI &amp; SDK
        </h2>
        <span
          className={`sdk-state ${
            !running ? "is-off" : paired ? "is-on" : "is-warn"
          }`}
          aria-live="polite"
        >
          {endState}
        </span>
      </div>

      <p className="card-copy">
        Scripts and editors reach the vault through a named pipe owned by your
        Windows account. The response never carries a value: <code>list</code>
        returns ids and titles, <code>copy</code> puts a field on the clipboard
        with the timed wipe, and <code>run</code> places values in the
        environment of a process the app starts. A paired token can therefore
        read any item while the vault is unlocked — pair only a tool you trust,
        and lock the vault to revoke it.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>Pipe</span>
          <span className="setting-hint">
            {status?.error
              ? status.error
              : running
                ? "Accepting local clients for this user only."
                : "Kestrel could not create the pipe."}
          </span>
        </div>
        <code className="sdk-pipe">{status?.pipe ?? PIPE}</code>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Access</span>
          <span className="setting-hint">
            {paired
              ? "One token is valid for this session. Locking the vault revokes it."
              : "No client is paired. Issue a token to let a CLI in."}
          </span>
        </div>
        <span className="sdk-count">{paired ? "Paired" : "Not paired"}</span>
      </div>

      {token ? (
        <div className="sdk-token" role="group" aria-label="Pairing token">
          <div className="sdk-token-head">
            <span className="setting-label">
              <span>Token</span>
              <span className="setting-hint">
                Shown once. Kestrel keeps only its hash; re-pairing replaces it.
              </span>
            </span>
            <div className="sdk-actions">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={copyToken}
              >
                {copied ? (
                  <>
                    <Check size={13} aria-hidden /> Copied
                  </>
                ) : (
                  <>
                    <Copy size={13} aria-hidden /> Copy
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={dismissToken}
              >
                Done
              </button>
            </div>
          </div>
          <code className="sdk-token-value">{token}</code>
          {copyError ? (
            <p className="sdk-error" role="alert">
              {copyError}
            </p>
          ) : null}
        </div>
      ) : (
        <div className="setting-row">
          <div className="setting-label">
            <span>Pair a client</span>
            <span className="setting-hint">
              {state.locked
                ? "Unlock the vault to pair a CLI."
                : "The token is displayed once; copy it into --token or KESTREL_TOKEN."}
            </span>
          </div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={pair}
            disabled={pairing || state.locked || !running}
          >
            {pairing ? "Pairing…" : "Pair a CLI"}
          </button>
        </div>
      )}

      <div className="sdk-tokens">
        <div className="sdk-tokens-head">
          <span className="setting-label">
            <span>Paired CLI tokens</span>
            <span className="setting-hint">
              A token lives until the vault locks. Revoking it also deletes the
              field grants recorded under its name.
            </span>
          </span>
        </div>
        {tokens.length === 0 ? (
          <p className="sdk-tokens-empty">
            No CLI token is paired for this session.
          </p>
        ) : (
          <ul className="sdk-token-list">
            {tokens.map((entry) => (
              <li
                className="sdk-token-row"
                key={entry.client ?? "unrestricted"}
              >
                <div className="sdk-token-identity">
                  <span className="sdk-token-name">
                    {entry.client ?? "Unrestricted pairing"}
                  </span>
                  <span className="sdk-token-meta">
                    {entry.unrestricted
                      ? "unrestricted — reads every field while unlocked"
                      : `${entry.grants} field${
                          entry.grants === 1 ? "" : "s"
                        } granted`}
                    {" · issued "}
                    {relativeTime(entry.createdAt)}
                    {" · "}
                    {entry.expiresAt
                      ? `expires ${new Date(
                          entry.expiresAt * 1000,
                        ).toLocaleDateString(undefined, {
                          day: "numeric",
                          month: "short",
                          year:
                            new Date(entry.expiresAt * 1000).getFullYear() ===
                            new Date().getFullYear()
                              ? undefined
                              : "numeric",
                        })}`
                      : "no expiry"}
                    {entry.oneShot ? " · one-shot" : ""}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => {
                    setRevokeError(null);
                    setRevoking(entry);
                  }}
                >
                  <Trash2 size={13} aria-hidden /> Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="sdk-reference">
        <span className="sdk-reference-title">
          <TerminalSquare size={13} aria-hidden /> Commands
        </span>
        <pre className="sdk-code">
          {COMMANDS.map((command) => (
            <code key={command}>{command}</code>
          ))}
        </pre>
        <p className="setting-hint">
          Exit codes: 0 ok, 2 usage, 3 vault locked, 4 not paired, 5 server
          error. A value is never in the response; <code>run</code> forwards the
          child&apos;s output and exit code, so a child that echoes its
          environment does disclose it.
        </p>
      </div>

      {error ? (
        <p className="sdk-error" role="alert">
          {error}
        </p>
      ) : null}

      <Dialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) setRevoking(null);
        }}
        alert
        title="Revoke this CLI token?"
        description={
          revoking
            ? `${revoking.client ?? "The unrestricted CLI token"} ${
                revoking.unrestricted
                  ? "currently reads every field while the vault is unlocked."
                  : `currently holds ${revoking.grants} field grant${
                      revoking.grants === 1 ? "" : "s"
                    }.`
              } The token stops working at once and its grants are deleted; the client must be paired again.`
            : undefined
        }
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              disabled={revokeBusy}
              onClick={() => setRevoking(null)}
            >
              Keep token
            </Button>
            <Button
              variant="danger"
              size="sm"
              disabled={revokeBusy}
              onClick={revoke}
            >
              {revokeBusy ? "Revoking…" : "Revoke token"}
            </Button>
          </>
        }
      >
        {revokeError ? (
          <p className="sdk-error" role="alert">
            {revokeError}
          </p>
        ) : null}
      </Dialog>
    </section>
  );
}
