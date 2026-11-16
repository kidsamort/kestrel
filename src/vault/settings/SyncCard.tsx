/**
 * Settings → Sync.
 *
 * The card is the whole configuration surface: where the server is, what the
 * core thinks the state is, and the two actions a person can take (sync now,
 * review conflicts). It never claims a sync that the core did not report: every
 * command returns the resulting `SyncStatus`, and that value is what the card
 * paints.
 *
 * The copy says what the design promises, no more: the server stores sealed
 * ciphertext it cannot read, and a field both sides changed is surfaced instead
 * of merged.
 */
import { useEffect, useState } from "react";
import {
  Check,
  CloudCheck,
  CloudOff,
  HardDrive,
  LoaderCircle,
  RefreshCw,
  Server,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import {
  announceSyncChange,
  sync,
  SYNC_CHANGED_EVENT,
  type InviteResult,
  type SyncStatus,
} from "../../lib/api-sync";
import { relativeTime } from "../../lib/format";
import { Button } from "../../ui/Button";
import Select from "../../ui/Select";
import { Switch } from "../../ui/Switch";
import "../../styles/recovery.css";

/** An http(s) URL without its trailing slash; null when the text is not one. */
function normaliseServer(value: string): string | null {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return trimmed;
  } catch {
    return null;
  }
}

/**
 * The whole vocabulary of automatic periods. The select offers exactly these,
 * so the card never sends a period the scheduler has to decide about: `secs`
 * is what the core stores, and the list is the label mapping a person reads.
 */
const AUTO_INTERVALS = [
  { secs: 300, label: "Every 5 minutes" },
  { secs: 900, label: "Every 15 minutes" },
  { secs: 3600, label: "Every hour" },
] as const;

/** What the switch picks when the vault has never had a period stored. */
const AUTO_DEFAULT_SECS = 900;

/** One honest sentence for the state, in the order a person needs it. */
function stateSentence(status: SyncStatus): string {
  if (!status.configured) {
    return "No sync server is configured. Nothing leaves this device.";
  }
  switch (status.state) {
    case "conflict":
      return `${status.conflicts} item${
        status.conflicts === 1 ? " has" : "s have"
      } edits from two devices. Nothing was merged; review the two sides.`;
    case "error":
      return "The last exchange failed. The core's message, if any, is below.";
    case "syncing":
      return "Syncing now. This card updates from the core's report, not a guess.";
    case "offline":
      return `Offline. ${
        status.pendingPush === 0
          ? "There is nothing waiting."
          : `${status.pendingPush} change${
              status.pendingPush === 1 ? "" : "s"
            } wait on this device.`
      }`;
    default:
      // "Up to date" is a claim about the queue, not about the clock: an item
      // saved since the last exchange is not up to date, it is waiting.
      if (status.pendingPush > 0) {
        return `${status.pendingPush} change${
          status.pendingPush === 1 ? "" : "s"
        } waiting to be uploaded.`;
      }
      return status.lastSyncAt
        ? `Up to date. Last exchange ${relativeTime(status.lastSyncAt)}.`
        : "Connected, but no exchange has completed yet.";
  }
}

export default function SyncCard({
  onReviewConflicts,
}: {
  /** Opens the full-pane conflict review; owned by the Settings page. */
  onReviewConflicts: () => void;
}) {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  // The rail says whether sync is set up, and shouts when it needs attention.
  useSettingsStatus(
    "sync",
    status
      ? status.conflicts > 0 || status.state === "error"
        ? {
            tone: "attention",
            label: status.conflicts > 0 ? `${status.conflicts} conflict` : "Failed",
          }
        : {
            tone: status.configured ? "on" : "off",
            label: status.configured ? "Configured" : "Not set up",
          }
      : null,
  );

  const [problem, setProblem] = useState<string | null>(null);
  const [server, setServer] = useState("");
  const [serverTouched, setServerTouched] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [busy, setBusy] = useState<
    | "saving"
    | "syncing"
    | "registering"
    | "joining"
    | "forgetting"
    | "inviting"
    | "approving"
    | "auto"
    | null
  >(null);
  const [note, setNote] = useState<string | null>(null);
  // The period the switch would use when it is turned on. Kept here so that
  // turning the timer off and on again does not silently change the period.
  const [autoSecs, setAutoSecs] = useState<number>(AUTO_DEFAULT_SECS);
  const [autoError, setAutoError] = useState<string | null>(null);
  // The device half of the card keeps its own messages: a failed enrolment is
  // not a bad server address and must not be reported as one.
  const [registerNote, setRegisterNote] = useState<string | null>(null);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [inviteDevice, setInviteDevice] = useState("");
  const [inviteAgreement, setInviteAgreement] = useState("");
  const [invite, setInvite] = useState<InviteResult | null>(null);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [joinCode, setJoinCode] = useState("");
  const [joinSealed, setJoinSealed] = useState("");
  const [joinSender, setJoinSender] = useState("");
  const [joinError, setJoinError] = useState<string | null>(null);
  const [confirmForget, setConfirmForget] = useState(false);
  const [forgetError, setForgetError] = useState<string | null>(null);

  // Read on mount and after any command, the same contract the pill follows:
  // a command in this card, in the conflict screen or in the shell announces
  // itself through `SYNC_CHANGED_EVENT` instead of leaving a stale count here.
  useEffect(() => {
    let live = true;
    let latest = 0;

    const read = () => {
      const ticket = ++latest;
      sync
        .status()
        .then((next) => {
          // A slower reply must not overwrite a newer one. A successful read
          // does not clear `problem`: that slot also carries the last command's
          // failure, which the status query knows nothing about.
          if (!live || ticket !== latest) return;
          setStatus(next);
          setServer((current) =>
            current.length > 0 ? current : (next.server ?? ""),
          );
        })
        .catch((failure: unknown) => {
          if (live && ticket === latest) setProblem(errorText(failure));
        });
    };

    read();
    window.addEventListener(SYNC_CHANGED_EVENT, read);
    return () => {
      live = false;
      window.removeEventListener(SYNC_CHANGED_EVENT, read);
    };
  }, []);

  async function saveServer() {
    if (busy) return;
    const address = normaliseServer(server);
    if (!address) {
      setFieldError(
        "Enter an http:// or https:// address, for example http://127.0.0.1:8787.",
      );
      return;
    }
    setBusy("saving");
    setFieldError(null);
    setNote(null);
    try {
      const next = await sync.configure(address);
      setStatus(next);
      setServer(next.server ?? address);
      setServerTouched(false);
      setProblem(null);
      setNote("The server address is saved. Nothing has been uploaded yet.");
    } catch (failure) {
      setFieldError(errorText(failure));
    } finally {
      setBusy(null);
      // The pill must re-read even when the command failed: its old state is
      // no longer known to be current.
      announceSyncChange();
    }
  }

  async function syncNow() {
    if (busy) return;
    setBusy("syncing");
    setNote(null);
    try {
      const next = await sync.now();
      setStatus(next);
      setProblem(null);
      setNote(
        next.lastSyncAt
          ? `Exchange finished ${relativeTime(next.lastSyncAt)}.`
          : "The core finished the exchange.",
      );
    } catch (failure) {
      setProblem(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  // Turning the timer on or off, or moving it to another period. The core's
  // reply is the only thing that flips the switch: a failed command leaves the
  // painted state where it was and shows why.
  async function changeAuto(intervalSecs: number) {
    if (busy) return;
    setBusy("auto");
    setAutoError(null);
    try {
      const next = await sync.setAuto({ intervalSecs });
      setStatus(next);
      if (next.intervalSecs > 0) setAutoSecs(next.intervalSecs);
    } catch (failure) {
      setAutoError(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  async function registerDevice() {
    if (busy) return;
    setBusy("registering");
    setRegisterError(null);
    setRegisterNote(null);
    try {
      const next = await sync.register();
      setStatus(next);
      setRegisterNote("This device is registered with the service.");
    } catch (failure) {
      setRegisterError(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  async function inviteDeviceNow() {
    if (busy) return;
    const guestDeviceId = inviteDevice.trim();
    const guestAgreementPub = inviteAgreement.trim();
    if (!guestDeviceId || !guestAgreementPub) {
      setInviteError(
        "Enter the joining device's id and its agreement key, both from its own Sync card.",
      );
      return;
    }
    setBusy("inviting");
    setInviteError(null);
    try {
      setInvite(await sync.invite({ guestDeviceId, guestAgreementPub }));
    } catch (failure) {
      setInviteError(errorText(failure));
      setInvite(null);
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  async function approveDevice() {
    if (busy) return;
    setBusy("approving");
    setInviteError(null);
    try {
      await sync.approve({ guestDeviceId: inviteDevice.trim() });
      setInviteDevice("");
      setInviteAgreement("");
      setInvite(null);
    } catch (failure) {
      setInviteError(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  async function joinAccount() {
    if (busy) return;
    const code = joinCode.trim();
    const sealed = joinSealed.trim();
    const senderAgreementPub = joinSender.trim();
    if (!code || !sealed || !senderAgreementPub) {
      setJoinError(
        "Fill in the code, the sealed envelope and the sender's agreement key.",
      );
      return;
    }
    setBusy("joining");
    setJoinError(null);
    try {
      // The core decides whether this vault may join; a vault that already
      // holds an account refuses here, and the refusal is shown as it comes.
      const next = await sync.acceptEnrollment({
        code,
        sealed,
        senderAgreementPub,
      });
      setStatus(next);
      setJoinCode("");
      setJoinSealed("");
      setJoinSender("");
    } catch (failure) {
      setJoinError(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  async function forgetServer() {
    if (busy) return;
    setBusy("forgetting");
    setForgetError(null);
    try {
      const next = await sync.forget();
      setStatus(next);
      setServer(next.server ?? "");
      setServerTouched(false);
      setNote(null);
      setRegisterNote(null);
      setConfirmForget(false);
    } catch (failure) {
      setForgetError(errorText(failure));
    } finally {
      setBusy(null);
      announceSyncChange();
    }
  }

  const configured = status?.configured ?? false;

  // The timer is offered, never hidden: a vault with no server or no account
  // sees why it cannot run one yet, instead of a control that quietly vanished.
  const autoBlocked =
    status === null
      ? null
      : !status.configured
        ? "Save a server address first: the timer has nothing to talk to."
        : status.accountId === null
          ? "This vault has no account yet, and auto-sync needs one to attach this device to."
          : null;
  // Only a period this card offers can be painted in its own select; anything
  // else (0 from off, or a value another build stored) falls back to the period
  // the switch would send.
  const autoPeriod =
    status !== null &&
    AUTO_INTERVALS.some((entry) => entry.secs === status.intervalSecs)
      ? status.intervalSecs
      : autoSecs;

  return (
    <section className="card" id="sync-card" aria-labelledby="sync-title">
      <div className="card-head">
        <h2 className="card-title" id="sync-title">
          <RefreshCw size={15} aria-hidden /> Sync
        </h2>
      </div>
      <p className="card-copy">
        Sync keeps the same items on every device you enrol. The server stores
        only sealed ciphertext: it cannot read a title, a field or a note, and it
        never receives the vault key or the account key. When two devices change
        the same field without seeing each other, the item is held as a{" "}
        <strong>conflict</strong> — Kestrel never merges two edits silently.
      </p>
      <p className="card-copy">
        Conflicts are resolved one item at a time: keep this device's version,
        keep the other device's, or keep both and let the vault create a copy.
        Nothing is uploaded until a server is set and a sync runs.
      </p>

      {problem ? (
        <p className="form-error" role="alert">
          {problem}
        </p>
      ) : status === null ? (
        <p className="card-copy">Reading sync state…</p>
      ) : (
        <>
          <p className="recovery-state" role="status">
            {status.state === "conflict" ? (
              <TriangleAlert size={14} aria-hidden />
            ) : status.state === "error" ? (
              <ShieldAlert size={14} aria-hidden />
            ) : status.state === "syncing" ? (
              <LoaderCircle size={14} aria-hidden />
            ) : status.configured ? (
              <CloudCheck size={14} aria-hidden />
            ) : (
              <CloudOff size={14} aria-hidden />
            )}
            {stateSentence(status)}
          </p>
          {status.error ? (
            <p className="form-error" role="alert">
              {status.error}
            </p>
          ) : null}
        </>
      )}

      <div className="card-head">
        <h3 className="card-title">
          <Server size={14} aria-hidden /> Server
        </h3>
      </div>
      <p className="card-copy">
        {configured
          ? "This is the base address the client talks to. Changing it keeps the account and device identity; the next sync starts against the new server."
          : "Start the sync service, then paste the base address it listens on. Saving the address stores it locally and does not send an item by itself."}
      </p>
      <label className="field-label" htmlFor="sync-server">
        Server URL
      </label>
      <div className="input-shell">
        <input
          id="sync-server"
          className="input is-mono"
          type="url"
          inputMode="url"
          spellCheck={false}
          autoComplete="off"
          value={server}
          placeholder="http://127.0.0.1:8787"
          onChange={(event) => {
            setServer(event.target.value);
            setServerTouched(true);
            setFieldError(null);
            setNote(null);
          }}
        />
      </div>
      {fieldError ? (
        <p className="form-error" role="alert">
          {fieldError}
        </p>
      ) : null}
      <div className="form-actions sync-actions">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={busy !== null || !server.trim()}
          onClick={() => void saveServer()}
        >
          {busy === "saving" ? "Saving…" : "Save server"}
        </Button>
        {note ? (
          <span className="form-ok">
            <Check size={13} aria-hidden /> {note}
          </span>
        ) : null}
      </div>

      {status ? (
        <>
          <div className="card-head">
            <h3 className="card-title">
              <HardDrive size={14} aria-hidden /> This device
            </h3>
          </div>
          <dl className="about-list sync-facts">
            <div>
              <dt>Account</dt>
              <dd className="mono">{status.accountId ?? "—"}</dd>
            </div>
            <div>
              <dt>Device</dt>
              <dd className="mono">{status.deviceId ?? "—"}</dd>
            </div>
            <div>
              <dt>Last sync</dt>
              <dd>
                {status.lastSyncAt
                  ? relativeTime(status.lastSyncAt)
                  : "Never synced"}
              </dd>
            </div>
            <div>
              <dt>Waiting to push</dt>
              <dd className="mono">
                {status.pendingPush} change
                {status.pendingPush === 1 ? "" : "s"}
              </dd>
            </div>
          </dl>

          <div className="form-actions sync-actions">
            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={!configured || busy !== null}
              onClick={() => void syncNow()}
            >
              {busy === "syncing" ? "Syncing…" : "Sync now"}
            </Button>
            {!configured ? (
              <span className="setting-hint">
                Save a server address first.
              </span>
            ) : null}
          </div>

          {configured ? (
            <>
              {status.accountId === null ? (
                <p className="setting-hint">
                  Sync needs an account first: create or join one in Settings →
                  Account, then register this device here. There is nothing for
                  the service to attach a device to until this vault has an
                  account id.
                </p>
              ) : (
                <div className="form-actions sync-actions">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => void registerDevice()}
                  >
                    {busy === "registering"
                      ? "Registering…"
                      : registerNote
                        ? "Register again"
                        : "Register this device"}
                  </Button>
                  {registerNote ? (
                    <span className="form-ok">
                      <Check size={13} aria-hidden /> {registerNote}
                    </span>
                  ) : null}
                </div>
              )}
              {registerError ? (
                <p className="form-error" role="alert">
                  {registerError}
                </p>
              ) : null}

              <details className="sync-join">
                <summary>Invite a device</summary>
                <p className="setting-hint">
                  Read this device's two public keys from the joining device
                  (Settings → Sync → This device), enter them here, and read the
                  code back. The sealed envelope and the sender key below are
                  what that device's "Join" panel asks for.
                </p>
                <label className="field-label" htmlFor="sync-invite-device">
                  Joining device id
                </label>
                <div className="input-shell">
                  <input
                    id="sync-invite-device"
                    className="input is-mono"
                    type="text"
                    spellCheck={false}
                    autoComplete="off"
                    value={inviteDevice}
                    placeholder="32 hex characters"
                    onChange={(event) => {
                      setInviteDevice(event.target.value);
                      setInviteError(null);
                    }}
                  />
                </div>
                <label className="field-label" htmlFor="sync-invite-agreement">
                  Joining device agreement key
                </label>
                <div className="input-shell">
                  <input
                    id="sync-invite-agreement"
                    className="input is-mono"
                    type="text"
                    spellCheck={false}
                    autoComplete="off"
                    value={inviteAgreement}
                    placeholder="64 hex characters"
                    onChange={(event) => {
                      setInviteAgreement(event.target.value);
                      setInviteError(null);
                    }}
                  />
                </div>
                <div className="form-actions sync-actions">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => void inviteDeviceNow()}
                  >
                    {busy === "inviting" ? "Creating invite…" : "Create invite"}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={busy !== null || !inviteDevice.trim()}
                    onClick={() => void approveDevice()}
                  >
                    {busy === "approving" ? "Approving…" : "Approve claim"}
                  </Button>
                </div>
                {invite ? (
                  <div className="sync-invite-result">
                    <p className="setting-hint">
                      Read these three values to the other device, then press
                      Approve claim once it has joined.
                    </p>
                    <code className="sync-invite-code">{invite.code}</code>
                    <code className="sync-invite-code">{invite.sealed}</code>
                    <code className="sync-invite-code">
                      {invite.senderAgreementPub}
                    </code>
                  </div>
                ) : null}
                {inviteError ? (
                  <p className="form-error" role="alert">
                    {inviteError}
                  </p>
                ) : null}
              </details>

              <details className="sync-join">
                <summary>Join an account instead</summary>
                <p className="setting-hint">
                  The other device prints these three values from its own Sync
                  card. Joining replaces nothing: a vault that already has an
                  account refuses, and the account key arrives sealed to this
                  device's keypair.
                </p>
                <label className="field-label" htmlFor="sync-join-code">
                  Code
                </label>
                <div className="input-shell">
                  <input
                    id="sync-join-code"
                    className="input is-mono"
                    type="text"
                    spellCheck={false}
                    autoComplete="off"
                    value={joinCode}
                    placeholder="XXXX-XXXX-…"
                    onChange={(event) => {
                      setJoinCode(event.target.value);
                      setJoinError(null);
                    }}
                  />
                </div>
                <label className="field-label" htmlFor="sync-join-sealed">
                  Sealed envelope
                </label>
                <div className="input-shell">
                  <textarea
                    id="sync-join-sealed"
                    className="input is-mono textarea"
                    rows={3}
                    spellCheck={false}
                    autoComplete="off"
                    value={joinSealed}
                    placeholder="the sealed account key, hex"
                    onChange={(event) => {
                      setJoinSealed(event.target.value);
                      setJoinError(null);
                    }}
                  />
                </div>
                <label className="field-label" htmlFor="sync-join-sender">
                  Sender agreement key
                </label>
                <div className="input-shell">
                  <input
                    id="sync-join-sender"
                    className="input is-mono"
                    type="text"
                    spellCheck={false}
                    autoComplete="off"
                    value={joinSender}
                    placeholder="64 hex characters"
                    onChange={(event) => {
                      setJoinSender(event.target.value);
                      setJoinError(null);
                    }}
                  />
                </div>
                <div className="form-actions sync-actions">
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => void joinAccount()}
                  >
                    {busy === "joining" ? "Joining…" : "Join"}
                  </Button>
                </div>
                {joinError ? (
                  <p className="form-error" role="alert">
                    {joinError}
                  </p>
                ) : null}
              </details>
            </>
          ) : null}

          <div className="setting-row sync-auto-row">
            <span className="setting-label">
              Sync automatically
              <span className="setting-hint">
                {autoBlocked ??
                  (status.auto
                    ? "Runs on a timer while this vault is unlocked."
                    : "Off. Nothing runs until you press Sync now.")}
              </span>
            </span>
            <span className="setting-value">
              {status.auto ? (
                <div className="select-shell">
                  <Select
                    label="Automatic sync interval"
                    value={String(autoPeriod)}
                    disabled={busy !== null}
                    options={AUTO_INTERVALS.map((entry) => ({
                      value: String(entry.secs),
                      label: entry.label,
                    }))}
                    onChange={(value) => void changeAuto(Number(value))}
                  />
                </div>
              ) : null}
              <Switch
                label="Sync automatically"
                checked={status.auto}
                // Only turning it on is gated: a setting that is already on
                // must stay switchable off.
                disabled={busy !== null || (autoBlocked !== null && !status.auto)}
                onCheckedChange={(next) =>
                  void changeAuto(next ? autoSecs : 0)
                }
              />
            </span>
          </div>
          {status.auto ? (
            <p className="setting-hint sync-auto-note">
              It runs only while this vault is unlocked and Kestrel is open: a
              locked vault does not sync. A failed run waits before trying
              again, backing off to at most half an hour.
            </p>
          ) : null}
          {autoError ? (
            <p className="form-error" role="alert">
              {autoError}
            </p>
          ) : null}

          <div className="setting-row sync-conflict-row">
            <span className="setting-label">
              Conflicts
              <span className="setting-hint">
                Two devices changed the same field. Each item waits here until
                you choose a side; no version is discarded by a merge rule.
              </span>
            </span>
            <span className="setting-value">
              <span className="sync-conflict-count">
                {status.conflicts}
              </span>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={onReviewConflicts}
              >
                {status.conflicts === 0 ? "Review" : "Review conflicts"}
              </Button>
            </span>
          </div>

          {serverTouched ? (
            <p className="setting-hint">
              The address above has unsaved changes.
            </p>
          ) : null}

          {configured ? (
            <>
              <div className="form-actions sync-actions sync-forget">
                {confirmForget ? (
                  <>
                    <span className="setting-hint">
                      Forgetting the server also clears the sync cursor: the
                      next run re-reads the whole log. Items on this device stay
                      where they are.
                    </span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={busy !== null}
                      onClick={() => void forgetServer()}
                    >
                      {busy === "forgetting"
                        ? "Forgetting…"
                        : "Yes, forget the server"}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={busy !== null}
                      onClick={() => setConfirmForget(false)}
                    >
                      Keep it
                    </Button>
                  </>
                ) : (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={busy !== null}
                    onClick={() => {
                      setConfirmForget(true);
                      setForgetError(null);
                    }}
                  >
                    Forget server
                  </Button>
                )}
              </div>
              {forgetError ? (
                <p className="form-error" role="alert">
                  {forgetError}
                </p>
              ) : null}
            </>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
