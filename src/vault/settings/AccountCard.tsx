/**
 * Settings → Account.
 *
 * The card is a state machine over `account_status`, a few transient values
 * (the Secret Key, shown exactly once, and one enrolment handover) and the v1
 * enrolment transport: the user reads a code aloud and carries the sealed blob
 * to the other device by hand. Enrolment itself makes no network call; the one
 * network path on this card is Revoke, which asks the configured sync service
 * to withdraw another device's access. No key material is persisted by the
 * renderer — the Secret Key lives in this component's state between "Create
 * account" and the acknowledgement, and the code lives there between "Show
 * enrolment code" and dismissal.
 *
 * Both halves of the flow are on this one card. A device with an account mints
 * the code and seals the account key to the other device's agreement public
 * key; a device without one shows its own public keys and joins with the three
 * values the sending device displayed. That is why the keys block is above the
 * branch: the joining device has to show its agreement key *before* it can
 * receive anything.
 */
import { useEffect, useState } from "react";
import { Ban, Check, Copy, KeyRound, ShieldAlert, ShieldCheck, Smartphone } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import {
  account,
  type AccountCreated,
  type AccountDevice,
  type AccountRevocation,
  type AccountStatus,
  type DeviceIdentity,
  type SealedEnrolment,
} from "../../lib/api-account";
import { Button } from "../../ui/Button";
import "../../styles/recovery.css";
import "../../styles/account.css";

/** A device key is one 32-byte public key, 64 hex characters. */
const AGREEMENT_KEY = /^[0-9a-fA-F]{64}$/;

export default function AccountCard() {
  const [status, setStatus] = useState<AccountStatus | null>(null);
  useSettingsStatus(
    "account",
    status
      ? {
          tone: status.exists && status.deviceCount > 0 ? "on" : "off",
          label: !status.exists
            ? "No account"
            : status.deviceCount === 0
              ? "No devices"
              : `${status.deviceCount} device${status.deviceCount === 1 ? "" : "s"}`,
        }
      : null,
  );
  const [devices, setDevices] = useState<AccountDevice[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<AccountCreated | null>(null);
  const [deviceKey, setDeviceKey] = useState("");
  const [verifyNote, setVerifyNote] = useState<string | null>(null);
  const [enrolment, setEnrolment] = useState<
    (SealedEnrolment & { code: string }) | null
  >(null);

  const [identity, setIdentity] = useState<DeviceIdentity | null>(null);
  const [keyProblem, setKeyProblem] = useState<string | null>(null);
  const [copied, setCopied] = useState<"signing" | "agreement" | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  const [joinCode, setJoinCode] = useState("");
  const [joinSealed, setJoinSealed] = useState("");
  const [joinSender, setJoinSender] = useState("");
  const [joined, setJoined] = useState<string | null>(null);

  /** The device whose Revoke button has been pressed once. */
  const [confirming, setConfirming] = useState<string | null>(null);
  /** What the last revocation actually did, so the card does not overclaim. */
  const [revocation, setRevocation] = useState<AccountRevocation | null>(null);

  useEffect(() => {
    let live = true;
    Promise.all([account.status(), account.devices()])
      .then(([next, list]) => {
        if (!live) return;
        setStatus(next);
        setDevices(list);
        setProblem(null);
      })
      .catch((failure: unknown) => {
        if (!live) return;
        setStatus(null);
        setProblem(errorText(failure));
      });
    // Asking for the public keys is what generates this device's keypair; it
    // needs the unlocked vault, so a locked session reports it separately
    // instead of hiding the account state that does not need the key.
    account
      .deviceIdentity()
      .then(async (next) => {
        if (!live) return;
        setIdentity(next);
        setKeyProblem(null);
        // The identity call is what creates this device's row, so the device
        // list read above can predate it. Read it again now that the row exists
        // instead of showing "no devices" under a device block.
        try {
          const list = await account.devices();
          if (live) setDevices(list);
        } catch {
          // A failed refresh leaves the earlier list; the block above still
          // shows the local device, which is the part that matters.
        }
      })
      .catch((failure: unknown) => {
        if (!live) return;
        setKeyProblem(errorText(failure));
      });
    return () => {
      live = false;
    };
  }, []);

  async function create() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const next = await account.create();
      setCreated(next);
      // Re-read rather than assume: creating the account also created this
      // device's keypair, and the device list has to show it.
      setStatus(await account.status());
      setDevices(await account.devices());
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  /** Re-open the Secret Key row and re-derive from it: `present` alone is a
   * tautology, `verified` is the check that the sealed copy still opens. */
  async function verifySecretKey() {
    setBusy(true);
    setError(null);
    setVerifyNote(null);
    try {
      const check = await account.secretKey();
      setVerifyNote(
        check.verified
          ? "The Secret Key row opens and re-derives the account key."
          : check.present
            ? "The row is present but does not open — replace the kit before you rely on it."
            : "No Secret Key row exists on this device. A joined device holds the account key only.",
      );
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function showEnrolment() {
    if (busy) return;
    const key = deviceKey.trim();
    if (!AGREEMENT_KEY.test(key)) {
      setError("Paste the other device's agreement key: 64 hex characters.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const minted = await account.enrolCode();
      const sealed = await account.sealForDevice(minted.code, key);
      setEnrolment({ ...sealed, code: minted.code });
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function join() {
    if (busy) return;
    const code = joinCode.trim();
    const sealed = joinSealed.trim();
    const sender = joinSender.trim();
    if (!code || !sealed || !sender) {
      setError(
        "Fill in the code, the sealed blob and the sender's agreement key.",
      );
      return;
    }
    if (!AGREEMENT_KEY.test(sender)) {
      setError("The sender's agreement key is 64 hex characters.");
      return;
    }
    setBusy(true);
    setError(null);
    setJoined(null);
    try {
      const claimed = await account.enrollClaim(code, sealed, sender);
      setJoined(claimed.accountId);
      setJoinCode("");
      setJoinSealed("");
      setJoinSender("");
      // The account row now exists; the core is the only source of truth for
      // what the card shows from here.
      setStatus(await account.status());
      setDevices(await account.devices());
    } catch (failure) {
      // A wrong code, a tampered blob and the wrong sender key all produce the
      // same sentence from the core, and this card adds nothing to it.
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function revokeDevice(device: AccountDevice) {
    if (busy) return;
    setBusy(true);
    setError(null);
    setRevocation(null);
    try {
      const result = await account.revokeDevice(device.deviceId);
      setRevocation(result);
      setConfirming(null);
      // Re-read both views: a server revocation keeps the row, a local-only one
      // removes it, and the device count changes only in the second case.
      setDevices(await account.devices());
      setStatus(await account.status());
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function copy(which: "signing" | "agreement", text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setCopyError(null);
    } catch (failure) {
      setCopyError(errorText(failure));
    }
  }

  const createdOn =
    status?.createdAt != null
      ? new Date(status.createdAt).toLocaleDateString(undefined, {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      : null;

  return (
    <section className="card" aria-labelledby="account-title">
      <div className="card-head">
        <h2 className="card-title" id="account-title">
          <KeyRound size={15} aria-hidden /> Account
        </h2>
      </div>
      <p className="card-copy">
        An account is the identity your other devices enrol against. It adds a
        second secret to the vault: the <strong>Secret Key</strong>, printed once
        and never transmitted. The account key is derived from the Secret Key
        alone — deliberately not from the master key, so changing the master
        password cannot strand a device that already holds it. A new device
        receives that account key sealed to its own agreement key; the sync
        service stores the envelope and cannot open it.
      </p>

      {problem ? (
        <p className="form-error" role="alert">
          {problem}
        </p>
      ) : status === null ? (
        <p className="card-copy">Checking for an account…</p>
      ) : status.exists ? (
        <p className="recovery-state" role="status">
          <ShieldCheck size={14} aria-hidden /> Account{" "}
          <code>{status.accountId}</code> created
          {createdOn ? ` ${createdOn}` : ""} · {status.deviceCount} device
          {status.deviceCount === 1 ? "" : "s"} · Secret Key{" "}
          {status.secretKeySet ? "set" : "not on this device"}
        </p>
      ) : (
        <p className="recovery-state" role="status">
          <ShieldAlert size={14} aria-hidden /> No account on this device yet.
          Create one here, or join an account that another device already has.
        </p>
      )}

      {created ? (
        <div className="recovery-preview">
          <span className="recovery-preview-label">
            Secret Key · shown once · account {created.accountId}
          </span>
          <code className="recovery-code">{created.secretKey}</code>
          <p className="recovery-preview-warn">
            <ShieldAlert size={13} aria-hidden /> Write this down and keep it
            away from this computer. It is the paper half of the account: the
            password alone will not enrol a new device without it, and this app
            cannot show it again.
          </p>
          <div className="form-actions">
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={() => setCreated(null)}
            >
              I have written it down
            </Button>
          </div>
        </div>
      ) : null}

      {joined ? (
        <p className="recovery-state" role="status">
          <ShieldCheck size={14} aria-hidden /> Joined account{" "}
          <code>{joined}</code>. The account key is sealed under this device's
          master key; the Secret Key stays on the device that created it.
        </p>
      ) : null}

      <div className="card-head">
        <h3 className="card-title">
          <Smartphone size={14} aria-hidden /> This device
        </h3>
      </div>
      {identity ? (
        <>
          <p className="card-copy">
            Every device has two keypairs: an <strong>Ed25519</strong> key that
            signs requests to the sync service and an <strong>X25519</strong>{" "}
            key that receives the sealed account key. Only the public halves are
            shown here; the private halves stay sealed under your master key.
            Give the agreement key to the device that holds the account, so it
            can seal the account key to this one.
          </p>
          <span className="field-label">
            This device's agreement key · {identity.deviceName}
          </span>
          <code className="recovery-code">{identity.agreementPub}</code>
          <div className="form-actions">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => void copy("agreement", identity.agreementPub)}
            >
              {copied === "agreement" ? (
                <>
                  <Check size={13} aria-hidden /> Copied
                </>
              ) : (
                <>
                  <Copy size={13} aria-hidden /> Copy agreement key
                </>
              )}
            </Button>
          </div>
          <span className="field-label">Signing key</span>
          <code className="recovery-code">{identity.signingPub}</code>
          <div className="form-actions">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => void copy("signing", identity.signingPub)}
            >
              {copied === "signing" ? (
                <>
                  <Check size={13} aria-hidden /> Copied
                </>
              ) : (
                <>
                  <Copy size={13} aria-hidden /> Copy signing key
                </>
              )}
            </Button>
          </div>
          <p className="setting-hint">
            Device <code>{identity.deviceId}</code> · keypair created{" "}
            {new Date(identity.createdAt).toLocaleDateString()}
          </p>
          {copyError ? (
            <p className="form-error" role="alert">
              {copyError}
            </p>
          ) : null}
        </>
      ) : (
        <p className="card-copy">
          {keyProblem ?? "Reading this device's keypair…"}
        </p>
      )}

      {status?.exists ? (
        <>
          <div className="form-actions">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={busy}
              onClick={() => void verifySecretKey()}
            >
              {busy ? "Checking…" : "Verify the Secret Key row"}
            </Button>
          </div>
          {verifyNote ? (
            <p className="recovery-state" role="status">
              <ShieldCheck size={14} aria-hidden /> {verifyNote}
            </p>
          ) : null}
          <p className="card-copy">
            <strong>Enrolment, first half.</strong> Given the other device's
            agreement public key (copy it from Settings → Account on that
            device), this mints the code to read aloud and the sealed account
            key for that device. On the other device, open Settings → Account,
            paste the three values below into <em>Join an account</em>, and it
            receives this account's key. The code is a credential: anyone who
            has it and the blob can open the account key.
          </p>
          <label className="field-label" htmlFor="account-device-key">
            Other device agreement key
          </label>
          <div className="input-shell">
            <input
              id="account-device-key"
              className="input is-mono"
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={deviceKey}
              placeholder="64 hex characters"
              onChange={(event) => setDeviceKey(event.target.value)}
            />
          </div>
          <div className="form-actions">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => void showEnrolment()}
            >
              {busy ? "Sealing…" : "Show enrolment code"}
            </Button>
          </div>

          {enrolment ? (
            <div className="recovery-preview">
              <span className="recovery-preview-label">
                Read this code aloud to the other device
              </span>
              <code className="recovery-code">{enrolment.code}</code>
              <span className="recovery-preview-label">
                Paste this sealed blob on that device
              </span>
              <code className="recovery-code">{enrolment.sealed}</code>
              <span className="recovery-preview-label">
                Sender agreement key (the other device needs it to compute the
                shared secret)
              </span>
              <code className="recovery-code">
                {enrolment.senderAgreementPub}
              </code>
              <p className="recovery-preview-warn">
                <ShieldAlert size={13} aria-hidden /> The code alone opens
                nothing, but the code plus this sealed blob is a credential:
                whoever holds both can receive this account's key. Read the code
                aloud, deliver the blob separately, and show each exactly once.
              </p>
              <div className="form-actions">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setEnrolment(null);
                    setDeviceKey("");
                  }}
                >
                  Done
                </Button>
              </div>
            </div>
          ) : null}
        </>
      ) : (
        <>
          <p className="card-copy">
            <strong>Create the account here</strong> if this is the first
            device. It returns the Secret Key once; write it down before closing
            the panel.
          </p>
          <div className="form-actions">
            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={busy}
              onClick={() => void create()}
            >
              {busy ? "Creating…" : "Create account"}
            </Button>
          </div>

          <div className="card-head">
            <h3 className="card-title">Join an account</h3>
          </div>
          <p className="card-copy">
            If another device already has the account, show it this device's
            agreement key above, then paste the three values it displays. The
            account key is sealed to this device's keypair; nothing here can
            open it for any other device.
          </p>
          <label className="field-label" htmlFor="account-join-code">
            Enrolment code
          </label>
          <div className="input-shell">
            <input
              id="account-join-code"
              className="input is-mono"
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={joinCode}
              placeholder="XXXX-XXXX-…"
              onChange={(event) => setJoinCode(event.target.value)}
            />
          </div>
          <label className="field-label" htmlFor="account-join-sealed">
            Sealed account key
          </label>
          <div className="input-shell">
            <textarea
              id="account-join-sealed"
              className="input is-mono textarea"
              rows={3}
              spellCheck={false}
              autoComplete="off"
              value={joinSealed}
              placeholder="the sealed blob, hex"
              onChange={(event) => setJoinSealed(event.target.value)}
            />
          </div>
          <label className="field-label" htmlFor="account-join-sender">
            Sender agreement key
          </label>
          <div className="input-shell">
            <input
              id="account-join-sender"
              className="input is-mono"
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={joinSender}
              placeholder="64 hex characters"
              onChange={(event) => setJoinSender(event.target.value)}
            />
          </div>
          <div className="form-actions">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => void join()}
            >
              {busy ? "Opening…" : "Join account"}
            </Button>
          </div>
        </>
      )}

      <div className="card-head">
        <h3 className="card-title">
          <Smartphone size={14} aria-hidden /> Devices
        </h3>
      </div>
      <p className="card-copy">
        Revoking withdraws a device's access to the sync service. It does not
        erase what that device already downloaded: a revoked device keeps every
        byte it pulled and the account key it holds. What it stops receiving is
        new changes. The account key is not rotated by this action, so a device
        that kept the key can still read ciphertext it obtains by other means.
      </p>
      {devices.length === 0 ? (
        <p className="card-copy">
          No devices are registered yet. The local mirror records this device's
          public keys; devices the sync service reports appear here once the
          client talks to it.
        </p>
      ) : (
        <ul className="device-list">
          {devices.map((device) => {
            const isLocal = identity?.deviceId === device.deviceId;
            const isRevoked = device.revokedAt != null;
            // Until this device's identity is known, no button is offered: the
            // one row that must never be revoked is this device itself.
            const canRevoke = identity != null && !isLocal && !isRevoked;
            return (
              <li
                key={device.deviceId}
                className={`device-row${isRevoked ? " is-revoked" : ""}`}
              >
                <div className="device-row-head">
                  <span className="device-row-name">{device.name}</span>
                  {isLocal ? (
                    <span className="device-badge is-local">This device</span>
                  ) : null}
                  {isRevoked ? (
                    <span className="device-badge is-revoked">
                      <Ban size={11} aria-hidden /> Revoked
                    </span>
                  ) : null}
                </div>
                <code className="device-row-id">{device.deviceId}</code>
                <span className="device-row-meta">
                  Added {new Date(device.createdAt).toLocaleDateString()} · last
                  seen {new Date(device.lastSeen).toLocaleString()}
                  {isRevoked
                    ? ` · revoked ${new Date(device.revokedAt as number).toLocaleString()}`
                    : ""}
                </span>
                {canRevoke ? (
                  confirming === device.deviceId ? (
                    <div className="device-confirm">
                      <p className="device-confirm-copy">
                        Stop accepting this device's signatures? It keeps the
                        vault data it already downloaded.
                      </p>
                      <div className="form-actions">
                        <Button
                          type="button"
                          variant="danger"
                          size="sm"
                          disabled={busy}
                          onClick={() => void revokeDevice(device)}
                        >
                          {busy ? "Revoking…" : "Confirm revoke"}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={busy}
                          onClick={() => setConfirming(null)}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="form-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() => {
                          setConfirming(device.deviceId);
                          setError(null);
                          setRevocation(null);
                        }}
                      >
                        Revoke
                      </Button>
                    </div>
                  )
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {revocation ? (
        <p className="device-notice" role="status">
          {revocation.serverRevoked ? (
            <>
              <ShieldCheck size={14} aria-hidden /> Device{" "}
              <code>{revocation.deviceId}</code> revoked. The sync service will
              refuse its signatures from now on; data it already downloaded
              stays on it and it will not receive new changes. The account key
              was not rotated.
            </>
          ) : (
            <>
              <ShieldAlert size={14} aria-hidden /> Device{" "}
              <code>{revocation.deviceId}</code> removed from this device's
              local mirror. No sync server is configured, so nothing was sent;
              that device's own copy of the vault is unchanged and nothing here
              can erase it.
            </>
          )}
        </p>
      ) : null}

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
