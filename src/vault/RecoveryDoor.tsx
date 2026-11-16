/**
 * The recovery-code door of the unlock gate: enter a printed code, then a new
 * master password, then print the replacement code.
 *
 * The core does the cryptography and the enforcement. This component owns only
 * the order of the three screens and the honesty of the copy:
 *
 * 1. the printed code is single use and its warning is shown *before* it is
 *    used, not after;
 * 2. the old master password is unknown by definition, so the only way forward
 *    is a new one — the core refuses every read until it exists;
 * 3. the replacement code is shown exactly once, right here.
 *
 * The code lives in component state for the minutes this component is on
 * screen. It is never written to storage, never passed to a toast, and never
 * echoed in an error.
 */
import { useState, type FormEvent } from "react";
import { KeyRound, Printer, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, errorText } from "../api";
import { recovery, type RecoveryCompletion, type RecoveryKit } from "../lib/api-recovery";
import type { VaultState } from "../types";
import { Button } from "../ui/Button";
import { TextField } from "../ui/Input";
import "../styles/recovery.css";
import RecoveryPrint, { RecoveryCode } from "./RecoveryPrint";

type Step = "code" | "password" | "finished";

export default function RecoveryDoor({
  onUnlocked,
  onClose,
}: {
  /** Called with the unlocked state once the new password is live. */
  onUnlocked: (state: VaultState) => void;
  /** Called when the user backs out; the core is locked before this runs. */
  onClose: () => void;
}) {
  const [step, setStep] = useState<Step>("code");
  const [code, setCode] = useState("");
  const [vaultName, setVaultName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [completion, setCompletion] = useState<RecoveryCompletion | null>(null);

  async function finish(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      // The rotated key only becomes a session here, so the shell cannot
      // navigate away from the code before the user has seen it.
      const next = await recovery.finish();
      onUnlocked(next);
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Read the code off a kit this app saved. The PDF carries the code as literal
   * text, so a 53-character code is not the only way in; a scan or a photo still
   * has to be typed, and the copy says so.
   */
  async function readKit() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const found = await recovery.readKit();
      // `null` is the person closing the file dialog.
      if (found) setCode(found);
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (!code.trim()) {
      setError("Enter the recovery code from the printed sheet.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const opened = await recovery.unlock(code);
      // The key is unwrapped and waiting; the code is not needed again and is
      // dropped here rather than kept in state for the rest of the flow.
      setCode("");
      setVaultName(opened.vaultName);
      setStep("password");
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError(null);
    if (password.length < 10) {
      setError("A master password needs at least 10 characters.");
      return;
    }
    if (password !== confirm) {
      setError("The two passwords do not match yet.");
      return;
    }
    setBusy(true);
    try {
      const done = await recovery.complete(password);
      setPassword("");
      setConfirm("");
      setCompletion(done);
      setStep("finished");
    } catch (failure) {
      // The pending key survives a failed rotation, so retyping is enough.
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (busy) return;
    setBusy(true);
    try {
      // Drops the unwrapped key with the session slot; the printed code was not
      // consumed, so the user can come back to this screen and try again.
      await api.lock();
    } catch {
      // Locking cannot fail in a way the user can act on; the door closes
      // regardless and the next attempt re-reads the core's state.
    } finally {
      setBusy(false);
      setCode("");
      setPassword("");
      setConfirm("");
      onClose();
    }
  }

  const kit: RecoveryKit | null = completion?.kit ?? null;

  if (step === "finished" && completion) {
    return (
      <form className="gate-form recovery-door" onSubmit={finish}>
        <div className="gate-heading">
          <span className="eyebrow">Recovery · step 3 of 3</span>
          <h2 className="display-sm">This is your new code.</h2>
          <p className="gate-sub">
            {kit
              ? `The code that opened ${completion.vaultName || "this vault"} has been destroyed, exactly as planned. Print this sheet now: it is the only time this code is shown, and it is the only copy.`
              : `The new master password is live. The replacement recovery code could not be stored, so create a new kit in Settings → Recovery once you are inside.`}
          </p>
        </div>

        {kit ? (
          <>
            <div className="recovery-preview">
              <span className="recovery-preview-label">
                New recovery code · {kit.vaultName}
              </span>
              <RecoveryCode code={kit.code} />
              <p className="recovery-preview-warn">
                <ShieldAlert size={13} aria-hidden /> Single use again: using it
                replaces it. Store the printed sheet offline, away from this
                computer.
              </p>
            </div>
            <Button
              type="button"
              variant="secondary"
              size="lg"
              block
              leading={<Printer size={15} aria-hidden />}
              onClick={() => window.print()}
            >
              Print the kit
            </Button>
          </>
        ) : null}

        <Button type="submit" variant="primary" size="lg" block disabled={busy}>
          {busy ? "Opening…" : "I have saved the code — open the vault"}
        </Button>
        {/* The unwrapped key ages out on the auto-lock clock. If that happens
            while this sheet is on screen, every action below fails — so leave
            a way back instead of a form that can only be escaped by reloading. */}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          block
          disabled={busy}
          onClick={() => onClose()}
        >
          Back to unlock
        </Button>

        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}

        {kit ? <RecoveryPrint kit={kit} /> : null}
      </form>
    );
  }

  if (step === "password") {
    return (
      <form className="gate-form recovery-door" onSubmit={submitPassword} noValidate>
        <div className="gate-heading">
          <span className="eyebrow">Recovery · step 2 of 3</span>
          <h2 className="display-sm">Set a new master password.</h2>
          <p className="gate-sub">
            The code opened {vaultName || "the vault"}. Its master password is
            unknown by definition, so nothing can be read until a new one exists.
            Every item, version, attachment and passkey is re-encrypted under it.
          </p>
        </div>

        <TextField
          label="New master password"
          type="password"
          value={password}
          autoComplete="new-password"
          spellCheck={false}
          autoFocus
          onChange={(event) => {
            setPassword(event.target.value);
            setError(null);
          }}
          leading={<KeyRound size={14} strokeWidth={1.5} aria-hidden />}
          hint="At least 10 characters. Argon2id re-derives the key from it."
        />
        <TextField
          label="Confirm master password"
          type="password"
          value={confirm}
          autoComplete="new-password"
          spellCheck={false}
          onChange={(event) => {
            setConfirm(event.target.value);
            setError(null);
          }}
        />

        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}

        <Button
          type="submit"
          variant="primary"
          size="lg"
          block
          disabled={busy || !password || !confirm}
        >
          {busy ? "Re-encrypting every item…" : "Set password and open"}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          block
          disabled={busy}
          onClick={() => void cancel()}
        >
          Cancel and lock
        </Button>
      </form>
    );
  }

  return (
    <form className="gate-form recovery-door" onSubmit={submitCode} noValidate>
      <div className="gate-heading">
        <span className="eyebrow">Recovery · step 1 of 3</span>
        <h2 className="display-sm">I have a recovery code.</h2>
        <p className="gate-sub">
          Type it from the printed sheet. Lower case and dashes are fine.
        </p>
      </div>

      <div className="recovery-warning" role="note">
        <ShieldAlert size={15} aria-hidden />
        <p>
          The printed code is <strong>single use</strong>. It opens this vault
          once, then asks for a new master password and shows a new code to
          print. The code you are about to enter stops working at that point, so
          have the sheet with you before you start.
        </p>
      </div>

      <TextField
        label="Recovery code"
        value={code}
        autoComplete="off"
        spellCheck={false}
        autoFocus
        placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-C"
        onChange={(event) => {
          setCode(event.target.value);
          setError(null);
        }}
        leading={<ShieldCheck size={14} strokeWidth={1.5} aria-hidden />}
        hint="52 characters in 13 groups, plus a checksum character."
      />

      <button
        type="button"
        className="gate-link"
        disabled={busy}
        onClick={() => void readKit()}
      >
        Read it from a saved kit…
      </button>

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      <Button
        type="submit"
        variant="primary"
        size="lg"
        block
        disabled={busy || !code.trim()}
      >
        {busy ? "Opening with the code…" : "Open with the code"}
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        block
        disabled={busy}
        onClick={() => void cancel()}
      >
        Use the master password instead
      </Button>
      <p className="gate-note">
        A mistyped code is refused by its checksum before any key derivation
        runs, and leaves the vault exactly as it was.
      </p>
    </form>
  );
}
