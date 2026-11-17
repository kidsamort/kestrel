import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Eye,
  EyeOff,
  FolderInput,
  FolderOpen,
  KeyRound,
  Lock,
  Printer,
  ScanFace,
  ShieldAlert,
  ShieldCheck,
  Wand2,
  Download,
} from "lucide-react";
import { api, errorText, hasCore } from "./api";
import {
  pickFolder,
  pickVaultFile,
  revealFolderPath,
  vault,
  vaultErrorCode,
  vaultErrorText,
  vaultFileName,
  vaultFilePath,
  type VaultLocation,
} from "./lib/api-vault";
import { recovery, type RecoveryKit } from "./lib/api-recovery";
import { durationLabel, strengthOf } from "./lib/format";
import { entropyFor } from "./lib/generator";
import type { HelloStatus, VaultState } from "./types";
import { Button } from "./ui/Button";
import { TextField } from "./ui/Input";
import { useNotify } from "./ui/Toast";
import RecoveryDoor from "./vault/RecoveryDoor";
import RecoveryPrint, { RecoveryCode } from "./vault/RecoveryPrint";
import "./styles/recovery.css";

/**
 * The gate has one shape per fact it can state:
 *
 * - no vault selected yet: name the file, put it in a folder, choose a password;
 * - a vault has just been created: show the one-time recovery code before the
 *   shell opens, with a way to skip it;
 * - a vault is selected but locked: the password door, its hint, and the file's
 *   name with a way to find it in Explorer;
 * - the remembered file is gone: say so, and offer another file or a new vault.
 *
 * The renderer never guesses a path and never creates over an existing file.
 * The core owns both decisions; this screen only reports what came back.
 */
type Screen =
  | "loading"
  | "create"
  | "recovery"
  | "locked"
  | "missing"
  | "unavailable";

/**
 * A long path keeps its beginning and its end: the drive says where, the last
 * segment says which folder. Clicking the path shows it whole.
 */
function middleEllipsis(path: string, max = 44): string {
  if (path.length <= max) return path;
  const head = Math.ceil((max - 1) * 0.4);
  const tail = max - 1 - head;
  return `${path.slice(0, head)}…${path.slice(path.length - tail)}`;
}

export default function Gate({
  state,
  lockedBy,
  onUnlocked,
  onPending,
}: {
  state: VaultState;
  lockedBy: "idle" | "manual" | null;
  onUnlocked: (next: VaultState) => void;
  /**
   * Told when the gate is holding the app back on purpose. The recovery step
   * runs after the vault is already unlocked, and the parent's unlock poll would
   * otherwise swap the shell in before the code can be read.
   */
  onPending?: (pending: boolean) => void;
}) {
  const notify = useNotify();
  const [screen, setScreen] = useState<Screen>("loading");
  const [location, setLocation] = useState<VaultLocation | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fileProblem, setFileProblem] = useState<string | null>(null);
  const [fileGone, setFileGone] = useState(false);
  const [returnScreen, setReturnScreen] = useState<"locked" | "missing" | null>(
    null,
  );

  // Create form.
  const [vaultName, setVaultName] = useState("personal");
  const [folder, setFolder] = useState("");
  const [hint, setHint] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [folderError, setFolderError] = useState<string | null>(null);
  /** The full path is shown when the person asks to see it. */
  const [pathExpanded, setPathExpanded] = useState(false);
  /** Typing a path is an escape hatch for UNC and network shares, not the norm. */
  const [pathEditing, setPathEditing] = useState(false);

  // Shared password fields.
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [reveal, setReveal] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [suggested, setSuggested] = useState(false);
  /** Where the last "Save as PDF" put the kit, so the person can find it. */
  const [pdfPath, setPdfPath] = useState<string | null>(null);
  const [pdfError, setPdfError] = useState<string | null>(null);
  /** Bits of a passphrase we generated ourselves, from the generator's own math. */
  const [suggestedBits, setSuggestedBits] = useState<number | null>(null);

  // The freshly created vault and the code that was minted for it. Both exist
  // only between "Create vault" and leaving this gate: the code is cleared
  // before the shell is handed the state, so nothing outside this step can
  // hold it.
  const [created, setCreated] = useState<VaultState | null>(null);
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [kitError, setKitError] = useState<string | null>(null);
  const [confirmSkip, setConfirmSkip] = useState(false);

  // Windows Hello and the recovery door — enrolment is answerable while locked.
  const [hello, setHello] = useState<HelloStatus | null>(null);
  const [helloBusy, setHelloBusy] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  // Missing-file screen: a path to try instead.

  const nameRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);
  const continueRef = useRef<HTMLButtonElement>(null);

  async function loadLocation() {
    setScreen("loading");
    setLoadError(null);
    setRecoveryOpen(false);
    if (!hasCore()) {
      setLoadError("This view is not running inside the Kestrel desktop app.");
      setScreen("unavailable");
      return;
    }
    let next: VaultLocation;
    try {
      next = await vault.location();
    } catch (failure) {
      setLoadError(errorText(failure));
      setScreen("unavailable");
      return;
    }
    setLocation(next);

    if (next.path === null) {
      setVaultName("personal");
      setFolder(next.defaultDir);
      setReturnScreen(null);
      setScreen("create");
      return;
    }

    try {
      // The remembered path is a claim, not proof: the file may have moved or
      // been deleted since the core read its config. Opening it is the only
      // honest way to tell the locked screen from the missing-file screen.
      const opened = await vault.openAt(next.path);
      if (!opened.locked) {
        onUnlocked(opened);
        return;
      }
      setFileProblem(null);
      setFileGone(false);
      setScreen("locked");
    } catch (failure) {
      setFileGone(vaultErrorCode(failure) === "not_found");
      setFileProblem(vaultErrorText(failure));
      setScreen("missing");
    }
  }

  useEffect(() => {
    void loadLocation();
    // The parent's callback is stable; the gate reads the location once per
    // mount and never re-opens a file on an ordinary re-render.
  }, []);

  // Enrolment state only: the core answers without a key, which is why this
  // works on a locked vault. A failure here must not break the password door,
  // so the button simply stays hidden.
  useEffect(() => {
    if (screen !== "locked" || !hasCore()) {
      setHello(null);
      return;
    }
    let live = true;
    api
      .helloStatus()
      .then((status) => {
        if (live) setHello(status);
      })
      .catch(() => {
        if (live) setHello(null);
      });
    return () => {
      live = false;
    };
  }, [screen]);

  // Moving between the three shapes is a fresh attempt: no password, no
  // half-typed error from the previous one.
  useEffect(() => {
    setPassword("");
    setConfirm("");
    setError(null);
    setPasswordError(null);
    setNameError(null);
    setFolderError(null);
    setTouched(false);
    setCapsLock(false);
  }, [screen]);

  useEffect(() => {
    if (screen === "create") nameRef.current?.focus();
    else if (screen === "locked") passwordRef.current?.focus();
    else if (screen === "recovery" && !confirmSkip) continueRef.current?.focus();
  }, [screen, confirmSkip]);

  // A passphrase we generated is estimated from the word list it came from, not
  // from the characters in it: "amber-comet-…" is not 294 bits of randomness.
  const strength =
    suggested && suggestedBits !== null
      ? {
          bits: suggestedBits,
          level: suggestedBits >= 90 ? 4 : suggestedBits >= 60 ? 3 : suggestedBits >= 40 ? 2 : 1,
          label: "Estimate for this passphrase",
        }
      : strengthOf(password);
  const longEnough = password.length >= 10;
  const matches = password === confirm;
  const mismatch = touched && confirm.length > 0 && !matches;
  const tooShort = touched && password.length > 0 && !longEnough;
  const storedHint = screen === "locked" ? location?.hint?.trim() || null : null;
  const fileName =
    screen === "locked" && location?.path
      ? vaultFileName(location.path)
      : null;

  function startCreate(from: "locked" | "missing" | null) {
    setReturnScreen(from);
    setVaultName("personal");
    setFolder(location?.defaultDir ?? "");
    setHint("");
    setRecoveryOpen(false);
    setScreen("create");
  }

  function openRecovery() {
    setError(null);
    setPassword("");
    setRecoveryOpen(true);
  }

  async function showFolder() {
    const target = folder.trim();
    if (!target) return;
    try {
      await revealFolderPath(target);
      setFolderError(null);
    } catch {
      // The only honest thing to say: this folder is not there.
      setFolderError("That folder is not there any more. Choose another one.");
    }
  }

  async function chooseVaultFile() {
    if (busy) return;
    setBusy(true);
    setFileProblem(null);
    try {
      const picked = await pickVaultFile();
      // `null` is Cancel: the screen stays exactly as it was.
      if (!picked) return;
      const opened = await vault.openAt(picked);
      // The row below the field names the file; switching files must rename it,
      // or the screen would claim the old vault is open.
      setLocation(await vault.location().catch(() => null));
      if (!opened.locked) {
        onUnlocked(opened);
      } else {
        setScreen("locked");
      }
    } catch (failure) {
      setFileGone(vaultErrorCode(failure) === "not_found");
      setFileProblem(vaultErrorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function chooseFolder() {
    if (busy) return;
    setBusy(true);
    setFolderError(null);
    try {
      const chosen = await pickFolder(folder.trim() ? folder.trim() : null);
      // `null` is a cancel: leave the current folder exactly as it was.
      if (chosen) {
        setFolder(chosen);
        setError(null);
      }
    } catch (failure) {
      setFolderError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function saveKitPdf() {
    if (busy || !kit || !created) return;
    setBusy(true);
    setPdfError(null);
    try {
      const path = await recovery.savePdf({
        vaultName: created.vaultName,
        code: kit.code,
        createdAt: kit.createdAt,
      });
      // `null` is the person closing the save dialog: nothing was written.
      setPdfPath(path);
    } catch (failure) {
      setPdfError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function suggestPassword() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const options = {
        length: 24,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        avoidAmbiguous: true,
        passphrase: true,
        words: 8,
        separator: "-",
      };
      const generated = await api.generate(options);
      // Both fields, and revealed: a master password the user cannot read is a
      // master password they cannot write down, and there is no recovery from
      // forgetting it.
      setPassword(generated);
      setConfirm(generated);
      setReveal(true);
      setTouched(false);
      setPasswordError(null);
      setSuggested(true);
      setSuggestedBits(entropyFor(options));
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  async function submitCreate(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setTouched(true);
    setError(null);
    setNameError(null);
    setFolderError(null);
    setPasswordError(null);

    const name = vaultName.trim();
    const dir = folder.trim();
    if (!dir) {
      setFolderError("Choose the folder that will hold the vault file.");
      folderRef.current?.focus();
      return;
    }
    if (!name) {
      setNameError("Give the vault a name.");
      nameRef.current?.focus();
      return;
    }
    const path = vaultFilePath(dir, name);
    if (!path) {
      setNameError('Use a file name without \\ / : * ? " < > |.');
      nameRef.current?.focus();
      nameRef.current?.select();
      return;
    }
    if (!longEnough) {
      setPasswordError("A master password needs at least 10 characters.");
      passwordRef.current?.focus();
      return;
    }
    if (!matches) {
      setPasswordError("The two passwords do not match yet.");
      confirmRef.current?.focus();
      return;
    }

    setBusy(true);
    try {
      const next = await vault.createAt(
        path,
        password,
        hint.trim() ? hint.trim() : null,
      );
      setPassword("");
      setConfirm("");
      setHint("");

      // The code is minted exactly once, here, because this step is the only
      // place it is shown. `createAt` has already made the vault live, so the
      // command has the session it needs. A failure is not fatal: the vault is
      // usable without a code, and the step still offers Continue.
      let minted: RecoveryKit | null = null;
      let mintProblem: string | null = null;
      try {
        minted = await recovery.create();
      } catch (failure) {
        mintProblem = errorText(failure);
      }

      setCreated(next);
      setKit(minted);
      setKitError(mintProblem);
      setConfirmSkip(false);
      onPending?.(true);
      setScreen("recovery");
    } catch (failure) {
      const code = vaultErrorCode(failure);
      if (code === "already_exists") {
        setNameError(vaultErrorText(failure));
        nameRef.current?.focus();
        nameRef.current?.select();
      } else if (code === "weak_password") {
        setPasswordError(vaultErrorText(failure));
        passwordRef.current?.focus();
        passwordRef.current?.select();
      } else if (code === "invalid_path") {
        setFolderError(vaultErrorText(failure));
        folderRef.current?.focus();
      } else {
        setError(vaultErrorText(failure));
      }
    } finally {
      setBusy(false);
    }
  }

  function leaveRecovery() {
    const next = created;
    // The code leaves with the screen: it is not part of the shell's state and
    // must not outlive this step in memory.
    setKit(null);
    setKitError(null);
    setConfirmSkip(false);
    setCreated(null);
    // The hold is released before the handoff, so the poll and the handoff agree.
    onPending?.(false);
    if (next) onUnlocked(next);
  }

  async function submitUnlock(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError(null);
    if (!password) {
      setError("Enter the master password to unlock.");
      passwordRef.current?.focus();
      return;
    }
    setBusy(true);
    try {
      const next = await api.unlock(password);
      setPassword("");
      setConfirm("");
      onUnlocked(next);
    } catch (failure) {
      setError(errorText(failure));
      passwordRef.current?.focus();
      passwordRef.current?.select();
    } finally {
      setBusy(false);
    }
  }

  async function unlockWithHello() {
    if (busy || helloBusy) return;
    setError(null);
    setHelloBusy(true);
    try {
      const next = await api.helloUnlock();
      setPassword("");
      setConfirm("");
      onUnlocked(next);
    } catch (failure) {
      // Cancelling the prompt and a missing TPM both land here with the core's
      // own words; never replace them with a reassuring generic. The toast says
      // the action failed, the form keeps the detail next to the door.
      const detail = errorText(failure);
      notify("Could not unlock with Windows Hello", {
        detail,
        tone: "danger",
      });
      setError(detail);
    } finally {
      setHelloBusy(false);
    }
  }

  async function revealFolder() {
    try {
      await vault.revealFolder();
    } catch (failure) {
      notify("Could not show the vault folder", {
        detail: errorText(failure),
        tone: "danger",
      });
    }
  }

  const trackCaps = (event: React.KeyboardEvent<HTMLInputElement>) => {
    setCapsLock(event.getModifierState("CapsLock"));
  };

  return (
    <main className="gate">
      <section className="gate-aside" aria-hidden="true">
        <div className="gate-intro">
          <span className="eyebrow">Local vault · this device only</span>
          <h1 className="display">
            {screen === "create" ? (
              <>
                One password,
                <br />
                kept nowhere.
              </>
            ) : screen === "recovery" ? (
              <>
                The vault is
                <br />
                open.
              </>
            ) : screen === "missing" ? (
              <>
                The file is
                <br />
                not here.
              </>
            ) : screen === "unavailable" ? (
              <>
                The gate
                <br />
                cannot read.
              </>
            ) : (
              <>
                The vault is
                <br />
                sealed.
              </>
            )}
          </h1>
          <p className="gate-intro-copy">
            {screen === "create"
              ? "Kestrel derives the vault key from this password on this machine. Nothing is sent, and nothing can recover it for you."
              : screen === "recovery"
                ? "The vault exists and is unlocked. The code on this screen is the only copy of the way back in."
                : screen === "missing"
                ? "Kestrel remembers the last file you opened and will not silently replace it. Point it at the file again, or make a new vault somewhere else."
                : screen === "unavailable"
                  ? "The interface is only a view; the core owns the path. Until it answers, no vault is opened and no file is touched."
                  : "Kestrel holds the key in memory only. Enter the master password to open it again."}
          </p>
        </div>

        <dl className="gate-facts">
          <div>
            <dt>Key derivation</dt>
            <dd>Argon2id · 64 MiB · t=3</dd>
          </div>
          <div>
            <dt>Object cipher</dt>
            <dd>XChaCha20-Poly1305</dd>
          </div>
          <div>
            <dt>Storage</dt>
            <dd>SQLite, ciphertext rows</dd>
          </div>
          <div>
            <dt>Network</dt>
            <dd>None. The renderer has no keys.</dd>
          </div>
        </dl>

        <p className="gate-aside-foot">
          <ShieldCheck size={13} aria-hidden />
          Auto-lock and clipboard wiping run in the Rust core, not here.
        </p>
      </section>

      <section className="gate-door">
        {screen === "loading" ? (
          <div className="gate-form" role="status">
            <div className="gate-heading">
              <span className="eyebrow">Vault</span>
              <h2 className="display-sm">Reading the vault location…</h2>
              <p className="gate-sub">
                The gate asks the core which file it remembers. It does not
                guess, and it does not create one.
              </p>
            </div>
          </div>
        ) : null}

        {screen === "unavailable" ? (
          <form
            className="gate-form"
            onSubmit={(event) => {
              event.preventDefault();
              void loadLocation();
            }}
          >
            <div className="gate-heading">
              <span className="eyebrow">Vault</span>
              <h2 className="display-sm">
                Kestrel cannot read the vault location.
              </h2>
              <p className="gate-sub">
                The gate will not guess where a vault lives, so nothing was
                opened and nothing was created.
              </p>
            </div>
            <p className="form-error" role="alert">
              {loadError ?? "The core did not answer."}
            </p>
            <Button type="submit" variant="primary" size="lg" block>
              Try again
            </Button>
          </form>
        ) : null}

        {screen === "create" ? (
          <form className="gate-form" onSubmit={submitCreate} noValidate>
            <div className="gate-heading">
              <span className="eyebrow">First run</span>
              <h2 className="display-sm">Create the vault.</h2>
              <p className="gate-sub">
                Name the file, choose where it lives, and use a password you can
                type from memory.
              </p>
            </div>

            <TextField
              ref={nameRef}
              label="Vault name"
              value={vaultName}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setVaultName(event.target.value);
                setNameError(null);
                setError(null);
              }}
              error={nameError}
              hint={`Saved as ${vaultName.trim() || "personal"}${
                /\.[^.\\/]+$/.test(vaultName.trim()) ? "" : ".db"
              }`}
            />

            {/* The folder is chosen, not typed: a path typed by hand is a path
                with a typo in it, and the person never sees the tree. The full
                path stays in the title for the case where it is truncated. */}
            <div className="gate-field">
              <span className="field-label">Folder</span>
              {pathEditing ? (
                <input
                  className="input is-mono gate-folder-input"
                  value={folder}
                  spellCheck={false}
                  autoComplete="off"
                  autoFocus
                  onChange={(event) => {
                    setFolder(event.target.value);
                    setFolderError(null);
                  }}
                  onBlur={() => setPathEditing(false)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === "Escape") {
                      setPathEditing(false);
                    }
                  }}
                />
              ) : (
                <div className="gate-folder">
                  {/* The path gets the whole line: three links beside it in a
                      348-pixel column pushed the tail — the part that says which
                      folder — off the end. */}
                  <button
                    type="button"
                    className={`gate-folder-path${pathExpanded ? " is-expanded" : ""}`}
                    title={folder || "No folder chosen"}
                    aria-expanded={pathExpanded}
                    onClick={() => setPathExpanded((open) => !open)}
                  >
                    {!folder
                      ? "No folder chosen"
                      : pathExpanded
                        ? folder
                        : middleEllipsis(folder, 46)}
                  </button>
                  <div className="gate-folder-actions">
                    <button
                      type="button"
                      className="gate-link"
                      disabled={busy}
                      onClick={() => void showFolder()}
                    >
                      <FolderOpen size={13} strokeWidth={1.5} aria-hidden />
                      Show in folder
                    </button>
                    <span className="gate-alternatives-sep" aria-hidden>
                      ·
                    </span>
                    <button
                      type="button"
                      className="gate-link"
                      disabled={busy}
                      onClick={() => void chooseFolder()}
                    >
                      Choose folder…
                    </button>
                    <span className="gate-alternatives-sep" aria-hidden>
                      ·
                    </span>
                    <button
                      type="button"
                      className="gate-link"
                      disabled={busy}
                      onClick={() => setPathEditing(true)}
                    >
                      Edit path
                    </button>
                  </div>
                </div>
              )}
              {folderError ? (
                <p className="form-error" role="alert">
                  {folderError}
                </p>
              ) : null}
            </div>

            <TextField
              ref={passwordRef}
              label="New master password"
              type={reveal ? "text" : "password"}
              value={password}
              autoComplete="new-password"
              spellCheck={false}
              onChange={(event) => {
                setPassword(event.target.value);
                setSuggested(false);
                setSuggestedBits(null);
                setPasswordError(null);
                setError(null);
              }}
              onKeyDown={trackCaps}
              onKeyUp={trackCaps}
              leading={<KeyRound size={14} strokeWidth={1.5} aria-hidden />}
              error={
                passwordError ?? (tooShort ? "At least 10 characters." : null)
              }
              trailing={
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => setReveal((value) => !value)}
                  aria-label={reveal ? "Hide password" : "Show password"}
                  aria-pressed={reveal}
                >
                  {reveal ? (
                    <EyeOff size={14} strokeWidth={1.5} aria-hidden />
                  ) : (
                    <Eye size={14} strokeWidth={1.5} aria-hidden />
                  )}
                </button>
              }
            />

            <div className="strength" aria-live="polite">
              <div className="strength-bars" aria-hidden="true">
                {[1, 2, 3, 4].map((step) => (
                  <span
                    key={step}
                    className={
                      strength.level >= step
                        ? `strength-bar on level-${strength.level}`
                        : "strength-bar"
                    }
                  />
                ))}
              </div>
              <span className="strength-label">
                {password
                  ? `${strength.label} · ≈${strength.bits} bits`
                  : "At least 10 characters"}
              </span>
              <button
                type="button"
                className="gate-link strength-suggest"
                disabled={busy}
                onClick={() => void suggestPassword()}
              >
                <Wand2 size={12} strokeWidth={1.5} aria-hidden />
                Generate a passphrase
              </button>
            </div>

            {suggested ? (
              <p className="gate-note">
                Write it down before you continue. Nothing can recover this
                password, and the passphrase is the only way in.
              </p>
            ) : null}

            <TextField
              ref={confirmRef}
              label="Confirm master password"
              type={reveal ? "text" : "password"}
              value={confirm}
              autoComplete="new-password"
              spellCheck={false}
              onChange={(event) => {
                setConfirm(event.target.value);
                setPasswordError(null);
                setError(null);
              }}
              onKeyDown={trackCaps}
              onKeyUp={trackCaps}
              onBlur={() => setTouched(true)}
              error={mismatch ? "These do not match yet." : null}
              leading={<Lock size={14} strokeWidth={1.5} aria-hidden />}
            />

            <TextField
              label="Password hint (optional)"
              value={hint}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setHint(event.target.value);
                setError(null);
              }}
              hint="Optional. Shown on the lock screen if you forget. Do not put the password itself here."
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
              disabled={busy}
            >
              {busy ? "Creating vault…" : "Create vault"}
            </Button>

            <p className="gate-note">
              If you forget the password and have no recovery code, nobody can
              open this vault — including us.
            </p>

            {returnScreen ? (
              <div className="gate-alternatives">
                <button
                  type="button"
                  className="gate-link"
                  disabled={busy}
                  onClick={() => setScreen(returnScreen)}
                >
                  Use the existing vault instead
                </button>
              </div>
            ) : null}
          </form>
        ) : null}

        {screen === "recovery" ? (
          <div className="gate-form recovery-door">
            <div className="gate-heading">
              <span className="eyebrow">CREATED</span>
              <h2 className="display-sm">Keep a way back in.</h2>
              <p className="gate-sub">
                This code opens this vault on its own, without the master
                password. It is shown <strong>once</strong>: Kestrel does not
                store it and cannot show it again.
              </p>
            </div>

            {kit ? (
              <>
                <div className="recovery-preview">
                  <span className="recovery-preview-label">
                    Recovery code · {kit.vaultName}
                  </span>
                  <RecoveryCode code={kit.code} />
                  <p className="recovery-preview-warn">
                    <ShieldAlert size={13} aria-hidden /> Print the sheet or
                    write the code down now. Anyone who reads it can open this
                    vault.
                  </p>
                </div>
                <div className="gate-kit-actions">
                <Button
                  type="button"
                  variant="secondary"
                  size="lg"
                  block
                  leading={<Printer size={15} aria-hidden />}
                  onClick={() => window.print()}
                >
                  Print kit
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  size="lg"
                  block
                  disabled={busy}
                  leading={<Download size={15} aria-hidden />}
                  onClick={() => void saveKitPdf()}
                >
                  {busy ? "Saving…" : "Save as PDF"}
                </Button>
                </div>
                {pdfPath ? (
                  <p className="gate-note gate-saved">
                    Saved to <code>{pdfPath}</code>
                  </p>
                ) : null}
                {pdfError ? (
                  <p className="form-error" role="alert">
                    {pdfError}
                  </p>
                ) : null}
              </>
            ) : null}

            {kitError ? (
              <>
                <p className="form-error" role="alert">
                  {kitError}
                </p>
                <p className="gate-note">
                  The vault itself was created and is ready to use. You can make
                  a recovery code later in Settings → Recovery.
                </p>
              </>
            ) : null}

            {confirmSkip ? (
              <div className="recovery-confirm">
                <p>
                  Without a code, a forgotten password means this vault cannot
                  be opened — by anyone.
                </p>
                <Button
                  type="button"
                  variant="danger"
                  size="lg"
                  block
                  onClick={leaveRecovery}
                >
                  Skip anyway
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="lg"
                  block
                  onClick={() => setConfirmSkip(false)}
                >
                  Back
                </Button>
              </div>
            ) : (
              <>
                <Button
                  ref={continueRef}
                  type="button"
                  variant="primary"
                  size="lg"
                  block
                  onClick={leaveRecovery}
                >
                  Continue
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  block
                  onClick={() => setConfirmSkip(true)}
                >
                  Skip for now
                </Button>
              </>
            )}

            {kit ? <RecoveryPrint kit={kit} /> : null}
          </div>
        ) : null}

        {screen === "locked" && recoveryOpen ? (
          <RecoveryDoor
            onUnlocked={onUnlocked}
            onClose={() => setRecoveryOpen(false)}
          />
        ) : null}

        {screen === "locked" && !recoveryOpen ? (
          <form className="gate-form" onSubmit={submitUnlock} noValidate>
            <div className="gate-heading">
              <span className="eyebrow">Locked</span>
              <h2 className="display-sm">Welcome back.</h2>
              <p className="gate-sub">
                {lockedBy === "idle"
                  ? "The vault locked itself after inactivity. Your work is saved."
                  : `Encrypted at rest · auto-lock ${durationLabel(
                      state.autolockSeconds,
                    )}`}
              </p>
            </div>

            {storedHint ? (
              <div className="gate-hint" role="note">
                <span className="gate-hint-label">Hint:</span>
                <p className="gate-hint-text">{storedHint}</p>
              </div>
            ) : null}

            <TextField
              ref={passwordRef}
              label="Master password"
              type={reveal ? "text" : "password"}
              value={password}
              autoComplete="current-password"
              spellCheck={false}
              onChange={(event) => {
                setPassword(event.target.value);
                setError(null);
              }}
              onKeyDown={trackCaps}
              onKeyUp={trackCaps}
              leading={<KeyRound size={14} strokeWidth={1.5} aria-hidden />}
              hint={capsLock ? "Caps Lock is on." : undefined}
              trailing={
                <button
                  type="button"
                  className="icon-btn"
                  onClick={() => setReveal((value) => !value)}
                  aria-label={reveal ? "Hide password" : "Show password"}
                  aria-pressed={reveal}
                >
                  {reveal ? (
                    <EyeOff size={14} strokeWidth={1.5} aria-hidden />
                  ) : (
                    <Eye size={14} strokeWidth={1.5} aria-hidden />
                  )}
                </button>
              }
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
              disabled={busy || helloBusy}
            >
              {busy ? "Unlocking…" : "Unlock vault"}
            </Button>

            {hello?.enrolled && hello.available ? (
              <Button
                type="button"
                variant="secondary"
                size="lg"
                block
                disabled={busy || helloBusy}
                leading={<ScanFace size={15} aria-hidden />}
                onClick={() => void unlockWithHello()}
                title={
                  hello.label
                    ? `Uses ${hello.label}. The master password always works.`
                    : undefined
                }
              >
                {helloBusy
                  ? "Waiting for Windows Hello…"
                  : "Unlock with Windows Hello"}
              </Button>
            ) : null}

            {hello?.enrolled && !hello.available ? (
              <p className="form-error" role="status">
                Windows Hello unlock is enrolled but unavailable on this machine
                {hello.detail ? `: ${hello.detail}` : "."}
              </p>
            ) : null}

            {/* Two ways out of the password field, on one line and on the same
                axis. Both are links: neither is the primary action, and a pair
                of full-width ghost buttons under a full-width primary reads as
                three competing calls to action. */}
            <div className="gate-alternatives">
              <button
                type="button"
                className="gate-link"
                disabled={busy || helloBusy}
                onClick={openRecovery}
              >
                <ShieldCheck size={13} strokeWidth={1.5} aria-hidden />
                I have a recovery code
              </button>
              <span className="gate-alternatives-sep" aria-hidden>
                ·
              </span>
              <button
                type="button"
                className="gate-link"
                disabled={busy || helloBusy}
                onClick={() => startCreate("locked")}
              >
                Create a new vault instead
              </button>
            </div>

            {fileName ? (
              <div className="gate-file">
                <span className="gate-file-name" title={location?.path ?? ""}>
                  {fileName}
                </span>
                <div className="gate-file-actions">
                  <button
                    type="button"
                    className="gate-link"
                    disabled={busy}
                    onClick={() => void chooseVaultFile()}
                  >
                    <FolderInput size={13} strokeWidth={1.5} aria-hidden />
                    Open another…
                  </button>
                  <span className="gate-alternatives-sep" aria-hidden>
                    ·
                  </span>
                  <button
                    type="button"
                    className="gate-link"
                    onClick={() => void revealFolder()}
                  >
                    <FolderOpen size={13} strokeWidth={1.5} aria-hidden />
                    Show in folder
                  </button>
                </div>
              </div>
            ) : null}
          </form>
        ) : null}

        {screen === "missing" ? (
          <div className="gate-form">
            <div className="gate-heading">
              <span className="eyebrow">Missing file</span>
              <h2 className="display-sm">
                {fileGone
                  ? "This file is not here any more."
                  : "The vault file could not be opened."}
              </h2>
              <p className="gate-sub">
                Kestrel did not create anything in its place. The old file may
                have been moved, renamed or deleted; the vault itself is not
                changed by pointing Kestrel elsewhere.
              </p>
            </div>

            <div className="gate-problem">
              <span className="gate-problem-label">Last known path</span>
              <code className="gate-problem-path">
                {location?.path ?? "No path is remembered."}
              </code>
            </div>

            {/* Two ways forward, equal width: open the file you moved, or start
                a new vault. The file is the expected action, so it is primary. */}
            <div className="gate-kit-actions">
              <Button
                type="button"
                variant="primary"
                size="lg"
                block
                disabled={busy}
                onClick={() => void chooseVaultFile()}
              >
                {busy ? "Opening…" : "Choose a vault file…"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                size="lg"
                block
                disabled={busy}
                onClick={() => startCreate("missing")}
              >
                Create a new vault
              </Button>
            </div>

            {fileProblem && !fileGone ? (
              <p className="form-error" role="alert">
                {fileProblem}
              </p>
            ) : null}

          </div>
        ) : null}
      </section>
    </main>
  );
}
