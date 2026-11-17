/**
 * Settings → Passkeys. Reports the HKCU CLSID registration, the DLL Windows
 * will load, the pipe the plugin uses, and what Windows says about the plugin
 * authenticator. The register/unregister pair are the only registry writes in
 * the product and they are explicit presses.
 *
 * Props: none. The card reads its own state so it stays correct when opened
 * before or after a vault unlock.
 *
 * Honest limits, repeated on screen: this build registers the provider and
 * serves real CTAP2 over a user-only pipe, but it does not perform a
 * PIN/biometric user-verification gesture, does not verify Windows' per-request
 * signature, and has not completed a browser ceremony in an unsigned build.
 */
import { useCallback, useEffect, useState } from "react";
import { Fingerprint, ShieldCheck, ShieldOff } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import { passkeys, type PasskeyStatus } from "../../lib/api-passkeys";
import { Button } from "../../ui/Button";
import "../../styles/passkeys.css";

function hresult(value: number | null): string {
  if (value === null) return "—";
  return `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
}

function registeredWithWindows(status: PasskeyStatus | null): boolean {
  // 0x8009000F is NTE_EXISTS: the authenticator is already there, which is the
  // outcome we want. 0 is S_OK on the first add.
  const code = status?.windowsHresult;
  return code === 0 || code === -2146893809;
}

function windowsLabel(status: PasskeyStatus): string {
  if (status.windowsError) return "Unavailable";
  if (status.windowsState === 1) return "Enabled";
  if (status.windowsState === 0) return "Disabled";
  return "Not added";
}

export default function PasskeysCard() {
  const [status, setStatus] = useState<PasskeyStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"register" | "unregister" | null>(null);

  const load = useCallback(() => {
    passkeys.status().then(
      (value) => {
        setStatus(value);
        setError(null);
      },
      (reason) => setError(errorText(reason)),
    );
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: "register" | "unregister") => {
    setBusy(action);
    try {
      const value =
        action === "register"
          ? await passkeys.register()
          : await passkeys.unregister();
      setStatus(value);
      setError(value.error);
    } catch (reason) {
      setError(errorText(reason));
      load();
    } finally {
      setBusy(null);
    }
  };

  const registered = status?.registered ?? false;
  useSettingsStatus(
    "passkeys",
    status
      ? {
          tone: registered ? "on" : "danger",
          label: registered ? "Registered" : "Not registered",
        }
      : null,
  );
  const dllPresent = status?.dllPresent ?? false;
  const stateLabel = status ? windowsLabel(status) : "Checking…";

  return (
    <section className="card passkeys-card" aria-labelledby="passkeys-title">
      <div className="card-head">
        <h2 className="card-title" id="passkeys-title">
          <Fingerprint size={15} aria-hidden /> Passkeys
        </h2>
        <span
          className={`passkeys-state ${registered ? "is-on" : "is-off"}`}
          aria-live="polite"
        >
          {status === null ? "Checking…" : registered ? "Registered" : "Not registered"}
        </span>
      </div>

      <p className="card-copy">
        Kestrel can serve passkeys through the Windows WebAuthn plugin
        interface. The plugin DLL holds no vault code: it forwards CTAP2 to this
        process, the core opens the sealed key for one assertion, and only the
        signed answer crosses the pipe.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>CLSID</span>
          <span className="setting-hint">
            Written under <code>HKCU\Software\Classes\CLSID</code>; never HKLM,
            never at install time.
          </span>
        </div>
        <code className="passkeys-path">{status?.clsid ?? "…"}</code>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Plugin DLL</span>
          <span className="setting-hint">
            {status === null
              ? "Checking the build output…"
              : dllPresent
                ? "Found next to kestrel.exe. Build with cargo build -p kestrel-passkey."
                : "Missing. Build kestrel-passkey and put kestrel_passkey.dll next to kestrel.exe."}
          </span>
        </div>
        <code className="passkeys-path">
          {status?.registeredPath ?? status?.dllPath ?? "…"}
        </code>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Windows plugin</span>
          <span className="setting-hint">
            {status?.windowsError
              ? status.windowsError
              : `Windows API HRESULT ${hresult(status?.windowsHresult ?? null)}`}
          </span>
        </div>
        <span className={`passkeys-state ${status?.windowsState === 1 ? "is-on" : "is-off"}`}>
          {stateLabel}
        </span>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Plugin pipe</span>
          <span className="setting-hint">
            User-only; it exists only while the registration is active.
          </span>
        </div>
        <code className="passkeys-path">
          {status?.pipe ?? String.raw`\\.\pipe\kestrel-passkeys`}
          {status?.pipeRunning ? " · running" : " · stopped"}
        </code>
      </div>

      <div className="passkeys-actions">
        <Button
          variant="primary"
          leading={<ShieldCheck size={15} aria-hidden />}
          disabled={busy !== null || !dllPresent}
          onClick={() => void run("register")}
        >
          {busy === "register" ? "Registering…" : "Register plugin"}
        </Button>
        <Button
          variant="secondary"
          leading={<ShieldOff size={15} aria-hidden />}
          disabled={busy !== null || (!registered && status?.windowsState !== 1)}
          onClick={() => void run("unregister")}
        >
          {busy === "unregister" ? "Unregistering…" : "Unregister"}
        </Button>
      </div>

      {error ? (
        <p className="passkeys-error" role="alert">
          {error}
        </p>
      ) : null}

      <div className="passkeys-note" role="note">
        <strong>What is verified here.</strong> The CLSID points at the built
        DLL, the pipe serves this user, and Windows answered{" "}
        <code>WebAuthNPluginAddAuthenticator</code>
        {status?.windowsHresult === null
          ? "."
          : registeredWithWindows(status)
            ? " with success."
            : ` with ${hresult(status?.windowsHresult ?? null)}.`}{" "}
        <strong>Where it stands.</strong>{" "}
        {registeredWithWindows(status) && status?.windowsState === 1
          ? "Kestrel is an enabled passkey provider on this device: Windows will offer it when a site asks for a passkey, and every signature waits for an explicit Approve here."
          : registeredWithWindows(status)
            ? "Windows accepted the provider but it is switched off: turn Kestrel on in Settings → Accounts → Passkeys → Advanced."
            : status?.windowsHresult === -2147009196
              ? "Windows refuses plugin authenticators from an unpackaged process. Run the packaged build (deploy/msix) so the app has package identity."
              : "Registration did not succeed; the code above is what Windows answered."}{" "}
        Assertions stay gated in the app: presence, not verification — no PIN or
        biometric check (<code>uv: false</code>) and no verification of
        Windows&apos; per-request signature.
      </div>
    </section>
  );
}
