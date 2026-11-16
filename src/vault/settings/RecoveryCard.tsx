/**
 * Settings → Recovery kit.
 *
 * The card is a state machine over one fact (`recovery_status`) and one
 * transient value (a freshly minted code). The code only exists in this
 * component's state between "Create kit" and the user dismissing it: the core
 * stores no copy, so the sheet is the copy, and the card says so.
 */
import { useEffect, useState } from "react";
import { Check, KeyRound, Printer, ShieldAlert, ShieldCheck } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import { recovery, type RecoveryKit, type RecoveryStatus } from "../../lib/api-recovery";
import { Button } from "../../ui/Button";
import { useNotify } from "../../ui/Toast";
import RecoveryPrint, { RecoveryCode } from "../RecoveryPrint";
import "../../styles/recovery.css";

export default function RecoveryCard() {
  const notify = useNotify();
  const [status, setStatus] = useState<RecoveryStatus | null>(null);
  useSettingsStatus(
    "recovery",
    status
      ? {
          tone: status.enrolled ? "on" : "attention",
          label: status.enrolled ? "Code created" : "No code",
        }
      : null,
  );
  const [problem, setProblem] = useState<string | null>(null);
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmReplace, setConfirmReplace] = useState(false);

  useEffect(() => {
    let live = true;
    recovery
      .status()
      .then((next) => {
        if (!live) return;
        setStatus(next);
        setProblem(null);
      })
      .catch((failure: unknown) => {
        if (!live) return;
        setStatus(null);
        setProblem(errorText(failure));
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
      const next = await recovery.create();
      setKit(next);
      setStatus({ enrolled: true, createdAt: next.createdAt });
      setConfirmReplace(false);
      notify("Recovery kit created", {
        detail: "Print it now — the code is shown once and never again.",
        tone: "success",
      });
    } catch (failure) {
      setError(errorText(failure));
    } finally {
      setBusy(false);
    }
  }

  const created =
    status?.createdAt != null
      ? new Date(status.createdAt).toLocaleDateString(undefined, {
          year: "numeric",
          month: "long",
          day: "numeric",
        })
      : null;

  return (
    <section className="card" aria-labelledby="recovery-title">
      <div className="card-head">
        <h2 className="card-title" id="recovery-title">
          <KeyRound size={15} aria-hidden /> Recovery kit
        </h2>
      </div>
      <p className="card-copy">
        A printed code that opens this vault on its own. It seals the
        <strong> master key</strong> — the key every vault in this account is
        derived from — under a key computed from the code, which is why it is
        the way back in if the password is forgotten, and why the sheet must be
        guarded like the password itself. The code exists only on paper: the
        database holds the sealed key and never the code.
      </p>

      {problem ? (
        <p className="form-error" role="alert">
          {problem}
        </p>
      ) : status === null ? (
        <p className="card-copy">Checking for a recovery code…</p>
      ) : (
        <p className="recovery-state" role="status">
          {status.enrolled ? (
            <>
              <ShieldCheck size={14} aria-hidden /> A recovery code is set
              {created ? `, created ${created}` : ""}. This app cannot show it
              again — it is on the sheet you printed.
            </>
          ) : (
            <>
              <ShieldAlert size={14} aria-hidden /> No recovery code is set. If
              the master password is lost, the vault stays closed.
            </>
          )}
        </p>
      )}

      {kit ? (
        <div className="recovery-preview">
          <span className="recovery-preview-label">
            Your new code · shown once · {kit.vaultName}
          </span>
          <RecoveryCode code={kit.code} />
          <p className="recovery-preview-warn">
            <ShieldAlert size={13} aria-hidden /> Print it and store it offline
            before closing this panel. Using the code replaces it; the sheet you
            print now stops working at that point.
          </p>
          <div className="form-actions">
            <Button
              type="button"
              variant="primary"
              size="sm"
              leading={<Printer size={14} aria-hidden />}
              onClick={() => window.print()}
            >
              Print kit
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              leading={<Check size={14} aria-hidden />}
              onClick={() => setKit(null)}
            >
              I have printed it
            </Button>
          </div>
        </div>
      ) : null}

      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}

      {confirmReplace ? (
        <div className="recovery-confirm">
          <p>
            Replacing destroys the code you already printed: the vault keeps one
            code at a time, and the old sheet stops opening anything.
          </p>
          <div className="form-actions">
            <Button
              type="button"
              variant="danger"
              size="sm"
              disabled={busy}
              onClick={() => void create()}
            >
              {busy ? "Minting a new code…" : "Replace the code"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={busy}
              onClick={() => setConfirmReplace(false)}
            >
              Keep the current one
            </Button>
          </div>
        </div>
      ) : (
        <div className="form-actions">
          {status?.enrolled ? (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => setConfirmReplace(true)}
            >
              Replace code
            </Button>
          ) : (
            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={busy || status === null}
              onClick={() => void create()}
            >
              {busy ? "Minting a code…" : "Create kit"}
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            size="sm"
            disabled={!kit}
            leading={<Printer size={14} aria-hidden />}
            title={
              kit
                ? "Print the code that is on screen"
                : "The code is only shown right after it is created. Replace it to print a new one."
            }
            onClick={() => window.print()}
          >
            Print kit
          </Button>
        </div>
      )}

      <p className="card-copy">
        Changing the master password replaces the master key, so it also clears
        the recovery code — the sheet sealed the old key. This card then shows no
        code, and a new kit is one click away.
      </p>

      {kit ? <RecoveryPrint kit={kit} /> : null}
    </section>
  );
}
