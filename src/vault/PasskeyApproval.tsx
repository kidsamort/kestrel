/**
 * PasskeyApproval — the in-app presence gate for a passkey assertion.
 *
 * The Windows WebAuthn broker owns the system dialog, but this build has no
 * user-verification channel: nothing in the protocol proves that the person at
 * the keyboard asked for the signature. So the core blocks every assertion
 * until this bar is answered, and only then sets the presence flag. A denial,
 * a timeout, or no window to ask in refuses the signature — the bar is the
 * gate, not a notification.
 *
 * The payload is the site and the account. No key, no credential id, nothing
 * that could be replayed.
 */
import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Fingerprint, X } from "lucide-react";
import { passkeys } from "../lib/api-passkeys";
import { Button } from "../ui/Button";

export const APPROVAL_EVENT = "passkeys://approval";

interface Request {
  id: number;
  rpId: string;
  account: string;
}

export default function PasskeyApproval() {
  const [request, setRequest] = useState<Request | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    let unlisten: (() => void) | null = null;
    listen<Request>(APPROVAL_EVENT, (event) => {
      if (live) setRequest(event.payload);
    })
      .then((stop) => {
        if (live) unlisten = stop;
        else stop();
      })
      .catch(() => {});
    return () => {
      live = false;
      unlisten?.();
    };
  }, []);

  const answer = useCallback(
    async (allow: boolean) => {
      if (!request) return;
      setBusy(true);
      try {
        await passkeys.answer(request.id, allow);
      } finally {
        setBusy(false);
        setRequest(null);
      }
    },
    [request],
  );

  if (!request) return null;

  return (
    <div className="passkey-approval" role="alertdialog" aria-label="Passkey sign-in">
      <Fingerprint size={18} strokeWidth={1.6} aria-hidden />
      <div className="passkey-approval-copy">
        <p className="passkey-approval-title">Use your passkey?</p>
        <p className="passkey-approval-body">
          <strong>{request.rpId}</strong> asked to sign in as{" "}
          <strong>{request.account}</strong>. Nothing is signed until you say
          yes, and the answer expires in a minute.
        </p>
      </div>
      <div className="passkey-approval-actions">
        <Button variant="ghost" onClick={() => void answer(false)} disabled={busy}>
          <X size={14} strokeWidth={1.8} aria-hidden /> Deny
        </Button>
        <Button variant="primary" onClick={() => void answer(true)} disabled={busy}>
          Approve
        </Button>
      </div>
    </div>
  );
}
