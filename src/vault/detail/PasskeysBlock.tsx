/**
 * PasskeysBlock — the WebAuthn credential list on a login.
 *
 * Props:
 *  - `itemId`  the owning item; both list and remove are scoped to it, so a
 *              credential cannot be removed from another item by id alone.
 *  - `onError` optional sentence sink for failures. When omitted the component
 *              reports through the app toast.
 *
 * What this block renders is metadata: the public credential id, the RP id and
 * timestamps. The private key never leaves the core, so there is nothing here
 * that could be copied into a page or a log. Removal is a two-step press and
 * cannot be undone; the site has to register the passkey again.
 */
import { useCallback, useEffect, useState } from "react";
import { Fingerprint, Trash2 } from "lucide-react";
import { errorText } from "../../api";
import {
  passkeys,
  shortCredentialId,
  type PasskeyInfo,
} from "../../lib/api-passkeys";
import { relativeTime } from "../../lib/format";
import { Button } from "../../ui/Button";
import { useNotify } from "../../ui/Toast";
import "../../styles/passkeys.css";

export default function PasskeysBlock({
  itemId,
  onError,
}: {
  itemId: string;
  onError?: (message: string) => void;
}) {
  const notify = useNotify();
  const [rows, setRows] = useState<PasskeyInfo[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const fail = useCallback(
    (message: string) => {
      if (onError) onError(message);
      else notify(message, { tone: "danger" });
    },
    [notify, onError],
  );

  useEffect(() => {
    let live = true;
    setRows(null);
    setLoadError(null);
    setConfirming(null);
    passkeys.forItem(itemId).then(
      (value) => {
        if (live) setRows(value);
      },
      (error) => {
        if (!live) return;
        setLoadError(errorText(error));
        setRows([]);
      },
    );
    return () => {
      live = false;
    };
  }, [itemId, reloadKey]);

  const remove = async (credentialId: string) => {
    setBusy(credentialId);
    try {
      await passkeys.remove(itemId, credentialId);
      setConfirming(null);
      setReloadKey((key) => key + 1);
      notify("Passkey removed");
    } catch (error) {
      fail(errorText(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="block passkeys-block" aria-label="Passkeys">
      <h2 className="block-title">
        Passkeys
        <span className="block-count">{rows?.length ?? 0}</span>
      </h2>

      {loadError ? (
        <p className="passkeys-error" role="alert">
          {loadError}
        </p>
      ) : rows === null ? (
        <p className="block-note">Reading credentials…</p>
      ) : rows.length === 0 ? (
        <p className="block-note">
          No passkeys on this login. A site registers one through the Kestrel
          provider; the plugin state is in Settings → Passkeys.
        </p>
      ) : (
        <ul className="passkeys-list">
          {rows.map((row) => {
            const isBusy = busy === row.credentialId;
            const isConfirming = confirming === row.credentialId;
            return (
              <li className="passkeys-row" key={row.credentialId}>
                <span className="passkeys-glyph" aria-hidden>
                  <Fingerprint size={15} strokeWidth={1.6} />
                </span>
                <span className="passkeys-copy">
                  <span className="passkeys-rp">{row.rpId}</span>
                  <span className="passkeys-meta">
                    <code
                      className="passkeys-id"
                      title={row.credentialId}
                    >
                      {shortCredentialId(row.credentialId)}
                    </code>
                    <span>created {relativeTime(row.createdAt)}</span>
                    <span>
                      {row.lastUsedAt
                        ? `last used ${relativeTime(row.lastUsedAt)}`
                        : "never used"}
                    </span>
                  </span>
                </span>
                {isConfirming ? (
                  <span className="passkeys-confirm">
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={isBusy}
                      onClick={() => void remove(row.credentialId)}
                    >
                      {isBusy ? "Removing…" : "Remove"}
                    </Button>
                    <Button
                      size="sm"
                      variant="quiet"
                      disabled={isBusy}
                      onClick={() => setConfirming(null)}
                    >
                      Cancel
                    </Button>
                  </span>
                ) : (
                  <Button
                    size="sm"
                    variant="quiet"
                    iconOnly
                    label={`Remove passkey for ${row.rpId}`}
                    disabled={busy !== null}
                    onClick={() => setConfirming(row.credentialId)}
                  >
                    <Trash2 size={14} strokeWidth={1.6} aria-hidden />
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <p className="block-note">
        The private key stays sealed in this vault; this list only receives the
        public credential id. Removing a passkey cannot be undone, and the site
        must register a new one.
      </p>
    </section>
  );
}
