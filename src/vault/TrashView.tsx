import { useCallback, useEffect, useRef, useState } from "react";
import { RotateCcw, Trash2 } from "lucide-react";
import { errorText } from "../api";
import { relativeTime } from "../lib/format";
import { trashApi, type TrashSummary } from "../lib/api-trash";
import { Button } from "../ui/Button";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { TextField } from "../ui/Input";
import { Dialog } from "../ui/Overlay";
import "../styles/trash.css";

/**
 * Trash — a full-pane view that replaces the list/detail area while open.
 * Render it inside a flex pane that spans that area (for example
 * `<div className="single-pane">`); the component fills its parent.
 *
 * Props
 * - `onError(message)` fires with a human-readable sentence when a command
 *   fails; the view also shows the message inline.
 *
 * Behaviour: rows list trashed items newest-deleted first. Restore is one
 * click. "Delete permanently" opens an inline confirmation that requires the
 * item title to be typed. "Empty trash" is a separate action behind its own
 * dialog. Deletion here removes the item row, its archived versions and its
 * attachments; until then the ciphertext stays in the vault.
 */
export default function TrashView({
  onChanged,
  onError,
}: {
  /** Fires after restore/purge, so the vault list and its counts re-read. */
  onChanged?: () => void;
  onError?: (m: string) => void;
}) {
  const [rows, setRows] = useState<TrashSummary[]>([]);
  const [loading, setLoading] = useState(true);
  /** Item id being restored/purged, or "trash" while emptying. */
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const [emptyOpen, setEmptyOpen] = useState(false);
  const [emptyTyped, setEmptyTyped] = useState("");

  const changedRef = useRef(onChanged);
  const errorRef = useRef(onError);
  useEffect(() => {
    changedRef.current = onChanged;
    errorRef.current = onError;
  }, [onChanged, onError]);

  const fail = useCallback((reason: unknown) => {
    const message = errorText(reason);
    setError(message);
    errorRef.current?.(message);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const items = await trashApi.list();
      setRows(items);
    } catch (reason) {
      fail(reason);
    } finally {
      setLoading(false);
    }
  }, [fail]);

  useEffect(() => {
    void load();
  }, [load]);

  const restore = useCallback(
    (row: TrashSummary) => {
      setBusy(row.id);
      setError(null);
      void trashApi
        .restore(row.id)
        .then(() => {
          setConfirmId(null);
          setTyped("");
          changedRef.current?.();
          return load();
        })
        .catch(fail)
        .finally(() => setBusy(null));
    },
    [fail, load],
  );

  const purge = useCallback(
    (row: TrashSummary) => {
      setBusy(row.id);
      setError(null);
      void trashApi
        .purge(row.id)
        .then(() => {
          setConfirmId(null);
          setTyped("");
          changedRef.current?.();
          return load();
        })
        .catch(fail)
        .finally(() => setBusy(null));
    },
    [fail, load],
  );

  const empty = useCallback(() => {
    setBusy("trash");
    setError(null);
    void trashApi
      .empty()
      .then(() => {
        setEmptyOpen(false);
        setEmptyTyped("");
        changedRef.current?.();
        return load();
      })
      .catch(fail)
      .finally(() => setBusy(null));
  }, [fail, load]);

  function beginConfirm(row: TrashSummary) {
    setConfirmId(row.id);
    setTyped("");
    setError(null);
  }

  function cancelConfirm() {
    setConfirmId(null);
    setTyped("");
  }

  const emptyReady = emptyTyped.trim() === "EMPTY";
  const emptyLabel =
    rows.length === 1 ? "1 item" : `${rows.length} items`;

  return (
    <section className="trash-view" aria-label="Trash">
      <header className="trash-head">
        <div className="trash-heading">
          <h1 className="trash-title">Trash</h1>
          <span className="trash-count" aria-live="polite">
            {rows.length}
          </span>
          <span className="trash-head-spacer" />
          <Button
            variant="danger"
            size="sm"
            leading={<Trash2 size={14} aria-hidden />}
            disabled={loading || rows.length === 0 || busy !== null}
            onClick={() => {
              setEmptyTyped("");
              setEmptyOpen(true);
            }}
          >
            Empty trash
          </Button>
        </div>
        <p className="trash-note">
          Trash keeps the ciphertext; purge removes the row.
        </p>
      </header>

      <div className="trash-scroll">
        {error ? (
          <p className="trash-error" role="alert">
            {error}
          </p>
        ) : null}

        {loading && rows.length === 0 ? (
          <div className="trash-loading" aria-hidden>
            <div className="row-skeleton" />
            <div className="row-skeleton" />
            <div className="row-skeleton" />
          </div>
        ) : null}

        {!loading && rows.length === 0 ? (
          <div className="trash-empty">
            <span className="trash-empty-glyph">
              <Trash2 size={18} strokeWidth={1.5} aria-hidden />
            </span>
            <h2 className="empty-title">Trash is empty</h2>
            <p className="empty-copy">
              Items you delete from the vault land here. They stay sealed and
              restorable until you empty the trash or delete one permanently.
            </p>
          </div>
        ) : null}

        {rows.length > 0 ? (
          <ul
            className="trash-list"
            aria-busy={loading || busy !== null}
            aria-label="Deleted items"
          >
            {rows.map((row) => {
              const confirming = confirmId === row.id;
              const working = busy === row.id;
              return (
                <li key={row.id} className="trash-item">
                  <div className="trash-row">
                    <span className="trash-glyph">
                      <CategoryGlyph category={row.category} size={15} />
                    </span>
                    <div className="trash-row-body">
                      <span className="trash-row-title">{row.title}</span>
                      <span className="trash-row-meta">
                        Deleted{" "}
                        {relativeTime(row.deletedAt ?? row.updatedAt)}
                      </span>
                    </div>
                    <div className="trash-row-actions">
                      <Button
                        variant="secondary"
                        size="sm"
                        leading={<RotateCcw size={13} aria-hidden />}
                        disabled={busy !== null}
                        onClick={() => restore(row)}
                      >
                        Restore
                      </Button>
                      <Button
                        variant="quiet"
                        size="sm"
                        className="trash-purge"
                        disabled={busy !== null || confirming}
                        aria-expanded={confirming}
                        onClick={() => beginConfirm(row)}
                      >
                        Delete permanently
                      </Button>
                    </div>
                  </div>

                  {confirming ? (
                    <div
                      className="trash-confirm"
                      role="group"
                      aria-label={`Confirm permanent deletion of ${row.title}`}
                    >
                      <p className="trash-confirm-copy">
                        Type the item title to confirm. This removes the
                        ciphertext, its version history and its attachments,
                        and cannot be undone.
                      </p>
                      <TextField
                        label={`Type “${row.title}” to confirm`}
                        value={typed}
                        autoFocus
                        spellCheck={false}
                        autoComplete="off"
                        onChange={(event) => setTyped(event.target.value)}
                      />
                      <div className="trash-confirm-actions">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={working}
                          onClick={cancelConfirm}
                        >
                          Cancel
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          disabled={
                            working || typed.trim() !== row.title.trim()
                          }
                          onClick={() => purge(row)}
                        >
                          {working ? "Deleting…" : "Delete permanently"}
                        </Button>
                      </div>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : null}
      </div>

      <Dialog
        open={emptyOpen}
        onOpenChange={(open) => {
          setEmptyOpen(open);
          if (!open) setEmptyTyped("");
        }}
        alert
        title="Empty the trash?"
        description={`Trash keeps the ciphertext; purge removes the row. This permanently deletes ${emptyLabel}, their version history and their attachments. This cannot be undone.`}
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              disabled={busy === "trash"}
              onClick={() => setEmptyOpen(false)}
            >
              Keep items
            </Button>
            <Button
              variant="danger"
              size="sm"
              disabled={!emptyReady || busy === "trash"}
              onClick={empty}
            >
              {busy === "trash" ? "Emptying…" : "Empty trash"}
            </Button>
          </>
        }
      >
        <TextField
          label="Type EMPTY to confirm"
          value={emptyTyped}
          autoFocus
          spellCheck={false}
          autoComplete="off"
          onChange={(event) => setEmptyTyped(event.target.value)}
        />
      </Dialog>
    </section>
  );
}
