/**
 * Conflict review — a full-pane screen in the editor's layout, not a dialog.
 *
 * One item at a time: the item title, the device that wrote the other side,
 * and one two-column table per field that both sides changed. A decision is
 * whole-item on purpose (`mine`, `theirs` or `both`); there is no per-field
 * merge, because the core never guesses and neither does this screen.
 *
 * Sensitive values start masked and use the same reveal control as the detail
 * view (`Eye`/`EyeOff`, `aria-pressed`), and they hide again when the window
 * loses focus or the next item is shown.
 */
import { useCallback, useEffect, useState } from "react";
import {
  Eye,
  EyeOff,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { errorText } from "../api";
import {
  announceSyncChange,
  sync,
  type ConflictView,
  type ResolveChoice,
} from "../lib/api-sync";
import { relativeTime, maskSecret } from "../lib/format";
import { Button } from "../ui/Button";
import { Tip } from "../ui/Tooltip";

/** `localUpdatedAt` is unix seconds in the sync contract; tolerate milliseconds. */
function unixSeconds(value: number): number {
  return value > 1_000_000_000_000 ? Math.floor(value / 1000) : value;
}

function ConflictValue({
  value,
  sensitive,
  revealed,
  onToggle,
  side,
}: {
  value: string;
  sensitive: boolean;
  revealed: boolean;
  onToggle: () => void;
  /** For the accessible name: "mine" or "theirs". */
  side: string;
}) {
  const empty = value.length === 0;
  const masked = sensitive && !revealed;
  return (
    <div
      className={`conflict-value ${empty ? "is-empty" : ""} ${
        sensitive ? "is-mono" : ""
      }`}
    >
      <span className="conflict-value-text">
        {empty ? "—" : masked ? maskSecret(value) : value}
      </span>
      {sensitive && !empty ? (
        <Tip label={revealed ? "Hide value" : "Reveal value"}>
          <button
            type="button"
            className="icon-btn"
            onClick={onToggle}
            aria-pressed={revealed}
            aria-label={
              revealed
                ? `Hide the ${side} value`
                : `Reveal the ${side} value`
            }
          >
            {revealed ? (
              <EyeOff size={14} strokeWidth={1.6} aria-hidden />
            ) : (
              <Eye size={14} strokeWidth={1.6} aria-hidden />
            )}
          </button>
        </Tip>
      ) : null}
    </div>
  );
}

export default function ConflictReview({
  onClose,
}: {
  /** Back to the Settings page that opened this screen. */
  onClose: () => void;
}) {
  const [rows, setRows] = useState<ConflictView[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState<ResolveChoice | null>(null);
  const [revealed, setRevealed] = useState<Record<string, true>>({});

  const load = useCallback(async () => {
    try {
      const next = await sync.conflicts();
      setRows(next);
      setProblem(null);
    } catch (failure) {
      setProblem(errorText(failure));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const current = rows?.[0] ?? null;

  // A new item is a new secret: collapse every reveal when it changes.
  useEffect(() => {
    setRevealed({});
  }, [current?.itemId]);

  // Same contract as the detail view: secrets do not survive lost attention.
  useEffect(() => {
    const hide = () => setRevealed({});
    window.addEventListener("blur", hide);
    const onVisibility = () => {
      if (document.hidden) hide();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("blur", hide);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  async function choose(choice: ResolveChoice) {
    if (!current || busy) return;
    setBusy(choice);
    setProblem(null);
    try {
      await sync.resolve(current.itemId, choice);
      // The core owns what is left: re-read instead of removing the row here,
      // so the next conflict shown is the next one the core reports.
      await load();
    } catch (failure) {
      setProblem(errorText(failure));
    } finally {
      setBusy(null);
      // The pill and the Settings card re-read either way: after a resolve the
      // conflict count has moved, and after a failure the old count is no
      // longer known to be current.
      announceSyncChange();
    }
  }

  const editedAt = current ? unixSeconds(current.localUpdatedAt) : 0;

  return (
    <section className="editor conflict-review" aria-label="Sync conflicts">
      <header className="editor-head">
        <div className="editor-head-inner">
          <div className="editor-status">
            <span className="eyebrow">Sync conflict</span>
            {rows && rows.length > 0 ? (
              <span className="dirty-flag">
                {rows.length} item{rows.length === 1 ? "" : "s"} left
              </span>
            ) : null}
          </div>
          <div className="editor-actions">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Back to settings
            </Button>
          </div>
        </div>
      </header>

      <div className="editor-scroll">
        {problem ? (
          <p className="form-error" role="alert">
            {problem}
          </p>
        ) : null}

        {rows === null ? (
          problem === null ? (
            <p className="conflict-lede">
              <LoaderCircle size={14} className="sync-spin" aria-hidden />{" "}
              Reading conflicts…
            </p>
          ) : null
        ) : current === null ? (
          <div className="conflict-empty">
            <span className="conflict-empty-glyph" aria-hidden>
              <ShieldCheck size={22} strokeWidth={1.5} />
            </span>
            <h1 className="conflict-title">No conflicts.</h1>
            <p className="conflict-lede">
              Every item on this device agrees with the server. Nothing is
              waiting for a decision.
            </p>
            <div className="form-actions conflict-empty-actions">
              <Button variant="secondary" size="sm" onClick={onClose}>
                Back to settings
              </Button>
            </div>
          </div>
        ) : (
          <>
            <div className="conflict-intro">
              <h1 className="conflict-title">{current.title}</h1>
              <p className="conflict-lede">
                <TriangleAlert size={13} aria-hidden />
                <span>
                  This device edited the item {relativeTime(editedAt)}. The other
                  side was written by <code>{current.remoteDevice}</code>.
                  Choosing a side writes it for the whole item; the version you
                  did not keep is not uploaded.
                </span>
              </p>
            </div>

            {current.fields.length === 0 ? (
              <p className="block-empty">
                The core reports no differing fields for this item. The two
                whole versions still differ, so choose one below.
              </p>
            ) : (
              current.fields.map((field) => {
                const localKey = `local:${current.itemId}:${field.path}`;
                const remoteKey = `remote:${current.itemId}:${field.path}`;
                return (
                  <section
                    className="edit-block conflict-field"
                    key={field.path}
                    aria-labelledby={`conflict-${field.path}`}
                  >
                    <h2
                      className="block-title conflict-field-title"
                      id={`conflict-${field.path}`}
                    >
                      {field.sensitive ? (
                        <LockKeyhole size={12} aria-hidden />
                      ) : null}
                      {field.label}
                    </h2>
                    <table className="conflict-table">
                      <thead>
                        <tr>
                          <th scope="col">Mine</th>
                          <th scope="col">Theirs · {current.remoteDevice}</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>
                            <ConflictValue
                              value={field.local}
                              sensitive={field.sensitive}
                              side="mine"
                              revealed={Boolean(revealed[localKey])}
                              onToggle={() =>
                                setRevealed((previous) => {
                                  const next = { ...previous };
                                  if (next[localKey]) delete next[localKey];
                                  else next[localKey] = true;
                                  return next;
                                })
                              }
                            />
                          </td>
                          <td>
                            <ConflictValue
                              value={field.remote}
                              sensitive={field.sensitive}
                              side="theirs"
                              revealed={Boolean(revealed[remoteKey])}
                              onToggle={() =>
                                setRevealed((previous) => {
                                  const next = { ...previous };
                                  if (next[remoteKey]) delete next[remoteKey];
                                  else next[remoteKey] = true;
                                  return next;
                                })
                              }
                            />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </section>
                );
              })
            )}
          </>
        )}
      </div>

      {current ? (
        <footer className="editor-foot">
          <div className="editor-foot-inner">
            <span className="editor-foot-hint">
              One choice resolves the whole item. “Keep both” creates a copy;
              the vault never overwrites one side with the other.
            </span>
            <div className="conflict-choices">
              <Button
                variant="ghost"
                size="sm"
                disabled={busy !== null}
                onClick={() => void choose("mine")}
              >
                {busy === "mine" ? "Keeping mine…" : "Keep mine"}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busy !== null}
                onClick={() => void choose("theirs")}
              >
                {busy === "theirs" ? "Keeping theirs…" : "Keep theirs"}
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={busy !== null}
                onClick={() => void choose("both")}
              >
                {busy === "both" ? "Creating copy…" : "Keep both (creates a copy)"}
              </Button>
            </div>
          </div>
        </footer>
      ) : null}
    </section>
  );
}
