import { useEffect, useMemo, useState } from "react";
import { Eye, EyeOff, History, RotateCcw, X } from "lucide-react";
import { errorText } from "../api";
import { historyGet, historyList, historyRestore, type VersionSummary } from "../lib/api-history";
import { maskSecret, relativeTime } from "../lib/format";
import type { Item } from "../types";
import { Button } from "../ui/Button";
import { useNotify } from "../ui/Toast";
import "../styles/history.css";

/**
 * Right-hand history rail for an open item.
 *
 * Props:
 * - `item`: the currently open (live) item; the rail compares versions to it.
 * - `onRestored`: called with the newly saved item after a successful restore,
 *   so the detail pane can switch to the restored content.
 * - `onClose`: closes the rail.
 *
 * Read-only: it never edits or purges anything. Restoring saves the chosen
 * archived version as a new version, so the current one is archived, not lost.
 */
export default function HistoryRail({
  item,
  onRestored,
  onClose,
}: {
  item: Item;
  onRestored: (item: Item) => void;
  onClose: () => void;
}) {
  const notify = useNotify();
  const [versions, setVersions] = useState<VersionSummary[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const [selected, setSelected] = useState<number | null>(null);
  const [snapshot, setSnapshot] = useState<Item | null>(null);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [versionError, setVersionError] = useState<string | null>(null);

  const [revealed, setRevealed] = useState<Record<string, true>>({});
  const [confirming, setConfirming] = useState(false);
  const [restoring, setRestoring] = useState(false);

  // A new item means a new history; drop any selection from the old one.
  useEffect(() => {
    setSelected(null);
    setSnapshot(null);
    setConfirming(false);
    setRevealed({});
  }, [item.id]);

  useEffect(() => {
    let live = true;
    setVersions(null);
    setListError(null);
    historyList(item.id)
      .then((next) => {
        if (live) setVersions(next);
      })
      .catch((e) => {
        if (live) setListError(errorText(e));
      });
    return () => {
      live = false;
    };
  }, [item.id, reloadKey]);

  useEffect(() => {
    if (selected === null) {
      setSnapshot(null);
      setVersionError(null);
      setLoadingVersion(false);
      return;
    }
    let live = true;
    setLoadingVersion(true);
    setVersionError(null);
    setSnapshot(null);
    historyGet(item.id, selected)
      .then((next) => {
        if (live) setSnapshot(next);
      })
      .catch((e) => {
        if (live) setVersionError(errorText(e));
      })
      .finally(() => {
        if (live) setLoadingVersion(false);
      });
    return () => {
      live = false;
    };
  }, [item.id, selected, reloadKey]);

  const comparison = useMemo(() => {
    if (!snapshot) return null;
    const liveById = new Map(item.fields.map((f) => [f.id, f]));
    const archivedIds = new Set(snapshot.fields.map((f) => f.id));
    return {
      titleChanged: snapshot.title !== item.title,
      notesChanged: snapshot.notes !== item.notes,
      fields: snapshot.fields.map((field) => {
        const live = liveById.get(field.id);
        return {
          field,
          changed: !live || live.label !== field.label || live.value !== field.value,
        };
      }),
      addedLater: item.fields.filter((f) => !archivedIds.has(f.id)),
    };
  }, [snapshot, item]);

  const selectVersion = (version: number | null) => {
    setSelected(version);
    setConfirming(false);
    setRevealed({});
  };

  const restore = async () => {
    if (selected === null) return;
    setRestoring(true);
    try {
      const restored = await historyRestore(item.id, selected);
      notify(`Restored “${restored.title}”`, {
        detail: "The previous current version is kept in history.",
      });
      setConfirming(false);
      setSelected(null);
      setReloadKey((k) => k + 1);
      onRestored(restored);
    } catch (e) {
      notify("Restore failed", { detail: errorText(e), tone: "danger" });
    } finally {
      setRestoring(false);
    }
  };

  const toggleReveal = (id: string) =>
    setRevealed((current) =>
      current[id] ? Object.fromEntries(Object.entries(current).filter(([k]) => k !== id)) : { ...current, [id]: true },
    );

  return (
    <aside className="history-rail" aria-label="Item history">
      <header className="history-head">
        <span className="history-title">
          <History size={14} strokeWidth={1.7} aria-hidden /> History
        </span>
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          label="Close history"
          onClick={onClose}
        >
          <X size={15} strokeWidth={1.7} aria-hidden />
        </Button>
      </header>

      <div className="history-scroll">
        <ul className="history-list">
          <li>
            <button
              type="button"
              className={`history-row ${selected === null ? "is-active" : ""}`}
              aria-pressed={selected === null}
              onClick={() => selectVersion(null)}
            >
              <span className="history-row-main">
                <span className="history-row-title">{item.title}</span>
                <span className="history-row-meta">
                  Edited {relativeTime(item.updatedAt)} · {item.fields.length}{" "}
                  {item.fields.length === 1 ? "field" : "fields"}
                </span>
              </span>
              <span className="history-badge history-badge-current">Current</span>
            </button>
          </li>

          {versions === null && listError === null ? (
            <li className="history-loading">Reading history…</li>
          ) : null}
          {listError ? (
            <li className="history-error" role="alert">
              {listError}
            </li>
          ) : null}

          {versions?.map((version) => (
            <li key={version.version}>
              <button
                type="button"
                className={`history-row ${selected === version.version ? "is-active" : ""}`}
                aria-pressed={selected === version.version}
                onClick={() => selectVersion(version.version)}
              >
                <span className="history-row-main">
                  <span className="history-row-title">{version.title}</span>
                  <span className="history-row-meta">
                    {relativeTime(version.archivedAt)} · {version.fieldCount}{" "}
                    {version.fieldCount === 1 ? "field" : "fields"}
                  </span>
                </span>
                <span className="history-badge">v{version.version}</span>
              </button>
            </li>
          ))}

          {versions !== null && versions.length === 0 && !listError ? (
            <li className="history-empty">
              No earlier versions yet — saving an edit creates one.
            </li>
          ) : null}
        </ul>

        {selected === null ? (
          <p className="history-hint">
            Pick an earlier version to compare it with the current item.
          </p>
        ) : loadingVersion ? (
          <p className="history-loading">Opening version…</p>
        ) : versionError ? (
          <p className="history-error" role="alert">
            {versionError}
          </p>
        ) : snapshot && comparison ? (
          <section className="history-preview" aria-label={`Version ${selected}`}>
            <h2
              className={`history-preview-title ${comparison.titleChanged ? "is-changed" : ""}`}
            >
              {snapshot.title}
            </h2>

            {comparison.fields.length === 0 ? (
              <p className="history-empty-note">This version has no fields.</p>
            ) : (
              <ul className="history-fields">
                {comparison.fields.map(({ field, changed }) => {
                  const hidden = field.sensitive && !revealed[field.id];
                  return (
                    <li
                      key={field.id}
                      className={`history-field ${changed ? "is-changed" : ""}`}
                    >
                      <span className="history-field-label">
                        {field.label}
                        {changed ? (
                          <span className="history-changed-mark">changed</span>
                        ) : null}
                      </span>
                      <span className="history-field-value-row">
                        <span
                          className={`history-field-value ${
                            field.sensitive ? "is-mono" : ""
                          } ${field.value ? "" : "is-empty"}`}
                        >
                          {field.value
                            ? hidden
                              ? maskSecret(field.value)
                              : field.value
                            : "empty"}
                        </span>
                        {field.sensitive && field.value ? (
                          <button
                            type="button"
                            className="icon-btn history-reveal"
                            aria-label={hidden ? `Reveal ${field.label}` : `Hide ${field.label}`}
                            onClick={() => toggleReveal(field.id)}
                          >
                            {hidden ? (
                              <Eye size={13} aria-hidden />
                            ) : (
                              <EyeOff size={13} aria-hidden />
                            )}
                          </button>
                        ) : null}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}

            {comparison.addedLater.length > 0 ? (
              <p className="history-empty-note">
                {comparison.addedLater.length}{" "}
                {comparison.addedLater.length === 1 ? "field was" : "fields were"}{" "}
                added after this version.
              </p>
            ) : null}

            {snapshot.notes ? (
              <div className={`history-notes ${comparison.notesChanged ? "is-changed" : ""}`}>
                <span className="history-field-label">
                  notes
                  {comparison.notesChanged ? (
                    <span className="history-changed-mark">changed</span>
                  ) : null}
                </span>
                <p className="history-notes-text">{snapshot.notes}</p>
              </div>
            ) : null}
          </section>
        ) : null}
      </div>

      <footer className="history-foot">
        {selected === null ? (
          <p className="history-foot-note">
            Versions are kept encrypted, up to 50 per item.
          </p>
        ) : confirming ? (
          <div className="history-confirm">
            <p className="history-confirm-copy">
              Replace the current item with v{selected}? The current version is
              archived, so nothing is lost.
            </p>
            <div className="history-actions">
              <Button
                variant="primary"
                size="sm"
                leading={<RotateCcw size={13} aria-hidden />}
                disabled={restoring}
                onClick={restore}
              >
                {restoring ? "Restoring…" : `Restore v${selected}`}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={restoring}
                onClick={() => setConfirming(false)}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            block
            leading={<RotateCcw size={13} aria-hidden />}
            onClick={() => setConfirming(true)}
          >
            Restore this version
          </Button>
        )}
      </footer>
    </aside>
  );
}
