/**
 * AttachmentsSection — the files block rendered under an item's fields.
 *
 * Props:
 *  - `itemId`   the owning item; every call is scoped to it, so files can
 *               never be read across items.
 *  - `onError`  called with a sentence when an operation fails. When omitted,
 *               the component reports through the app toast itself.
 *
 * Nothing here renders file content: no <img>, no <iframe>, no object URL.
 * A preview of an untrusted HTML or PDF file would be an escape hatch, so
 * rows deliberately show metadata only.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Download,
  FileText,
  Info,
  Paperclip,
  Trash2,
  Upload,
} from "lucide-react";
import { errorText } from "../api";
import {
  ATTACHMENT_LIMIT_BYTES,
  attachments,
  humanSize,
  toByteArray,
  type Attachment,
} from "../lib/api-attachments";
import { Button } from "../ui/Button";
import { useNotify } from "../ui/Toast";
import { Tip } from "../ui/Tooltip";
import "../styles/attachments.css";

/**
 * v1 stores attachment bytes on this device only (PROTOCOL.md, "v1 is
 * frozen"), so every row states that plainly. The badge is a statement, not a
 * control: it stays out of the tab order and carries no affordance.
 */
const LOCAL_ONLY_BADGE = "This device only";
const LOCAL_ONLY_SENTENCE =
  "Attachments are stored locally and are not synced yet. This file will not appear on your other devices.";

interface PendingUpload {
  name: string;
  index: number;
  total: number;
}

export default function AttachmentsSection({
  itemId,
  onError,
}: {
  itemId: string;
  onError?: (msg: string) => void;
}) {
  const notify = useNotify();
  const [files, setFiles] = useState<Attachment[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [pending, setPending] = useState<PendingUpload | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [missing, setMissing] = useState<Record<string, true>>({});
  const input = useRef<HTMLInputElement>(null);
  const liveItem = useRef(itemId);
  liveItem.current = itemId;

  const fail = useCallback(
    (message: string) => {
      if (onError) onError(message);
      else notify(message, { tone: "danger" });
    },
    [notify, onError],
  );

  useEffect(() => {
    let live = true;
    setFiles(null);
    setLoadError(null);
    setConfirming(null);
    setMissing({});
    attachments.list(itemId).then(
      (rows) => {
        if (live) setFiles(rows);
      },
      (error) => {
        if (live) {
          setFiles([]);
          setLoadError(errorText(error));
        }
      },
    );
    return () => {
      live = false;
    };
  }, [itemId, reloadKey]);

  const ingest = useCallback(
    async (incoming: File[]) => {
      if (!incoming.length || pending) return;
      const target = itemId;
      let added = 0;
      for (let index = 0; index < incoming.length; index += 1) {
        const file = incoming[index];
        if (file.size > ATTACHMENT_LIMIT_BYTES) {
          fail(
            `“${file.name}” is ${humanSize(file.size)}. Attachments are limited to 25 MiB.`,
          );
          continue;
        }
        if (file.size === 0) {
          fail(`“${file.name}” is empty, so there is nothing to seal.`);
          continue;
        }
        setPending({ name: file.name, index: index + 1, total: incoming.length });
        try {
          const buffer = await file.arrayBuffer();
          const created = await attachments.add(
            target,
            file.name,
            file.type || "application/octet-stream",
            toByteArray(buffer),
          );
          added += 1;
          if (liveItem.current === target) {
            setFiles((current) => [...(current ?? []), created]);
          }
        } catch (error) {
          fail(errorText(error));
        }
      }
      setPending(null);
      if (added > 0) {
        notify(added === 1 ? "Attachment sealed." : `${added} attachments sealed.`);
      }
    },
    [fail, itemId, notify, pending],
  );

  async function saveAs(attachment: Attachment) {
    setBusyId(attachment.id);
    try {
      const path = await attachments.saveAs(itemId, attachment.id);
      setMissing((current) => {
        if (!current[attachment.id]) return current;
        const next = { ...current };
        delete next[attachment.id];
        return next;
      });
      notify("Saved to Downloads", { detail: path });
    } catch (error) {
      const message = errorText(error);
      if (/no longer in the vault|not found/i.test(message)) {
        setMissing((current) => ({ ...current, [attachment.id]: true }));
        fail(`“${attachment.name}” has no stored data left.`);
      } else {
        fail(message);
      }
    } finally {
      setBusyId(null);
    }
  }

  async function remove(attachment: Attachment) {
    setBusyId(attachment.id);
    try {
      await attachments.remove(itemId, attachment.id);
      setFiles((current) => (current ?? []).filter((f) => f.id !== attachment.id));
      setConfirming(null);
      notify(`Removed “${attachment.name}”.`);
    } catch (error) {
      fail(errorText(error));
    } finally {
      setBusyId(null);
    }
  }

  const loading = files === null;
  const count = files?.length ?? 0;
  const disabled = loading || pending !== null;

  return (
    <section className="block attachments" aria-label="Attachments" aria-busy={pending !== null}>
      <div className="attachment-head">
        <h2 className="block-title">
          Attachments
          {count > 0 ? <span className="block-count">{count}</span> : null}
        </h2>
        <Tip
          label="Files are shown as metadata only. Kestrel never renders previews, so no HTML or PDF is opened from the vault."
          side="top"
        >
          <span className="attachment-info" tabIndex={0} aria-label="About attachments">
            <Info size={12} strokeWidth={1.8} aria-hidden />
          </span>
        </Tip>
      </div>

      {loadError ? (
        <p className="attachment-error" role="alert">
          {loadError}{" "}
          <button
            type="button"
            className="attachment-retry"
            onClick={() => setReloadKey((n) => n + 1)}
          >
            Try again
          </button>
        </p>
      ) : null}

      {count > 0 ? (
        <ul className="attachment-list">
          {files?.map((attachment) => {
            const confirmingThis = confirming === attachment.id;
            const busy = busyId === attachment.id;
            const isMissing = Boolean(missing[attachment.id]);
            return (
              <li
                key={attachment.id}
                className={`attachment-row${isMissing ? " is-missing" : ""}`}
              >
                <span className="attachment-glyph" aria-hidden>
                  <FileText size={15} strokeWidth={1.6} />
                </span>
                <div className="attachment-copy">
                  <span className="attachment-name" title={attachment.name}>
                    {attachment.name}
                  </span>
                  <span className="attachment-meta">
                    <span>{humanSize(attachment.size)}</span>
                    <span className="attachment-dot" aria-hidden>·</span>
                    <span className="attachment-digest" title="SHA-256 prefix">
                      {attachment.digest}
                    </span>
                    {isMissing ? (
                      <span className="attachment-missing">Data missing</span>
                    ) : null}
                  </span>
                </div>
                {/* Honesty about v1 scope: the bytes are on this device only. */}
                <span className="attachment-local" title={LOCAL_ONLY_SENTENCE}>
                  {LOCAL_ONLY_BADGE}
                  <span className="sr-only">. {LOCAL_ONLY_SENTENCE}</span>
                </span>
                {confirmingThis ? (
                  <div className="attachment-confirm">
                    <span>Remove?</span>
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={busy}
                      onClick={() => remove(attachment)}
                    >
                      {busy ? "Removing…" : "Remove"}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy}
                      onClick={() => setConfirming(null)}
                    >
                      Keep
                    </Button>
                  </div>
                ) : (
                  <div className="attachment-actions">
                    <Tip label="Decrypt and write to Downloads" side="top">
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() => saveAs(attachment)}
                        leading={<Download size={13} aria-hidden />}
                      >
                        {busy ? "Saving…" : "Save as"}
                      </Button>
                    </Tip>
                    <Tip label="Remove this file from the item" side="top">
                      <button
                        type="button"
                        className="icon-btn attachment-remove"
                        aria-label={`Remove ${attachment.name}`}
                        disabled={busy}
                        onClick={() => setConfirming(attachment.id)}
                      >
                        <Trash2 size={14} strokeWidth={1.6} aria-hidden />
                      </button>
                    </Tip>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="block-empty">
          {loading ? "Checking for attachments…" : "No files attached yet."}
        </p>
      )}

      <div
        className={`attachment-drop${dragOver ? " is-over" : ""}`}
        onDragOver={(event) => {
          if (disabled) return;
          event.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
            setDragOver(false);
          }
        }}
        onDrop={(event) => {
          event.preventDefault();
          setDragOver(false);
          if (disabled) return;
          void ingest(Array.from(event.dataTransfer.files));
        }}
      >
        <span className="attachment-drop-glyph" aria-hidden>
          <Paperclip size={15} strokeWidth={1.6} />
        </span>
        <div className="attachment-drop-copy">
          <span className="attachment-drop-title">
            {dragOver ? "Drop to seal these files" : "Drop files here"}
          </span>
          <span className="attachment-drop-hint">
            Sealed with this item’s key · 25 MiB per file
          </span>
        </div>
        <input
          ref={input}
          type="file"
          multiple
          className="attachment-input"
          tabIndex={-1}
          aria-hidden
          onChange={(event) => {
            const chosen = Array.from(event.currentTarget.files ?? []);
            event.currentTarget.value = "";
            void ingest(chosen);
          }}
        />
        <Button
          size="sm"
          variant="secondary"
          disabled={disabled}
          onClick={() => input.current?.click()}
          leading={<Upload size={13} aria-hidden />}
        >
          Add file
        </Button>
      </div>

      {pending ? (
        <div className="attachment-progress" role="status" aria-live="polite">
          <span className="attachment-progress-text">
            Sealing “{pending.name}”
            {pending.total > 1 ? ` · ${pending.index} of ${pending.total}` : ""}…
          </span>
          <span className="attachment-progress-track" aria-hidden>
            <span className="attachment-progress-bar" />
          </span>
        </div>
      ) : null}
    </section>
  );
}
