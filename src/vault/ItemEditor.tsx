import { useEffect, useMemo, useRef, useState } from "react";
import { X } from "lucide-react";
import { api, errorText } from "../api";
import { normalizeSeedPhrase } from "../lib/fields";
import type { Field, Item } from "../types";
import { Button } from "../ui/Button";
import { TextArea, TextField } from "../ui/Input";
import { Dialog } from "../ui/Overlay";
import { Switch } from "../ui/Switch";
import { useNotify } from "../ui/Toast";
import { FieldRows } from "./FieldRows";
import { GeneratorPanel } from "./GeneratorPanel";
import { TagEditor } from "./TagEditor";
import AccessSection from "./AccessSection";

const BASE32 = /^[A-Z2-7]+=*$/i;

function totpValid(secret: string): boolean {
  if (!secret.trim()) return true;
  let candidate = secret.trim();
  if (candidate.toLowerCase().startsWith("otpauth://")) {
    const match = /[?&]secret=([^&]+)/i.exec(candidate);
    candidate = match ? decodeURIComponent(match[1]) : "";
    if (!candidate) return false;
  }
  candidate = candidate.replace(/[\s-]/g, "");
  return candidate.length >= 8 && BASE32.test(candidate);
}

function fingerprint(item: Item): string {
  return JSON.stringify({
    title: item.title,
    fields: item.fields,
    notes: item.notes,
    urls: item.urls,
    tags: item.tags,
    favorite: item.favorite,
    totpSecret: item.totpSecret ?? "",
  });
}

export default function ItemEditor({
  item,
  onCancel,
  onSaved,
  focusFieldId,
  onDirtyChange,
}: {
  item: Item;
  onCancel: () => void;
  onSaved: (saved: Item) => void;
  onDirtyChange: (dirty: boolean) => void;
  /** Field to scroll to and focus on open (the audit's Fix action). */
  focusFieldId?: string;
}) {
  const notify = useNotify();
  const [draft, setDraft] = useState<Item>(item);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [genFor, setGenFor] = useState<Field | null>(null);
  const titleRef = useRef<HTMLInputElement>(null);
  const savedRef = useRef(onSaved);
  savedRef.current = onSaved;

  const dirty = useMemo(
    () => fingerprint(draft) !== fingerprint(item),
    [draft, item],
  );
  const totpOk = totpValid(draft.totpSecret ?? "");
  const canSave = dirty && draft.title.trim().length > 0 && totpOk && !saving;

  useEffect(() => {
    if (!focusFieldId) return;
    const node = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(
      `[data-field-value="${CSS.escape(focusFieldId)}"]`,
    );
    if (!node) return;
    node.scrollIntoView({ block: "center" });
    node.focus();
    node.select();
  }, [focusFieldId]);

  useEffect(() => {
    titleRef.current?.focus();
    titleRef.current?.select();
  }, []);

  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  function patch(changes: Partial<Item>) {
    setDraft((current) => ({ ...current, ...changes }));
  }

  function patchField(id: string, changes: Partial<Field>) {
    setDraft((current) => ({
      ...current,
      fields: current.fields.map((field) =>
        field.id === id ? { ...field, ...changes } : field,
      ),
    }));
  }

  function addField() {
    const id = crypto.randomUUID();
    setDraft((current) => ({
      ...current,
      fields: [...current.fields, { id, label: "", kind: "text", value: "", sensitive: false }],
    }));
    requestAnimationFrame(() => {
      const input = document.querySelector<HTMLInputElement>(
        `[data-field-label="${id}"]`,
      );
      input?.focus();
    });
  }

  function save() {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    // A seed phrase is copied and compared as words, so it is stored with
    // single spaces whatever the paste looked like. The textarea normalises on
    // blur, but Ctrl+S can fire while it still has focus.
    const fields = draft.fields
      .map((field) =>
        field.kind === "seedPhrase"
          ? { ...field, value: normalizeSeedPhrase(field.value) }
          : field,
      )
      .filter((field) => field.label.trim() || field.value);
    api
      .save({ ...draft, fields })
      .then((saved) => {
        notify(`Saved “${saved.title}”`, { tone: "success" });
        savedRef.current(saved);
      })
      .catch((failure) => setError(errorText(failure)))
      .finally(() => setSaving(false));
  }

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        save();
      }
      if (event.key !== "Escape" || genFor !== null) return;
      // Escape inside a dialog (generator, discard confirmation, menu) belongs
      // to that layer: canceling the editor too would throw the draft away and
      // re-open the very dialog the user just dismissed.
      if (event.defaultPrevented) return;
      if (document.querySelector("[role='dialog'], [role='alertdialog']")) return;
      event.preventDefault();
      onCancel();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <section className="editor" aria-label={`Editing ${item.title || "new item"}`}>
      <header className="editor-head">
        <div className="editor-head-inner">
        <div className="editor-status">
          <span className="eyebrow">Editing</span>
          <span className={dirty ? "dirty-flag" : "dirty-flag is-clean"}>
            {dirty ? "Unsaved changes" : "No changes yet"}
          </span>
        </div>
        <div className="editor-actions">
          <Button variant="ghost" size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            disabled={!canSave}
            onClick={save}
          >
            {saving ? "Saving…" : "Save item"}
          </Button>
        </div>
        </div>
      </header>

      <div className="editor-scroll">
        <input
          ref={titleRef}
          className="title-input"
          value={draft.title}
          placeholder="Untitled"
          aria-label="Item title"
          onChange={(event) => patch({ title: event.target.value })}
        />

        <div className="editor-grid">
          <div className="editor-main">
            <fieldset className="edit-block">
              <legend className="block-title">Fields</legend>
              <FieldRows
                fields={draft.fields}
                onPatch={patchField}
                onRemove={(id) =>
                  setDraft((current) => ({
                    ...current,
                    fields: current.fields.filter((f) => f.id !== id),
                  }))
                }
                onAdd={addField}
                onGenerate={setGenFor}
                note="“Secret” fields are masked in the detail view. The vault stores every field the same way; the flag is a display contract. A seed phrase is always masked, counted in words and never indexed for search."
              />
            </fieldset>

            <div className="edit-block">
              <h2 className="block-title">Notes</h2>
              <TextArea
                label="Notes"
                quietLabel
                rows={5}
                value={draft.notes}
                placeholder="Anything that should travel with this item."
                onChange={(event) => patch({ notes: event.target.value })}
              />
            </div>
          </div>

          <div className="editor-side">
            <section className="side-panel" aria-label="Organisation">
              <h2 className="block-title">Organisation</h2>
              <div className="switch-row">
                <span>
                  Favorite
                  <span className="gen-hint">Pinned to the top of the list.</span>
                </span>
                <Switch
                  label="Favorite"
                  checked={draft.favorite}
                  onCheckedChange={(favorite) => patch({ favorite })}
                />
              </div>
              <div className="edit-subhead">Tags</div>
              <TagEditor tags={draft.tags} onChange={(tags) => patch({ tags })} />
            </section>

            <section className="side-panel" aria-label="Websites and one-time code">
              <h2 className="block-title">Websites</h2>
              <UrlEditor urls={draft.urls} onChange={(urls) => patch({ urls })} />
              <h2 className="block-title">One-time code</h2>
              <TextField
                label="TOTP secret"
                quietLabel
                value={draft.totpSecret ?? ""}
                placeholder="otpauth://… or base32"
                spellCheck={false}
                className="mono-input"
                onChange={(event) =>
                  patch({
                    totpSecret: event.target.value || undefined,
                  })
                }
                error={totpOk ? null : "That is not a base32 secret Kestrel can read."}
                hint="Paste an otpauth:// URI or the base32 secret itself."
              />
            </section>

            <AccessSection item={item} disabled={dirty} />
          </div>
        </div>

        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>

      <footer className="editor-foot">
        <div className="editor-foot-inner">
        <span className="editor-foot-hint">
          <kbd className="kbd">Ctrl</kbd> <kbd className="kbd">S</kbd> saves ·{" "}
          <kbd className="kbd">Esc</kbd> cancels
        </span>
        <span className="editor-foot-hint">
          {draft.fields.length} field{draft.fields.length === 1 ? "" : "s"} ·{" "}
          {draft.tags.length} tag{draft.tags.length === 1 ? "" : "s"}
        </span>
        </div>
      </footer>

      <Dialog
        open={genFor !== null}
        onOpenChange={(open) => {
          if (!open) setGenFor(null);
        }}
        title="Generate a password"
        description={
          genFor ? `Sets “${genFor.label || "field"}” on this item.` : undefined
        }
        width={480}
      >
        <GeneratorPanel
          variant="dialog"
          onUse={(value) => {
            if (genFor) patchField(genFor.id, { value });
            setGenFor(null);
          }}
        />
      </Dialog>
    </section>
  );
}

function UrlEditor({
  urls,
  onChange,
}: {
  urls: string[];
  onChange: (urls: string[]) => void;
}) {
  const [draft, setDraft] = useState("");

  function commit() {
    const value = draft.trim();
    if (!value) return;
    onChange([...urls, value]);
    setDraft("");
  }

  return (
    <div className="url-editor">
      {urls.length > 0 ? (
        <ul className="url-list">
          {urls.map((url, index) => (
            <li key={`${url}-${index}`} className="url-chip">
              <span className="url-chip-text">{url}</span>
              <button
                type="button"
                className="icon-btn"
                aria-label={`Remove website ${url}`}
                onClick={() => onChange(urls.filter((_, i) => i !== index))}
              >
                <X size={12} aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="block-empty">No websites yet.</p>
      )}
      <div className="url-add">
        <input
          className="input"
          value={draft}
          placeholder="https://…"
          aria-label="Add website"
          spellCheck={false}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              commit();
            }
          }}
        />
        <Button variant="secondary" size="sm" onClick={commit} disabled={!draft.trim()}>
          Add
        </Button>
      </div>
    </div>
  );
}
