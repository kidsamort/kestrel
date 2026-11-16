import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Check } from "lucide-react";
import { api, errorText } from "../api";
import { metaFor } from "../lib/catalog";
import type { Category, Item } from "../types";
import { CATEGORIES } from "../types";
import { Button } from "../ui/Button";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { TextArea, TextField } from "../ui/Input";
import { Dialog } from "../ui/Overlay";
import { useNotify } from "../ui/Toast";
import { FieldRows } from "./FieldRows";
import { GeneratorPanel } from "./GeneratorPanel";

type Step = "category" | "fields" | "review";

const STEP_LABEL: Record<Step, string> = {
  category: "Choose a type",
  fields: "Fill in the details",
  review: "Review and save",
};

const STEP_ORDER: Step[] = ["category", "fields", "review"];

/**
 * Three-step creation flow: pick a category, fill it, confirm.
 *
 * The category step calls `create_item`, so the field template comes from the
 * Rust core instead of a second copy in TypeScript. That call returns a draft
 * the core has not stored, so a cancelled wizard leaves nothing behind and
 * needs no compensating delete.
 */
export default function NewItemWizard({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (item: Item) => void;
}) {
  const notify = useNotify();
  const [step, setStep] = useState<Step>("category");
  const [draft, setDraft] = useState<Item | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [genFor, setGenFor] = useState<string | null>(null);
  // Reset whenever the dialog is opened; a closed wizard owns nothing.
  useEffect(() => {
    if (open) {
      setStep("category");
      setDraft(null);
      setError(null);
      setBusy(false);
      setGenFor(null);
    }
  }, [open]);

  const close = useCallback(
    (next: boolean) => {
      onOpenChange(next);
    },
    [onOpenChange],
  );

  const pickCategory = (category: Category) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    api
      .createItem(category)
      .then((created) => {
        setDraft(created);
        setStep("fields");
      })
      .catch((problem) => setError(errorText(problem)))
      .finally(() => setBusy(false));
  };

  const patch = (next: Partial<Item>) =>
    setDraft((current) => (current ? { ...current, ...next } : current));

  const patchField = (id: string, values: Partial<Item["fields"][number]>) =>
    setDraft((current) =>
      current
        ? {
            ...current,
            fields: current.fields.map((field) =>
              field.id === id ? { ...field, ...values } : field,
            ),
          }
        : current,
    );

  const save = () => {
    if (!draft || busy) return;
    setBusy(true);
    setError(null);
    const title = draft.title.trim();
    api
      .save({
        ...draft,
        title: title === "" ? metaFor(draft.category).noun : title,
        urls: draft.urls.map((url) => url.trim()).filter(Boolean),
        tags: draft.tags.map((tag) => tag.trim()).filter(Boolean),
        totpSecret: draft.totpSecret?.trim() ? draft.totpSecret.trim() : undefined,
      })
      .then((saved) => {
        setDraft(null);
        onCreated(saved);
        onOpenChange(false);
        notify("Item created", { detail: saved.title });
      })
      .catch((problem) => setError(errorText(problem)))
      .finally(() => setBusy(false));
  };

  const filledFields = draft
    ? draft.fields.filter((field) => field.value.trim() !== "").length
    : 0;
  const canAdvance = draft !== null && draft.title.trim() !== "";

  const footer =
    step === "category" ? (
      <Button variant="ghost" size="sm" onClick={() => close(false)}>
        Cancel
      </Button>
    ) : step === "fields" ? (
      <>
        <Button
          variant="ghost"
          size="sm"
          leading={<ArrowLeft size={13} aria-hidden />}
          onClick={() => setStep("category")}
        >
          Back
        </Button>
        <Button
          variant="primary"
          size="sm"
          disabled={!canAdvance}
          onClick={() => setStep("review")}
        >
          Review
        </Button>
      </>
    ) : (
      <>
        <Button
          variant="ghost"
          size="sm"
          leading={<ArrowLeft size={13} aria-hidden />}
          onClick={() => setStep("fields")}
        >
          Back
        </Button>
        <Button variant="primary" size="sm" disabled={busy} onClick={save}>
          {busy ? "Saving…" : "Save item"}
        </Button>
      </>
    );

  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title="New item"
      description={STEP_LABEL[step]}
      width={620}
      footer={footer}
    >
      <ol className="wizard-steps" aria-label="Progress">
        {STEP_ORDER.map((name, index) => (
          <li
            key={name}
            className={`wizard-step ${
              name === step ? "is-current" : STEP_ORDER.indexOf(step) > index ? "is-done" : ""
            }`}
            aria-current={name === step ? "step" : undefined}
          >
            <span className="wizard-dot" aria-hidden>
              {STEP_ORDER.indexOf(step) > index ? <Check size={10} /> : index + 1}
            </span>
            {name === "category" ? "Type" : name === "fields" ? "Details" : "Review"}
          </li>
        ))}
      </ol>

      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}

      {step === "category" ? (
        <div className="wizard-grid" role="group" aria-label="Item type">
          {CATEGORIES.map((category) => (
            <button
              key={category.id}
              type="button"
              className="wizard-cat"
              onClick={() => pickCategory(category.id)}
              disabled={busy}
            >
              <span className="wizard-cat-glyph" aria-hidden>
                <CategoryGlyph category={category.id} size={16} />
              </span>
              <span className="wizard-cat-name">{metaFor(category.id).noun}</span>
            </button>
          ))}
        </div>
      ) : null}

      {step === "fields" && draft ? (
        <div className="wizard-form">
          <TextField
            label="Title"
            autoFocus
            value={draft.title}
            placeholder={metaFor(draft.category).noun}
            onChange={(event) => patch({ title: event.target.value })}
          />
          <div className="wizard-block">
            <h3 className="block-title">Fields</h3>
            <FieldRows
              fields={draft.fields}
              onPatch={patchField}
              onRemove={(id) =>
                patch({ fields: draft.fields.filter((field) => field.id !== id) })
              }
              onAdd={() =>
                patch({
                  fields: [
                    ...draft.fields,
                    {
                      id: crypto.randomUUID(),
                      label: "field",
                      kind: "text",
                      value: "",
                      sensitive: false,
                    },
                  ],
                })
              }
              onGenerate={(field) => setGenFor(field.id)}
            />
          </div>
          <div className="wizard-block">
            <h3 className="block-title">Notes</h3>
            <TextArea
              label="Notes"
              quietLabel
              rows={3}
              value={draft.notes}
              placeholder="Optional context that travels with this item."
              onChange={(event) => patch({ notes: event.target.value })}
            />
          </div>
        </div>
      ) : null}

      {step === "review" && draft ? (
        <dl className="wizard-review">
          <div>
            <dt>Type</dt>
            <dd>
              <span className="wizard-cat-glyph" aria-hidden>
                <CategoryGlyph category={draft.category} size={14} />
              </span>
              {metaFor(draft.category).noun}
            </dd>
          </div>
          <div>
            <dt>Title</dt>
            <dd>{draft.title.trim() || metaFor(draft.category).noun}</dd>
          </div>
          <div>
            <dt>Fields</dt>
            <dd>
              {filledFields} of {draft.fields.length} filled
            </dd>
          </div>
          <div>
            <dt>Notes</dt>
            <dd>{draft.notes.trim() ? `${draft.notes.trim().length} characters` : "—"}</dd>
          </div>
          <div>
            <dt>Stored</dt>
            <dd>Encrypted with the vault key (XChaCha20-Poly1305)</dd>
          </div>
        </dl>
      ) : null}

      {genFor ? (
        <GeneratorPanel
          variant="dialog"
          onUse={(value) => {
            patchField(genFor, { value, sensitive: true, kind: "password" });
            setGenFor(null);
          }}
        />
      ) : null}
    </Dialog>
  );
}
