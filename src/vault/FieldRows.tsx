import { Eye, EyeOff, Plus, Trash2, Wand2 } from "lucide-react";
import {
  FIELD_KINDS,
  isMultilineField,
  isSecretField,
  isSecretKind,
} from "../lib/catalog";
import { normalizeSeedPhrase, seedWarning, seedWordCount } from "../lib/fields";
import type { Field } from "../types";
import { Tip } from "../ui/Tooltip";
import Select from "../ui/Select";
import "../styles/fields.css";

/**
 * The field list shared by the full-pane editor and the create wizard.
 *
 * One implementation on purpose: a second copy would drift, and a field row is
 * exactly the place where drift shows up as inconsistent affordances.
 */
export function FieldRows({
  fields,
  onPatch,
  onRemove,
  onAdd,
  onGenerate,
  note,
}: {
  fields: Field[];
  onPatch: (id: string, patch: Partial<Field>) => void;
  onRemove: (id: string) => void;
  onAdd: () => void;
  onGenerate: (field: Field) => void;
  note?: string;
}) {
  return (
    <>
      <div className="field-list">
        {fields.map((field) => {
          const seed = field.kind === "seedPhrase";
          const warning = seed ? seedWarning(field.value) : null;
          return (
            <div className="edit-field" key={field.id}>
              <input
                className="input edit-field-label"
                value={field.label}
                placeholder="Label"
                aria-label="Field label"
                data-field-label={field.id}
                onChange={(event) => onPatch(field.id, { label: event.target.value })}
              />
              {seed || isMultilineField(field) ? (
                <div className="field-value-stack">
                  <textarea
                    className="input edit-field-value edit-textarea"
                    data-field-value={field.id}
                    value={field.value}
                    placeholder={seed ? "Word 1 word 2 word 3 …" : "Value"}
                    aria-label={`Value for ${field.label || "field"}`}
                    rows={3}
                    spellCheck={false}
                    onChange={(event) =>
                      onPatch(field.id, {
                        // Collapse runs as they are typed or pasted, so a
                        // multi-line paste reads as one line immediately. The
                        // trailing space a typist needs is a single space, and
                        // blur trims it.
                        value: seed
                          ? event.target.value.replace(/\s+/g, " ")
                          : event.target.value,
                      })
                    }
                    onBlur={
                      seed
                        ? () =>
                            onPatch(field.id, {
                              value: normalizeSeedPhrase(field.value),
                            })
                        : undefined
                    }
                  />
                  {seed ? (
                    <span
                      className={`field-hint ${warning ? "is-warn" : ""}`}
                    >
                      {seedWordCount(field.value)} words
                      {warning ? ` · ${warning}` : ""}
                    </span>
                  ) : null}
                </div>
              ) : (
                <input
                  className={`input edit-field-value ${
                    isSecretField(field) ? "is-mono" : ""
                  }`}
                  data-field-value={field.id}
                  value={field.value}
                  placeholder="Value"
                  aria-label={`Value for ${field.label || "field"}`}
                  spellCheck={false}
                  onChange={(event) => onPatch(field.id, { value: event.target.value })}
                />
              )}
              <Select
                className="edit-field-kind"
                label={`Kind for ${field.label || "field"}`}
                value={field.kind}
                options={FIELD_KINDS.map((kind) => ({
                  value: kind.id,
                  label: kind.label,
                }))}
                onChange={(kind) => {
                  onPatch(field.id, {
                    kind,
                    // Marking is what makes the search projection skip a
                    // field; a secret kind must not depend on the flag alone.
                    ...(isSecretKind(kind) ? { sensitive: true } : {}),
                    ...(kind === "seedPhrase"
                      ? { value: normalizeSeedPhrase(field.value) }
                      : {}),
                  });
                }}
              />
              <div className="edit-field-tools">
                {isSecretField(field) && !seed ? (
                  <Tip label="Generate a password">
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Generate a password for ${field.label || "field"}`}
                      onClick={() => onGenerate(field)}
                    >
                      <Wand2 size={14} strokeWidth={1.6} aria-hidden />
                    </button>
                  </Tip>
                ) : null}
                <Tip label={field.sensitive ? "Shown masked" : "Shown in clear"}>
                  <button
                    type="button"
                    className={`icon-btn ${field.sensitive ? "is-on" : ""}`}
                    aria-pressed={field.sensitive}
                    aria-label={`${field.sensitive ? "Unmark" : "Mark"} ${
                      field.label || "field"
                    } as secret`}
                    onClick={() => onPatch(field.id, { sensitive: !field.sensitive })}
                  >
                    {field.sensitive ? (
                      <EyeOff size={14} strokeWidth={1.6} aria-hidden />
                    ) : (
                      <Eye size={14} strokeWidth={1.6} aria-hidden />
                    )}
                  </button>
                </Tip>
                <Tip label="Remove field">
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label={`Remove ${field.label || "field"}`}
                    onClick={() => onRemove(field.id)}
                  >
                    <Trash2 size={14} strokeWidth={1.6} aria-hidden />
                  </button>
                </Tip>
              </div>
            </div>
          );
        })}
      </div>
      <button type="button" className="add-field" onClick={onAdd}>
        <Plus size={13} aria-hidden /> Add field
      </button>
      {note ? <p className="edit-note">{note}</p> : null}
    </>
  );
}
