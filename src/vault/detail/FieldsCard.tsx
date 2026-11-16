import { useEffect, useState } from "react";
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  Globe,
  LockKeyhole,
  UserRound,
} from "lucide-react";
import { isMultilineField, isSecretField } from "../../lib/catalog";
import type { CopyApi } from "../../lib/copy";
import { expiryHint, seedWordCount, seedWordCountOk } from "../../lib/fields";
import { formatCardNumber, maskSecret } from "../../lib/format";
import type { Field } from "../../types";
import { Tip } from "../../ui/Tooltip";
import "../../styles/fields.css";

export default function FieldsCard({
  itemId,
  fields,
  copiedKey,
  onCopy,
}: {
  itemId: string;
  fields: Field[];
  copiedKey: string | null;
  onCopy: CopyApi["copyField"];
}) {
  const [revealed, setRevealed] = useState<Record<string, true>>({});

  useEffect(() => {
    setRevealed({});
  }, [itemId]);

  // Secrets hide when the window loses attention, without a timer to get wrong.
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

  return (
    <section className="block">
      <h2 className="block-title">Details</h2>
      {fields.length === 0 ? (
        <p className="block-empty">
          This category has no default fields. Add whatever you need with
          Edit.
        </p>
      ) : (
        <div className="field-table">
          {fields
            .filter((field) => !(field.kind === "url" && !field.value))
            .map((field) => (
            <FieldRow
              key={field.id}
              field={field}
              itemId={itemId}
              revealed={Boolean(revealed[field.id])}
              copied={copiedKey === `field:${field.id}`}
              onToggleReveal={() =>
                setRevealed((current) => {
                  const next = { ...current };
                  if (next[field.id]) delete next[field.id];
                  else next[field.id] = true;
                  return next;
                })
              }
              onCopy={onCopy}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function FieldRow({
  field,
  itemId,
  revealed,
  copied,
  onToggleReveal,
  onCopy,
}: {
  field: Field;
  itemId: string;
  revealed: boolean;
  copied: boolean;
  onToggleReveal: () => void;
  onCopy: CopyApi["copyField"];
}) {
  const secret = isSecretField(field);
  const multiline = isMultilineField(field);
  const card = field.kind === "creditCardNumber";
  const seed = field.kind === "seedPhrase";
  const empty = field.value.length === 0;
  const words = seed ? seedWordCount(field.value) : 0;
  const hint =
    field.kind === "date" && !empty
      ? expiryHint(field.value, field.label)
      : null;

  let display = field.value;
  if (secret && !revealed) display = maskSecret(field.value);
  else if (card) display = formatCardNumber(field.value);

  return (
    <div
      className={`field-row ${multiline ? "is-multiline" : ""} ${
        seed ? "is-seed" : ""
      }`}
    >
      <div className="field-row-label">
        {field.kind === "username" ? <UserRound size={12} aria-hidden /> : null}
        {field.kind === "url" ? <Globe size={12} aria-hidden /> : null}
        {secret ? <LockKeyhole size={12} aria-hidden /> : null}
        <span>{field.label}</span>
        {seed && words > 0 ? (
          <span
            className={`field-tag ${
              seedWordCountOk(field.value) ? "" : "is-warn"
            }`}
            title={
              seedWordCountOk(field.value)
                ? "A standard seed phrase length"
                : "Not 12, 15, 18, 21 or 24 words"
            }
          >
            {words} words
          </span>
        ) : null}
      </div>
      <div
        className={`field-row-value ${empty ? "is-empty" : ""} ${
          secret || multiline ? "is-mono" : ""
        } ${secret && !revealed ? "is-masked" : ""}`}
        aria-label={empty ? `${field.label}: not set` : undefined}
      >
        {empty ? "—" : display}
        {hint ? (
          <span
            className={`field-hint ${hint.startsWith("expired") ? "is-expired" : ""}`}
          >
            {hint}
          </span>
        ) : null}
      </div>
      <div className="field-row-actions">
        {secret && !empty ? (
          <Tip label={revealed ? "Hide value" : "Reveal value"}>
            <button
              type="button"
              className="icon-btn"
              onClick={onToggleReveal}
              aria-label={revealed ? `Hide ${field.label}` : `Reveal ${field.label}`}
              aria-pressed={revealed}
            >
              {revealed ? (
                <EyeOff size={14} strokeWidth={1.6} aria-hidden />
              ) : (
                <Eye size={14} strokeWidth={1.6} aria-hidden />
              )}
            </button>
          </Tip>
        ) : null}
        {!empty ? (
          <Tip label={`Copy ${field.label}`}>
            <button
              type="button"
              className="icon-btn"
              aria-label={`Copy ${field.label}`}
              onClick={() => onCopy(itemId, field.id, field.label)}
            >
              {copied ? (
                <Check size={14} className="copy-done" aria-hidden />
              ) : (
                <Copy size={14} strokeWidth={1.6} aria-hidden />
              )}
            </button>
          </Tip>
        ) : null}
      </div>
    </div>
  );
}
