import { Check, CornerDownLeft, KeyRound, UserRound } from "lucide-react";
import { secondaryText } from "../lib/catalog";
import type { ItemSummary } from "../types";
import { PaletteRow } from "../ui/PaletteRow";
import type { CopyField, CopyFlash } from "./types";

const copyLabel = (item: ItemSummary) => item.title || "this item";

/**
 * One quick-access hit: the shared palette row plus the copy affordances. The
 * copy buttons keep their own Enter/Space activation, so the body keyboard map
 * steps aside for them.
 */
export function QuickRow({
  item,
  active,
  copied,
  onActivate,
  onSelect,
  onCopy,
}: {
  item: ItemSummary;
  active: boolean;
  copied: CopyFlash | null;
  onActivate: () => void;
  onSelect: () => void;
  onCopy: (item: ItemSummary, field: CopyField) => void;
}) {
  return (
    <PaletteRow
      item={{
        title: item.title || "Untitled",
        meta: secondaryText(item),
        category: item.category,
      }}
      active={active}
      dataItemId={item.id}
      className="qa-row"
      onActivate={onActivate}
      onSelect={onSelect}
      trailing={
        <span className="qa-actions">
          {item.username ? (
            <button
              type="button"
              data-copy="username"
              className="icon-btn"
              title="Copy username"
              aria-label={`Copy the username for ${copyLabel(item)}`}
              onClick={(event) => {
                event.stopPropagation();
                onCopy(item, "username");
              }}
            >
              {copied?.itemId === item.id && copied.field === "username" ? (
                <Check size={13} className="copy-done" aria-hidden="true" />
              ) : (
                <UserRound size={13} strokeWidth={1.6} aria-hidden="true" />
              )}
            </button>
          ) : null}
          <button
            type="button"
            data-copy="password"
            className="icon-btn"
            title="Copy password"
            aria-label={`Copy the password for ${copyLabel(item)}`}
            onClick={(event) => {
              event.stopPropagation();
              onCopy(item, "password");
            }}
          >
            {copied?.itemId === item.id && copied.field === "password" ? (
              <Check size={13} className="copy-done" aria-hidden="true" />
            ) : (
              <KeyRound size={13} strokeWidth={1.6} aria-hidden="true" />
            )}
          </button>
        </span>
      }
      activeTrailing={
        <CornerDownLeft
          size={12}
          strokeWidth={1.6}
          className="palette-enter"
          aria-hidden="true"
        />
      }
    />
  );
}
