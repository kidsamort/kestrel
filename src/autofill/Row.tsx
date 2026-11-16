import { KeyRound, UserRound } from "lucide-react";
import { secondaryText } from "../lib/catalog";
import type { ItemSummary } from "../types";
import { PaletteRow } from "../ui/PaletteRow";

/**
 * One pickable item in the overlay: the palette row plus one explicit `Fill`
 * action. The row body only selects; the button is the thing that writes.
 */
export function AutofillRow({
  item,
  active,
  isPassword,
  busy,
  onActivate,
  onFill,
}: {
  item: ItemSummary;
  active: boolean;
  isPassword: boolean;
  busy: boolean;
  onActivate: () => void;
  onFill: () => void;
}) {
  const field = isPassword ? "password" : "username";
  const Glyph = isPassword ? KeyRound : UserRound;
  return (
    <PaletteRow
      item={{
        title: item.title || "Untitled",
        meta: secondaryText(item),
        category: item.category,
      }}
      active={active}
      dataItemId={item.id}
      className="af-row"
      onActivate={onActivate}
      onSelect={onActivate}
      trailing={
        <button
          type="button"
          className="af-fill"
          data-fill={field}
          aria-label={`Fill the ${field} for ${item.title || "this item"}`}
          disabled={busy}
          onClick={(event) => {
            event.stopPropagation();
            onFill();
          }}
        >
          <Glyph size={12} strokeWidth={1.7} aria-hidden />
          {busy ? "Filling…" : `Fill ${field}`}
        </button>
      }
    />
  );
}
