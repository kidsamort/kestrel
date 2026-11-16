import type { ReactNode } from "react";
import { CategoryGlyph } from "./CategoryGlyph";

/** Row payload both palettes can supply: items and plain commands alike. */
export interface PaletteRowItem {
  title: string;
  /** Secondary line. Only items have one; commands pass nothing. */
  meta?: ReactNode;
  /** Item category, rendered as the standard category glyph. */
  category?: string;
  /** Explicit glyph for non-item rows (commands); wins over `category`. */
  glyph?: ReactNode;
}

/**
 * One selectable row of a search palette: glyph, title/meta copy, trailing
 * affordances and the active highlight. Both palettes share this skeleton so
 * the row geometry, hover and highlight stay identical across windows.
 */
export function PaletteRow({
  item,
  active,
  glyphSize = 16,
  id,
  dataItemId,
  onActivate,
  onSelect,
  trailing,
  activeTrailing,
  className,
}: {
  item: PaletteRowItem;
  active: boolean;
  /** Glyph box is 16 px in quick access, 15 px in the command palette. */
  glyphSize?: number;
  /** Row id referenced by the search input's `aria-activedescendant`. */
  id?: string;
  /** Item id exposed as `data-item-id` for the quick-access window. */
  dataItemId?: string;
  /** Pointer intent: moves the highlight without committing the row. */
  onActivate?: () => void;
  /** Commits the row, from a click or from Enter in the palette input. */
  onSelect: () => void;
  /** Content after the copy, always rendered. */
  trailing?: ReactNode;
  /** Content after the copy, rendered on the active row only (enter hint). */
  activeTrailing?: ReactNode;
  /** Consumer-specific row class (`qa-row`); the base look lives in CSS. */
  className?: string;
}) {
  const classes = ["palette-row", active ? "is-active" : "", className]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      id={id}
      role="option"
      aria-selected={active}
      className={classes}
      data-item-id={dataItemId}
      onMouseMove={onActivate}
      onClick={onSelect}
    >
      <span className="palette-glyph">
        {item.glyph ??
          (item.category ? (
            <CategoryGlyph category={item.category} size={glyphSize} />
          ) : null)}
      </span>
      <span className="palette-copy">
        <span className="palette-title">{item.title}</span>
        {item.meta !== undefined ? (
          <span className="palette-meta">{item.meta}</span>
        ) : null}
      </span>
      {trailing}
      {active ? activeTrailing : null}
    </div>
  );
}
