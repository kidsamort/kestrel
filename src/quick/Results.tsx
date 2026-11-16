import { CircleAlert, Search } from "lucide-react";
import type { ItemSummary } from "../types";
import { EmptyState } from "../ui/EmptyState";
import { QuickRow } from "./Row";
import type { CopyField, CopyFlash } from "./types";

/**
 * The palette's listbox: progress hairline, error, skeleton and empty states,
 * then one `QuickRow` per hit with roving selection.
 */
export function QuickResults({
  items,
  active,
  query,
  searching,
  searchError,
  copied,
  onActivate,
  onSelect,
  onCopy,
}: {
  items: ItemSummary[];
  active: number;
  query: string;
  searching: boolean;
  searchError: string | null;
  copied: CopyFlash | null;
  onActivate: (index: number) => void;
  onSelect: (id: string) => void;
  onCopy: (item: ItemSummary, field: CopyField) => void;
}) {
  return (
    <div
      className="palette-results qa-results"
      id="quick-results"
      role="listbox"
      aria-label="Matching items"
    >
      {searching && items.length > 0 ? (
        <div className="list-progress" aria-hidden="true" />
      ) : null}

      {searchError ? (
        <div className="palette-empty qa-empty" role="alert">
          <CircleAlert size={13} strokeWidth={1.6} aria-hidden />
          {searchError}
        </div>
      ) : searching && items.length === 0 ? (
        <div className="qa-skeletons" aria-busy="true" aria-label="Searching">
          {[0, 1, 2].map((n) => (
            <div
              className="row-skeleton"
              key={n}
              style={{ opacity: 1 - n * 0.2 }}
            />
          ))}
        </div>
      ) : items.length === 0 ? (
        query ? (
          <EmptyState
            variant="no-match"
            query={query}
            className="qa-empty-state"
            glyphSize={16}
          />
        ) : (
          <EmptyState
            variant="empty-vault"
            className="qa-empty-state"
            glyph={<Search size={16} strokeWidth={1.4} />}
            secondary={
              <>
                Add your first login in the main window; it appears here the
                moment it is saved.
              </>
            }
          />
        )
      ) : (
        items.map((item, index) => (
          <QuickRow
            key={item.id}
            item={item}
            active={index === active}
            copied={copied}
            onActivate={() => onActivate(index)}
            onSelect={() => onSelect(item.id)}
            onCopy={onCopy}
          />
        ))
      )}
    </div>
  );
}
