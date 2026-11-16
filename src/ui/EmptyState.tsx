import type { ReactNode } from "react";
import { Search } from "lucide-react";
import { Button } from "./Button";
import { CategoryGlyph } from "./CategoryGlyph";

const NO_MATCH_COPY =
  "Search reads titles, tags, websites and non-secret fields. Secret values are never searched.";

type EmptyStateProps = {
  /** Which agreed-on empty message to show. */
  variant: "no-match" | "empty-vault";
  /** Search term, interpolated into the no-match heading. */
  query?: string;
  /** Renders the “Clear search” action; no-match only. */
  onClear?: () => void;
  /**
   * Body copy. Defaults to the agreed search explanation for `no-match`; every
   * `empty-vault` caller supplies its own, because the two windows promise
   * different next steps.
   */
  secondary?: ReactNode;
  /** Glyph inside the framed square; defaults per variant. */
  glyph?: ReactNode;
  /** Trailing actions, e.g. the “Add a login” pair. */
  actions?: ReactNode;
  /** Glyph size; the frame is fixed, the icon differs by window. */
  glyphSize?: number;
  /** Container class: the owning surface owns padding and width. */
  className?: string;
};

/**
 * Empty list state shared by the main item list and the quick-access window.
 * Heading text is part of the agreed design, so it lives here rather than at
 * the call sites.
 */
export function EmptyState({
  variant,
  query = "",
  onClear,
  secondary,
  glyph,
  actions,
  glyphSize = 18,
  className = "list-empty",
}: EmptyStateProps) {
  const noMatch = variant === "no-match";
  const heading = noMatch
    ? `Nothing matches “${query}”.`
    : "The vault is empty.";
  const body = secondary ?? (noMatch ? NO_MATCH_COPY : null);
  const leading =
    glyph ??
    (noMatch ? (
      <Search size={glyphSize} strokeWidth={1.4} />
    ) : (
      <CategoryGlyph category="login" size={glyphSize} />
    ));

  return (
    <div className={className}>
      <span className="list-empty-glyph" aria-hidden="true">
        {leading}
      </span>
      <h2 className="empty-title">{heading}</h2>
      {body ? <p className="empty-copy">{body}</p> : null}
      {actions ??
        (noMatch && onClear ? (
          <Button variant="secondary" size="sm" onClick={onClear}>
            Clear search
          </Button>
        ) : null)}
    </div>
  );
}
