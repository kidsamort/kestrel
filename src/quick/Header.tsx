import type { RefObject } from "react";
import { Search } from "lucide-react";
import { Kbd } from "../ui/Kbd";

/**
 * The palette's search field: combobox semantics wired to the results listbox
 * and the `Esc` hint the window listens for.
 */
export function QuickHeader({
  searchRef,
  query,
  hasResults,
  onQueryChange,
}: {
  searchRef: RefObject<HTMLInputElement | null>;
  query: string;
  hasResults: boolean;
  onQueryChange: (value: string) => void;
}) {
  return (
    <div className="palette-input-row qa-search-row">
      <span className="palette-icon" aria-hidden="true">
        <Search size={15} strokeWidth={1.6} />
      </span>
      <input
        ref={searchRef}
        className="palette-input"
        type="text"
        role="combobox"
        aria-expanded={hasResults}
        aria-controls="quick-results"
        aria-autocomplete="list"
        aria-label="Search the vault"
        placeholder="Search the vault"
        autoComplete="off"
        spellCheck={false}
        value={query}
        onChange={(event) => onQueryChange(event.target.value)}
      />
      <Kbd>Esc</Kbd>
    </div>
  );
}
