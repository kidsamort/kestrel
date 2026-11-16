import type { RefObject } from "react";
import { CircleX, Search } from "lucide-react";

/**
 * Search field portalled into the window toolbar. It owns no state: the query
 * lives in `useShellPanels`, which also focuses the input from shortcuts and
 * from tag search.
 */
export default function TitlebarSearch({
  query,
  inputRef,
  onQuery,
}: {
  query: string;
  inputRef: RefObject<HTMLInputElement | null>;
  onQuery: (query: string) => void;
}) {
  return (
    <div className="search titlebar-search-field">
      <Search size={14} strokeWidth={1.6} aria-hidden className="search-icon" />
      <input
        ref={inputRef}
        className="search-input"
        type="text"
        value={query}
        placeholder="Search titles, tags, usernames"
        aria-label="Search items"
        spellCheck={false}
        onChange={(event) => onQuery(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && query !== "") {
            event.preventDefault();
            onQuery("");
          }
        }}
      />
      {query ? (
        <button
          type="button"
          className="search-clear"
          aria-label="Clear search"
          onClick={() => {
            onQuery("");
            inputRef.current?.focus();
          }}
        >
          <CircleX size={13} strokeWidth={1.6} aria-hidden />
        </button>
      ) : null}
    </div>
  );
}
