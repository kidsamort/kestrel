import { useCallback, useEffect, useState } from "react";
import { api, errorText } from "../api";
import type { ItemSummary } from "../types";

const MAX_ROWS = 8;

/**
 * Debounced item search for the palette. It asks the core for one window of
 * `MAX_ROWS` hits, so a keystroke never decrypts the whole match set.
 */
export function useQuickSearch(unlocked: boolean) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [active, setActive] = useState(0);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  useEffect(() => {
    if (!unlocked) {
      setItems([]);
      return;
    }
    let cancelled = false;
    setSearching(true);
    setSearchError(null);
    const timer = window.setTimeout(
      () => {
        api
          .listPage(query, null, false, MAX_ROWS, 0)
          .then((next) => {
            if (cancelled) return;
            setItems(next.items);
            setActive(0);
          })
          .catch((failure) => {
            if (cancelled) return;
            setItems([]);
            setSearchError(errorText(failure));
          })
          .finally(() => {
            if (!cancelled) setSearching(false);
          });
      },
      query ? 110 : 0,
    );
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [unlocked, query]);

  const move = useCallback(
    (delta: number) => {
      if (items.length === 0) return;
      setActive((current) => (current + delta + items.length) % items.length);
    },
    [items.length],
  );

  /** Every appearance starts with an empty query and the first row selected. */
  const reset = useCallback(() => {
    setQuery("");
    setActive(0);
  }, []);

  /** A lock drops the results without touching the selection. */
  const clear = useCallback(() => {
    setItems([]);
    setQuery("");
  }, []);

  return {
    query,
    setQuery,
    items,
    active,
    setActive,
    searching,
    searchError,
    move,
    reset,
    clear,
  };
}
