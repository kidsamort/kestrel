import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorText } from "../../api";
import type { Filter, Sort } from "../../lib/navigation";
import type { Counts, ItemSummary } from "../../types";
import type { Notify } from "./notify";

export interface VaultDataOptions {
  /** Committed filter; drives the visible list. */
  filter: Filter;
  /** Debounced search text. */
  debouncedQuery: string;
  sort: Sort;
  notify: Notify;
  /**
   * Set by a filter change and consumed by the list response. Reset here on a
   * failed request: a failure cannot answer the check, and a stale flag would
   * surprise the next successful load with an old decision.
   */
  filterCheckPending: { current: boolean };
}

/**
 * Everything the shell reads from the core: the filtered list, the whole-vault
 * overview, the sidebar counters, and the version counter every action bumps
 * to re-read them.
 */
export function useVaultData({
  filter,
  debouncedQuery,
  sort,
  notify,
  filterCheckPending,
}: VaultDataOptions) {
  const [summaries, setSummaries] = useState<ItemSummary[]>([]);
  const [allItems, setAllItems] = useState<ItemSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);
  const [counts, setCounts] = useState<Counts | null>(null);
  /** Version number whose overview (sidebar) failure was already reported. */
  const overviewReported = useRef<number | null>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    api
      .list(
        debouncedQuery,
        filter.mode === "category" ? filter.category : null,
        filter.mode === "favorites",
      )
      .then((rows) => {
        if (live) setSummaries(rows);
      })
      .catch((error) => {
        if (!live) return;
        // The check cannot be answered by a failed request; drop it instead of
        // surprising a later list load with a stale decision.
        filterCheckPending.current = false;
        setSummaries([]);
        notify("Could not read the item list", {
          detail: errorText(error),
          tone: "danger",
        });
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [debouncedQuery, filter, filterCheckPending, notify, version]);

  useEffect(() => {
    let live = true;
    api
      .list("", null, false)
      .then((rows) => {
        if (live) setAllItems(rows);
      })
      .catch((error) => {
        if (!live) return;
        // One report per data version: both overview queries fail together
        // when the core is gone, and stacking two toasts per refresh is noise.
        if (overviewReported.current === version) return;
        overviewReported.current = version;
        notify("Could not read the vault overview", {
          detail: errorText(error),
          tone: "danger",
        });
      });
    return () => {
      live = false;
    };
  }, [notify, version]);

  useEffect(() => {
    let live = true;
    api
      .counts()
      .then((next) => {
        if (live) setCounts(next);
      })
      .catch((error) => {
        if (!live) return;
        if (overviewReported.current === version) return;
        overviewReported.current = version;
        notify("Could not read the vault overview", {
          detail: errorText(error),
          tone: "danger",
        });
      });
    return () => {
      live = false;
    };
  }, [notify, version]);

  const refresh = useCallback(() => setVersion((value) => value + 1), []);

  const sorted = useMemo(() => {
    if (sort === "title") return summaries;
    return [...summaries].sort((a, b) => b.updatedAt - a.updatedAt);
  }, [summaries, sort]);

  return {
    summaries,
    sorted,
    allItems,
    loading,
    version,
    refresh,
    counts,
  };
}
