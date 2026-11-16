import { useCallback, useEffect, useRef, useState } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { errorText } from "../api";
import {
  autofill,
  onAutofillTarget,
  onVaultLocked,
  type AutofillSuggest,
  type AutofillTarget,
} from "../lib/api-autofill";
import type { ItemSummary } from "../types";

const EMPTY: AutofillSuggest = { recent: [], matches: [] };

/**
 * Window state for the overlay: the target the shell pushed, the rows for the
 * search query, and the explicit fill action.
 *
 * The target arrives twice on purpose — once from `autofill_target` on mount
 * (the overlay is built after the focus event), and then from the
 * `autofill://target` event for every later field. Both are descriptions; a
 * value never arrives here.
 */
export function useAutofill() {
  const [target, setTarget] = useState<AutofillTarget | null>(null);
  const [locked, setLocked] = useState(false);
  const [bootError, setBootError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [suggest, setSuggest] = useState<AutofillSuggest>(EMPTY);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [fillError, setFillError] = useState<string | null>(null);
  const [filling, setFilling] = useState<string | null>(null);
  const [active, setActive] = useState(0);

  /** Set when Windows refused to give the overlay keyboard focus. */
  const [inputHint, setInputHint] = useState<string | null>(null);
  const activated = useRef(false);

  useEffect(() => {
    let live = true;
    const stops: UnlistenFn[] = [];
    const keep = (stop: UnlistenFn) => {
      if (live) stops.push(stop);
      else stop();
    };

    autofill
      .target()
      .then((value) => {
        if (live && value) setTarget(value);
      })
      .catch((failure) => {
        if (live) setBootError(errorText(failure));
      });

    void onAutofillTarget((value) => {
      if (!live) return;
      // Each appearance needs a new activation: focus was lost when the
      // previous one closed, even though this webview stayed alive.
      activated.current = false;
      setInputHint(null);
      setTarget(value);
      setQuery("");
      setActive(0);
      setFillError(null);
      setSearchError(null);
    }).then(keep);

    void onVaultLocked(() => {
      if (live) setLocked(true);
    }).then(keep);

    return () => {
      live = false;
      for (const stop of stops) stop();
    };
  }, []);

  // One query window of hits, debounced like the palette. A refusal or a
  // locked vault has no rows to fetch.
  useEffect(() => {
    if (!target || target.refused || locked) {
      setSuggest(EMPTY);
      return;
    }
    let cancelled = false;
    setSearching(true);
    setSearchError(null);
    const timer = window.setTimeout(
      () => {
        autofill
          .suggest(query)
          .then((value) => {
            if (cancelled) return;
            setSuggest(value);
            setActive(0);
          })
          .catch((failure) => {
            if (cancelled) return;
            setSuggest(EMPTY);
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
  }, [target, query, locked]);

  /** Ask Windows to activate the overlay for typing, once per appearance. */
  const takeInput = useCallback(() => {
    if (activated.current) return;
    activated.current = true;
    autofill
      .takeInput()
      .then(() => setInputHint(null))
      .catch((failure) => {
        activated.current = false;
        setInputHint(errorText(failure));
      });
  }, []);

  const fill = useCallback(
    async (item: ItemSummary) => {
      if (!target || target.refused) return;
      const field = target.isPassword ? "password" : "username";
      setFilling(item.id);
      setFillError(null);
      try {
        await autofill.fill(item.id, field);
      } catch (failure) {
        setFillError(errorText(failure));
        setFilling(null);
      }
    },
    [target],
  );

  const move = useCallback(
    (delta: number, length: number) => {
      if (length === 0) return;
      setActive((current) => (current + delta + length) % length);
    },
    [],
  );

  return {
    target,
    locked,
    bootError,
    query,
    setQuery,
    suggest,
    searching,
    searchError,
    fillError,
    filling,
    active,
    setActive,
    move,
    fill,
    takeInput,
    inputHint,
  };
}
