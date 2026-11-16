import { useCallback, useEffect, useMemo, useRef } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { CircleAlert, Lock, Search, ShieldAlert } from "lucide-react";
import { autofill } from "../lib/api-autofill";
import type { ItemSummary } from "../types";
import { Kbd } from "../ui/Kbd";
import { AutofillRow } from "./Row";
import { useAutofill } from "./useAutofill";

interface GroupedRow {
  item: ItemSummary;
  group: "recent" | "matches";
}

const FIELD_LABEL = "Search items";

/**
 * The overlay surface. It is a picker, not an automatic filler: every write is
 * the `Fill` button on a row (or Enter on the selected row).
 *
 * The window is `WS_EX_NOACTIVATE`, so it appears without taking focus from
 * the application. Typing needs an explicit activation: the first pointer
 * press asks the shell for input focus (`autofill_take_input`).
 */
export default function Overlay() {
  const {
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
  } = useAutofill();
  const searchRef = useRef<HTMLInputElement | null>(null);

  // Rows: recents only make sense for an empty query, and an item that is both
  // recent and a hit is listed once (in the recent group).
  const rows = useMemo<GroupedRow[]>(() => {
    const seen = new Set<string>();
    const out: GroupedRow[] = [];
    if (!query) {
      for (const item of suggest.recent) {
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        out.push({ item, group: "recent" });
      }
    }
    for (const item of suggest.matches) {
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      out.push({ item, group: "matches" });
    }
    return out;
  }, [query, suggest]);

  // Escape closes. The Rust side also swallows Escape while the picker is
  // visible, so this works even before the webview has keyboard focus.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        void autofill.dismiss();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Losing activation hides the overlay. The shell's foreground hook covers
  // the same case; this keeps the surface honest if the webview is blurred
  // without a foreground change.
  useEffect(() => {
    const onBlur = () => {
      void autofill.dismiss();
    };
    window.addEventListener("blur", onBlur);
    return () => window.removeEventListener("blur", onBlur);
  }, []);

  const activate = useCallback(() => {
    takeInput();
    // DOM focus is not enough for typing; it follows the activation request.
    searchRef.current?.focus();
  }, [takeInput]);

  const commit = (item: ItemSummary) => {
    void fill(item);
  };

  const onSearchKey = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1, rows.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1, rows.length);
    } else if (event.key === "Enter" && rows[active]) {
      event.preventDefault();
      commit(rows[active].item);
    }
  };

  const exe = target?.exe ?? "";

  return (
    <div className="af" onPointerDown={activate}>
      <div className="palette-input-row af-search">
        <span className="palette-icon" aria-hidden="true">
          <Search size={15} strokeWidth={1.6} />
        </span>
        <input
          ref={searchRef}
          className="palette-input"
          type="text"
          role="combobox"
          aria-expanded={rows.length > 0}
          aria-controls="autofill-results"
          aria-autocomplete="list"
          aria-label={FIELD_LABEL}
          placeholder={exe ? `Search for ${exe}` : "Search the vault"}
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={onSearchKey}
          // The window cannot be typed into until the shell activates it.
          onFocus={activate}
        />
        <Kbd>Esc</Kbd>
      </div>

      <div
        className="af-body palette-results"
        id="autofill-results"
        role="listbox"
        aria-label="Items to fill"
      >
        {searching && rows.length > 0 ? (
          <div className="list-progress" aria-hidden="true" />
        ) : null}

        {target?.refused ? (
          <div className="af-notice" role="alert">
            <ShieldAlert size={16} strokeWidth={1.6} aria-hidden />
            <div>
              <p className="af-notice-title">Autofill refused</p>
              <p>{target.refused}</p>
              {exe ? <p className="af-notice-sub">Window: {exe}</p> : null}
            </div>
          </div>
        ) : locked ? (
          <div className="af-notice" role="alert">
            <Lock size={16} strokeWidth={1.6} aria-hidden />
            <div>
              <p className="af-notice-title">The vault is locked</p>
              <p>Unlock Kestrel in the main window, then open the picker again.</p>
            </div>
          </div>
        ) : bootError ? (
          <div className="af-notice" role="alert">
            <CircleAlert size={16} strokeWidth={1.6} aria-hidden />
            <div>
              <p className="af-notice-title">The picker is unavailable</p>
              <p>{bootError}</p>
            </div>
          </div>
        ) : searchError ? (
          <div className="af-notice" role="alert">
            <CircleAlert size={16} strokeWidth={1.6} aria-hidden />
            <div>
              <p className="af-notice-title">Could not load items</p>
              <p>{searchError}</p>
            </div>
          </div>
        ) : rows.length === 0 ? (
          <div className="palette-empty af-empty" role="status">
            {searching
              ? "Searching…"
              : query
                ? "No items match."
                : "No items to fill yet."}
          </div>
        ) : (
          rows.map(({ item, group }, index) => {
            const previous = index > 0 ? rows[index - 1].group : null;
            return (
              <div key={item.id} className="af-group-item">
                {group !== previous ? (
                  <div className="palette-group-label af-group-label">
                    {group === "recent" ? `Recent in ${exe}` : "Items"}
                  </div>
                ) : null}
                <AutofillRow
                  item={item}
                  active={index === active}
                  isPassword={target?.isPassword ?? false}
                  busy={filling === item.id}
                  onActivate={() => setActive(index)}
                  onFill={() => commit(item)}
                />
              </div>
            );
          })
        )}
      </div>

      <div className="palette-foot af-foot">
        <span className="af-foot-app" title={target?.automationId || undefined}>
          {exe || "No window"}
          {target ? ` · ${target.controlType}` : ""}
        </span>
        <span className="af-foot-note" role="status" aria-live="polite">
          {fillError ? (
            <>
              <CircleAlert size={11} strokeWidth={1.6} aria-hidden />
              {fillError}
            </>
          ) : inputHint ? (
            inputHint
          ) : (
            <>Nothing is written until you press Fill.</>
          )}
        </span>
        <span className="af-foot-keys">
          <Kbd>Enter</Kbd> fill
        </span>
      </div>
    </div>
  );
}
