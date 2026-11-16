import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { errorText } from "../../api";
import { quick as quickApi } from "../../lib/api-quick";
import { SYNC_VIEW_EVENT } from "../../lib/api-sync";
import { ALL_FILTER, type Filter, type Panel, type Sort } from "../../lib/navigation";
import {
  resolveShellShortcut,
  runShellShortcut,
  type ShortcutHandlers,
} from "./hotkeys";
import type { Notify } from "./notify";
import type { ShellSession } from "./session";

export interface ShellPanelsOptions {
  session: RefObject<ShellSession | null>;
  notify: Notify;
}

/**
 * Navigation state of the shell: what the sidebar and list show, what the
 * toolbar search contains, which pane or overlay is open, and the keyboard map
 * that drives all of it.
 */
export function useShellPanels({ session, notify }: ShellPanelsOptions) {
  const [filter, setFilter] = useState<Filter>(ALL_FILTER);
  const [panel, setPanel] = useState<Panel>("vault");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [sort, setSort] = useState<Sort>("title");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [compact, setCompact] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  /** True while a filter change is waiting for its list to load (U4). */
  const filterCheckPending = useRef(false);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 1080px)");
    const apply = () => setCompact(media.matches);
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query), 130);
    return () => window.clearTimeout(timer);
  }, [query]);

  /** Run through the session guard; with no session mounted nothing is dirty. */
  const guarded = useCallback(
    (action: () => void) => (session.current ? session.current.guard(action) : action()),
    [session],
  );

  const applyFilter = useCallback(
    (next: Filter) => {
      guarded(() => {
        setPanel("vault");
        setFilter(next);
        if (next.mode === "all") setQuery("");
        session.current?.resetEditor();
        // Whether the selected item survives is only known once the filtered
        // list has loaded, so the decision moves to that response.
        filterCheckPending.current = true;
      });
    },
    [guarded, session],
  );

  const openPanel = useCallback(
    (next: Panel) => {
      guarded(() => {
        setPanel(next);
        session.current?.closeHistory();
        session.current?.resetEditor();
      });
    },
    [guarded, session],
  );

  const searchTag = useCallback((tag: string) => {
    setFilter({ mode: "all" });
    setQuery(tag);
    setPanel("vault");
    requestAnimationFrame(() => searchRef.current?.focus());
  }, []);

  const handlers = useMemo<ShortcutHandlers>(
    () => ({
      openPalette: () => {
        quickApi
          .open()
          .catch((error) =>
            notify("Could not open the palette", {
              detail: errorText(error),
              tone: "danger",
            }),
          );
      },
      togglePalette: () => setPaletteOpen((open) => !open),
      lock: () => session.current?.lock(),
      focusSearch: () => {
        setPanel("vault");
        requestAnimationFrame(() => {
          searchRef.current?.focus();
          searchRef.current?.select();
        });
      },
      createItem: () => session.current?.createItem("login"),
      editSelected: () => session.current?.editSelected(),
      openPanel,
      applyFilter,
    }),
    [applyFilter, notify, openPanel, session],
  );

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const shortcut = resolveShellShortcut({
        key: event.key,
        mod: event.ctrlKey || event.metaKey,
        shift: event.shiftKey,
        dialogOpen:
          document.querySelector("[role='dialog'], [role='alertdialog']") !==
          null,
        paletteOpen,
        hasSelection: session.current?.selectedId != null,
      });
      if (!shortcut) return;
      event.preventDefault();
      runShellShortcut(shortcut, handlers);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handlers, paletteOpen, session]);

  // The window bar renders outside this hook, so the sync pill cannot call
  // `openPanel` itself; it leaves a request on the window instead.
  useEffect(() => {
    const open = () => openPanel("settings");
    window.addEventListener(SYNC_VIEW_EVENT, open);
    return () => window.removeEventListener(SYNC_VIEW_EVENT, open);
  }, [openPanel]);

  return {
    filter,
    panel,
    query,
    debouncedQuery,
    sort,
    setPanel,
    setFilter,
    setQuery,
    setSort,
    wizardOpen,
    setWizardOpen,
    paletteOpen,
    setPaletteOpen,
    compact,
    applyFilter,
    openPanel,
    searchTag,
    searchRef,
    filterCheckPending,
  };
}
