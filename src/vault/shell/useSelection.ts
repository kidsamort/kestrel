import {
  useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState,
} from "react";
import { api, errorText } from "../../api";
import { trashApi } from "../../lib/api-trash";
import { ALL_FILTER, type Filter, type Panel } from "../../lib/navigation";
import type { Category, Item, ItemSummary } from "../../types";
import { resolveFilterSelection } from "./logic";
import type { Notify } from "./notify";
import type { ShellSession } from "./session";
import {
  CLOSED_EDITOR, NO_SELECTION, type EditorSession, type SelectionSnapshot,
} from "./selection-state";

export interface SelectionOptions {
  /** Pane currently shown; the one-shot auto-select only fires on `vault`. */
  panel: Panel;
  version: number;
  summaries: ItemSummary[];
  filterCheckPending: { current: boolean };
  notify: Notify;
  refresh: () => void;
  setPanel: (panel: Panel) => void;
  setFilter: (filter: Filter) => void;
  setQuery: (query: string) => void;
  onLock: () => void;
}

/**
 * The open item and its editing session: which row is selected, whether the
 * editor holds unsaved edits, and the guard every navigation must pass before
 * it can throw that editor away.
 */
export function useSelection(options: SelectionOptions) {
  const { panel, version, summaries, filterCheckPending, notify, refresh,
    setPanel, setFilter, setQuery, onLock } = options;
  const [selection, setSelection] = useState<SelectionSnapshot>(NO_SELECTION);
  const [editor, setEditor] = useState<EditorSession>(CLOSED_EDITOR);
  const [pendingAction, setPendingAction] = useState<(() => void) | null>(null);
  const { selectedId, item, itemLoading, historyOpen } = selection;
  const didAutoSelect = useRef(false);
  const itemRequest = useRef(0);
  /**
   * Id of the item the editor is creating. It has no row until it is saved, so
   * the loader below must not try to fetch it; the draft is already in state.
   */
  const draftId = useRef<string | null>(null);
  /** Latest committed selection, readable from async list callbacks. */
  const selectedIdRef = useRef<string | null>(null);

  const patch = useCallback(
    (fields: Partial<SelectionSnapshot>) => setSelection((s) => ({ ...s, ...fields })),
    [],
  );

  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) return patch({ item: null });
    if (draftId.current === selectedId) return;
    const token = ++itemRequest.current;
    patch({ itemLoading: true });
    api.get(selectedId)
      .then((loaded) => {
        if (token === itemRequest.current) patch({ item: loaded });
      })
      .catch((error) => {
        if (token !== itemRequest.current) return;
        notify("Could not decrypt that item", { detail: errorText(error), tone: "danger" });
        patch({ item: null, selectedId: null });
      })
      .finally(() => {
        if (token === itemRequest.current) patch({ itemLoading: false });
      });
  }, [selectedId, version, notify, patch]);

  // Exactly one automatic pick, and only where the list is on screen.
  useEffect(() => {
    if (didAutoSelect.current || panel !== "vault") return;
    const first = summaries[0];
    if (!first) return;
    didAutoSelect.current = true;
    patch({ selectedId: first.id });
  }, [summaries, panel, patch]);

  // A filter change is answered by its list, never guessed up front. The detail
  // pane must not describe an item outside the filtered list, so the selection
  // is dropped rather than moved when the response no longer offers it. Layout
  // timing keeps the list and the detail pane in the same paint.
  useLayoutEffect(() => {
    if (!filterCheckPending.current) return;
    filterCheckPending.current = false;
    const current = selectedIdRef.current;
    if (resolveFilterSelection(summaries, current) === current) return;
    patch({ selectedId: null, item: null });
  }, [summaries, filterCheckPending, patch]);

  const guard = useCallback(
    (action: () => void) => {
      if (!editor.open || !editor.dirty) return action();
      setPendingAction(() => action);
    },
    [editor],
  );

  // Locking is a navigation like any other: it must not throw away an unsaved
  // draft without asking, so every lock entry point uses this instead of the
  // raw prop.
  const guardedLock = useCallback(() => guard(onLock), [guard, onLock]);
  const closeEditor = useCallback(() => setEditor(CLOSED_EDITOR), []);

  const openItem = useCallback(
    (id: string) => {
      guard(() => {
        setPanel("vault");
        patch({ selectedId: id, historyOpen: false });
        setEditor(CLOSED_EDITOR);
      });
    },
    [guard, patch, setPanel],
  );

  /** Select an item and open its editor, for the list's context menu. */
  const openAndEdit = useCallback(
    (id: string) => {
      guard(() => {
        setPanel("vault");
        patch({ selectedId: id, historyOpen: false });
        setEditor({ open: true, dirty: false, field: null });
      });
    },
    [guard, patch, setPanel],
  );

  const openCreated = useCallback(
    (created: Item, edit: boolean) => {
      setPanel("vault");
      setFilter(ALL_FILTER);
      setQuery("");
      draftId.current = edit ? created.id : null;
      patch({ selectedId: created.id, item: created });
      setEditor({ open: edit, dirty: false, field: null });
      refresh();
    },
    [patch, refresh, setFilter, setPanel, setQuery],
  );

  const createItem = useCallback(
    (category: Category) => {
      guard(() => {
        api.createItem(category)
          .then((created) => {
            openCreated(created, true);
            requestAnimationFrame(() => {
              document.querySelector<HTMLInputElement>(".title-input")?.focus();
            });
          })
          .catch((error) => {
            notify("Could not create the item", {
              detail: errorText(error),
              tone: "danger",
            });
          });
      });
    },
    [guard, notify, openCreated],
  );

  /** The audit's "Fix": open the item in the editor on the flagged field. */
  const fixFinding = useCallback(
    (itemId: string, fieldId: string) => {
      guard(() => {
        setPanel("vault");
        patch({ selectedId: itemId });
        setEditor({ open: true, dirty: false, field: fieldId });
      });
    },
    [guard, patch, setPanel],
  );

  const finishEditing = useCallback(
    (saved: Item) => {
      draftId.current = null;
      patch({ item: saved });
      setEditor(CLOSED_EDITOR);
      refresh();
    },
    [patch, refresh],
  );

  // A new item is a draft until it is saved, so cancelling it has nothing to
  // undo: the row never existed.
  const cancelEditing = useCallback(() => {
    if (!editor.open) return;
    const wasDraft = item !== null && !summaries.some((row) => row.id === item.id);
    draftId.current = null;
    setEditor(CLOSED_EDITOR);
    if (wasDraft) patch({ selectedId: null, item: null });
  }, [editor.open, item, patch, summaries]);

  const requestCancel = useCallback(() => {
    if (editor.dirty) return setPendingAction(() => cancelEditing);
    cancelEditing();
  }, [cancelEditing, editor.dirty]);

  const deleteCurrent = useCallback(() => {
    patch({ selectedId: null, item: null });
    setEditor(CLOSED_EDITOR);
    refresh();
  }, [patch, refresh]);

  /** A different vault (or a renamed one) invalidates the whole view. */
  const vaultChanged = useCallback(() => {
    patch({ selectedId: null, item: null, historyOpen: false });
    setEditor(CLOSED_EDITOR);
    setQuery("");
    refresh();
  }, [patch, refresh, setQuery]);

  const toggleFavorite = useCallback(
    (favorite: boolean) => {
      if (!item) return;
      api.save({ ...item, favorite })
        .then((saved) => {
          patch({ item: saved });
          refresh();
          notify(favorite ? "Added to favorites" : "Removed from favorites", {
            tone: "neutral",
          });
        })
        .catch((error) => {
          notify("Could not update the item", { detail: errorText(error), tone: "danger" });
        });
    },
    [item, notify, patch, refresh],
  );

  /** Toggle a row's favourite state without opening it first. */
  const setFavorite = useCallback(
    (id: string, favorite: boolean) => {
      api
        .get(id)
        .then((full) => api.save({ ...full, favorite }))
        .then((saved) => {
          setSelection((s) => (s.selectedId === saved.id ? { ...s, item: saved } : s));
          refresh();
          notify(favorite ? "Added to favorites" : "Removed from favorites", {
            tone: "neutral",
          });
        })
        .catch((error) =>
          notify("Could not update the item", { detail: errorText(error), tone: "danger" }),
        );
    },
    [notify, patch, refresh],
  );

  /** Move a row to the trash without selecting it. */
  const trashById = useCallback(
    (id: string) => {
      trashApi
        .trash(id)
        .then(() => {
          setSelection((s) =>
            s.selectedId === id ? { ...s, selectedId: null, item: null } : s,
          );
          refresh();
          notify("Moved to the trash", { tone: "neutral" });
        })
        .catch((error) =>
          notify("Could not move the item to the trash", {
            detail: errorText(error),
            tone: "danger",
          }),
        );
    },
    [notify, refresh],
  );

  const setDirty = useCallback(
    (dirty: boolean) => setEditor((s) => ({ ...s, dirty })),
    [],
  );
  const setItem = useCallback(
    (next: Item | null) => patch({ item: next }),
    [patch],
  );
  const setHistoryOpen = useCallback(
    (open: boolean) => patch({ historyOpen: open }),
    [patch],
  );
  const closeHistory = useCallback(() => patch({ historyOpen: false }), [patch]);
  const editSelected = useCallback(
    () => guard(() => setEditor((s) => ({ ...s, open: true }))),
    [guard],
  );

  // Surface the navigation hooks call before discarding a draft. Built here so
  // the session contract tracks this hook's own actions.
  const session = useMemo<ShellSession>(
    () => ({
      guard,
      resetEditor: closeEditor,
      closeHistory,
      createItem,
      editSelected,
      lock: guardedLock,
      selectedId,
    }),
    [guard, closeEditor, closeHistory, createItem, editSelected, guardedLock, selectedId],
  );

  return {
    selectedId,
    item,
    itemLoading,
    editing: editor.open,
    dirty: editor.dirty,
    focusField: editor.field,
    historyOpen,
    pendingAction,
    setPendingAction,
    setDirty,
    setItem,
    setHistoryOpen,
    guard,
    guardedLock,
    closeEditor,
    closeHistory,
    editSelected,
    openAndEdit,
    setFavorite,
    trashById,
    session,
    openItem,
    openCreated,
    createItem,
    fixFinding,
    finishEditing,
    cancelEditing,
    requestCancel,
    deleteCurrent,
    toggleFavorite,
    vaultChanged,
  };
}
