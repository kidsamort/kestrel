import type { Filter, Panel } from "../../lib/navigation";

/**
 * Keyboard map of the vault shell: a pure decision function plus the executor
 * that turns its answer into one navigation call. The hook that owns the
 * listener supplies the handlers, so neither the precedence rules (palette
 * chords first, then modal gating, then the rest) nor the command set needs a
 * DOM to be tested.
 */
export type ShellShortcut =
  | "open-palette"
  | "toggle-palette"
  | "lock"
  | "focus-search"
  | "new-item"
  | "edit-item"
  | "generator"
  | "settings"
  | "filter-all"
  | "filter-favorites";

export interface ShortcutInput {
  /** `KeyboardEvent.key`, verbatim (case and punctuation preserved). */
  key: string;
  mod: boolean;
  shift: boolean;
  dialogOpen: boolean;
  paletteOpen: boolean;
  hasSelection: boolean;
}

export function resolveShellShortcut(
  input: ShortcutInput,
): ShellShortcut | null {
  const key = input.key.toLowerCase();

  // Chords that must work regardless of what is open: the palette fallback,
  // its toggle, and locking.
  if (input.mod && input.shift && key === "k") return "open-palette";
  if (input.mod && key === "k") return "toggle-palette";
  if (input.mod && key === "l") return "lock";

  // A dialog or the palette owns typing while it is up.
  if (input.dialogOpen || input.paletteOpen) return null;

  if (input.mod && key === "f") return "focus-search";
  if (input.mod && key === "n") return "new-item";
  if (input.mod && key === "e" && input.hasSelection) return "edit-item";
  if (input.mod && key === "g") return "generator";
  if (input.mod && input.key === ",") return "settings";
  if (input.mod && key === "1") return "filter-all";
  if (input.mod && key === "2") return "filter-favorites";
  return null;
}

export interface ShortcutHandlers {
  openPalette: () => void;
  togglePalette: () => void;
  lock: () => void;
  focusSearch: () => void;
  createItem: () => void;
  editSelected: () => void;
  openPanel: (panel: Panel) => void;
  applyFilter: (filter: Filter) => void;
}

export function runShellShortcut(
  shortcut: ShellShortcut,
  handlers: ShortcutHandlers,
): void {
  switch (shortcut) {
    case "open-palette":
      handlers.openPalette();
      return;
    case "toggle-palette":
      handlers.togglePalette();
      return;
    case "lock":
      handlers.lock();
      return;
    case "focus-search":
      handlers.focusSearch();
      return;
    case "new-item":
      handlers.createItem();
      return;
    case "edit-item":
      handlers.editSelected();
      return;
    case "generator":
      handlers.openPanel("generator");
      return;
    case "settings":
      handlers.openPanel("settings");
      return;
    case "filter-all":
      handlers.applyFilter({ mode: "all" });
      return;
    case "filter-favorites":
      handlers.applyFilter({ mode: "favorites" });
      return;
  }
}
