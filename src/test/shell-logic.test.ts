import { describe, expect, it, vi } from "vitest";
import type { ItemSummary } from "../types";
import {
  autolockWarning,
  PANEL_LABEL,
  resolveFilterSelection,
} from "../vault/shell/logic";
import {
  resolveShellShortcut,
  runShellShortcut,
  type ShortcutHandlers,
  type ShortcutInput,
} from "../vault/shell/hotkeys";
import type { Panel } from "../lib/navigation";
import type { Filter } from "../lib/navigation";

function summary(id: string): ItemSummary {
  return {
    id,
    title: id,
    category: "login",
    username: "",
    url: "",
    tags: [],
    favorite: false,
    hasTotp: false,
    updatedAt: 0,
  };
}

describe("resolveFilterSelection", () => {
  it("keeps a selection the filtered list still offers", () => {
    expect(resolveFilterSelection([summary("a"), summary("b")], "b")).toBe("b");
  });

  it("drops a selection the filtered list no longer offers", () => {
    expect(resolveFilterSelection([summary("a")], "b")).toBeNull();
    expect(resolveFilterSelection([], "b")).toBeNull();
  });

  it("never invents a selection for an empty pick", () => {
    expect(resolveFilterSelection([summary("a")], null)).toBeNull();
  });
});

describe("autolockWarning", () => {
  it("caps the warning window at 30 s", () => {
    expect(autolockWarning(12, 300)).toEqual({ warnAt: 30, warning: true });
    expect(autolockWarning(31, 300).warning).toBe(false);
  });

  it("uses half of a short autolock with an 8 s floor", () => {
    expect(autolockWarning(10, 20).warnAt).toBe(10);
    expect(autolockWarning(18, 3600).warnAt).toBe(30);
    expect(autolockWarning(4, 10).warnAt).toBe(8);
  });

  it("is never in the warning window at zero remaining", () => {
    expect(autolockWarning(0, 300).warning).toBe(false);
  });
});

const base: ShortcutInput = {
  key: "x",
  mod: true,
  shift: false,
  dialogOpen: false,
  paletteOpen: false,
  hasSelection: true,
};

describe("resolveShellShortcut", () => {
  it("handles palette chords and locking even over a dialog", () => {
    const overDialog = { ...base, dialogOpen: true };
    expect(resolveShellShortcut({ ...overDialog, key: "K", shift: true })).toBe(
      "open-palette",
    );
    expect(resolveShellShortcut({ ...overDialog, key: "k" })).toBe(
      "toggle-palette",
    );
    expect(resolveShellShortcut({ ...overDialog, key: "l" })).toBe("lock");
    expect(resolveShellShortcut({ ...overDialog, paletteOpen: true, key: "k" })).toBe(
      "toggle-palette",
    );
  });

  it("lets a dialog or the palette swallow the rest", () => {
    expect(resolveShellShortcut({ ...base, key: "f", dialogOpen: true })).toBeNull();
    expect(resolveShellShortcut({ ...base, key: "f", paletteOpen: true })).toBeNull();
  });

  it("maps the single-key commands", () => {
    expect(resolveShellShortcut({ ...base, key: "F" })).toBe("focus-search");
    expect(resolveShellShortcut({ ...base, key: "n" })).toBe("new-item");
    expect(resolveShellShortcut({ ...base, key: "e" })).toBe("edit-item");
    expect(resolveShellShortcut({ ...base, key: "g" })).toBe("generator");
    expect(resolveShellShortcut({ ...base, key: "," })).toBe("settings");
    expect(resolveShellShortcut({ ...base, key: "1" })).toBe("filter-all");
    expect(resolveShellShortcut({ ...base, key: "2" })).toBe("filter-favorites");
  });

  it("requires a selection for edit and a modifier for everything else", () => {
    expect(resolveShellShortcut({ ...base, key: "e", hasSelection: false })).toBeNull();
    expect(resolveShellShortcut({ ...base, key: "f", mod: false })).toBeNull();
    expect(resolveShellShortcut({ ...base, key: "Enter" })).toBeNull();
  });
});

describe("runShellShortcut", () => {
  function handlers() {
    return {
      openPalette: vi.fn(),
      togglePalette: vi.fn(),
      lock: vi.fn(),
      focusSearch: vi.fn(),
      createItem: vi.fn(),
      editSelected: vi.fn(),
      openPanel: vi.fn(),
      applyFilter: vi.fn(),
    } satisfies ShortcutHandlers;
  }

  it("routes panel shortcuts to their panes", () => {
    const h = handlers();
    runShellShortcut("generator", h);
    runShellShortcut("settings", h);
    expect(h.openPanel.mock.calls).toEqual([["generator"], ["settings"]]);
  });

  it("routes filter shortcuts to the matching filter", () => {
    const h = handlers();
    runShellShortcut("filter-all", h);
    runShellShortcut("filter-favorites", h);
    const expected: Filter[] = [{ mode: "all" }, { mode: "favorites" }];
    expect(h.applyFilter.mock.calls.map(([filter]) => filter)).toEqual(expected);
  });

  it("routes command shortcuts to their commands", () => {
    const h = handlers();
    runShellShortcut("lock", h);
    runShellShortcut("new-item", h);
    runShellShortcut("edit-item", h);
    runShellShortcut("focus-search", h);
    expect(h.lock).toHaveBeenCalledOnce();
    expect(h.createItem).toHaveBeenCalledOnce();
    expect(h.editSelected).toHaveBeenCalledOnce();
    expect(h.focusSearch).toHaveBeenCalledOnce();
  });
});

describe("PANEL_LABEL", () => {
  it("labels every pane but the vault", () => {
    const panels: Panel[] = ["vault", "generator", "settings", "trash", "audit"];
    expect(PANEL_LABEL.vault).toBeNull();
    expect(panels.filter((panel) => PANEL_LABEL[panel] !== null)).toHaveLength(4);
    expect(PANEL_LABEL.trash).toBe("Trash");
  });
});
