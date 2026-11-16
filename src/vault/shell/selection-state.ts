import type { Item } from "../../types";

/** The editor is one session: its flags always change and reset together. */
export interface EditorSession {
  open: boolean;
  dirty: boolean;
  /** Item was created in this session; cancelling discards it, not saves it. */
  /** Field the editor focuses when it opens. */
  field: string | null;
}

export const CLOSED_EDITOR: EditorSession = {
  open: false,
  dirty: false,
  field: null,
};

/** Everything the detail pane reads, updated as one snapshot. */
export interface SelectionSnapshot {
  selectedId: string | null;
  item: Item | null;
  itemLoading: boolean;
  historyOpen: boolean;
}

export const NO_SELECTION: SelectionSnapshot = {
  selectedId: null,
  item: null,
  itemLoading: false,
  historyOpen: false,
};
