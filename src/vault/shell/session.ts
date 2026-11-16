import type { Category } from "../../types";

/**
 * Late-bound handle on the selection/editor session. The navigation hooks must
 * ask that session before throwing a draft away, while the session uses the
 * navigation setters; they meet through this handle instead of one closing over
 * the other. Entries are only read from event handlers.
 */
export interface ShellSession {
  guard: (action: () => void) => void;
  resetEditor: () => void;
  closeHistory: () => void;
  createItem: (category: Category) => void;
  editSelected: () => void;
  lock: () => void;
  selectedId: string | null;
}
