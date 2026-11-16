import type { Panel } from "../../lib/navigation";
import type { ItemSummary } from "../../types";

/**
 * Which selection survives once a filtered list has answered the pending
 * filter check.
 *
 * The detail pane must never describe an item the filtered list no longer
 * offers, but a filter change must not move the selection either: the initial
 * auto-select stays the only automatic pick. So the answer is either the same
 * id (`rows` still contains it) or `null` (drop it), never another row.
 */
export function resolveFilterSelection(
  rows: readonly ItemSummary[],
  selectedId: string | null,
): string | null {
  if (!selectedId) return null;
  return rows.some((row) => row.id === selectedId) ? selectedId : null;
}

export interface AutolockWarning {
  /** Remaining seconds at which the countdown turns amber. */
  warnAt: number;
  /** True while the toolbar countdown is inside its warning window. */
  warning: boolean;
}

/**
 * Countdown warning window, kept in one place so the toolbar badge turns amber
 * exactly when the shell starts warning (30 s, but never more than half of a
 * short autolock and never below 8 s).
 */
export function autolockWarning(
  remainingSeconds: number,
  autolockSeconds: number,
): AutolockWarning {
  const warnAt = Math.min(30, Math.max(8, Math.round(autolockSeconds / 2)));
  return {
    warnAt,
    warning: remainingSeconds > 0 && remainingSeconds <= warnAt,
  };
}

/**
 * Pane labels used by the single-pane workspace; the vault itself has no label
 * because its panes are named by the list and detail views.
 */
export const PANEL_LABEL: Record<Panel, string | null> = {
  vault: null,
  generator: "Generator",
  settings: "Settings",
  trash: "Trash",
  audit: "Security audit",
};
