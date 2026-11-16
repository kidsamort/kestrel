import type { ImportFormat } from "../../lib/api-portability";

/**
 * One row per on-disk format. Import and export expose the very same three
 * formats, so a single list keeps the two flows from drifting apart; only the
 * wording differs, hence the two labels.
 */
export interface FormatSpec {
  id: ImportFormat;
  importLabel: string;
  exportLabel: string;
}

export const FORMATS: readonly FormatSpec[] = [
  { id: "json", importLabel: "JSON", exportLabel: "JSON — full items" },
  { id: "csv", importLabel: "CSV", exportLabel: "CSV — one row per item" },
  {
    id: "1pux",
    importLabel: "1PUX (1Password)",
    exportLabel: "1PUX — 1Password archive",
  },
];
