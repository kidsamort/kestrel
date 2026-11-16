/**
 * Import / export bridge for the `Move data` settings block.
 *
 * The core returns plaintext strings for JSON/CSV and raw bytes for 1PUX; the
 * renderer only turns those into a download. Nothing here writes to disk
 * directly, and the master password is only sent to prove presence to the core.
 */
import { invoke } from "@tauri-apps/api/core";

export type ImportFormat = "json" | "csv" | "1pux";
export type ExportFormat = ImportFormat;

export interface ImportFailure {
  /** 1-based record number in the source file (CSV counts its header as row 1). */
  row: number;
  reason: string;
}

export interface ImportReport {
  imported: number;
  skipped: number;
  failed: ImportFailure[];
}

export interface ImportSample {
  title: string;
  category: string;
  fieldCount: number;
}

export interface ImportPreview {
  total: number;
  sample: ImportSample[];
}

export const portability = {
  preview: (format: ImportFormat, bytes: Uint8Array) =>
    invoke<ImportPreview>("import_preview", { format, bytes: Array.from(bytes) }),

  importItems: (format: ImportFormat, bytes: Uint8Array) =>
    invoke<ImportReport>("import_items", { format, bytes: Array.from(bytes) }),

  exportItems: (format: ExportFormat, password: string) =>
    invoke<string>("export_items", { format, password }),

  export1pux: async (password: string): Promise<Uint8Array<ArrayBuffer>> => {
    const buffer = await invoke<ArrayBuffer>("export_1pux", { password });
    return new Uint8Array(buffer);
  },
};

/** Detect a supported format from a file name; `null` when the extension lies. */
export function formatFromFileName(name: string): ImportFormat | null {
  const lower = name.toLowerCase();
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".csv")) return "csv";
  if (lower.endsWith(".1pux")) return "1pux";
  return null;
}

/**
 * Hand data to the user as a download. Deliberately renderer-only: the core
 * never writes export files itself.
 */
export function downloadBlob(
  name: string,
  data: BlobPart,
  mime = "application/octet-stream",
): void {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
