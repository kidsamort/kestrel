/**
 * Attachment bridge — mirrors `src-tauri/core/src/attachments.rs`.
 *
 * Blobs cross the IPC boundary as number arrays, which is why the 25 MiB cap
 * is enforced before the call is made and callers must show a pending state
 * while the promise is outstanding: serialising a large file is not instant.
 */
import { invoke } from "@tauri-apps/api/core";

export interface Attachment {
  id: string;
  name: string;
  mime: string;
  size: number;
  /** First 16 hex characters of SHA-256. */
  digest: string;
  createdAt: number;
}

/** Must match `MAX_ATTACHMENT_BYTES` in the core. */
export const ATTACHMENT_LIMIT_BYTES = 25 * 1024 * 1024;

export const attachments = {
  list: (itemId: string) =>
    invoke<Attachment[]>("attachment_list", { itemId }),
  add: (itemId: string, name: string, mime: string, bytes: number[]) =>
    invoke<Attachment>("attachment_add", { itemId, name, mime, bytes }),
  read: (itemId: string, attachmentId: string) =>
    invoke<number[]>("attachment_read", { itemId, attachmentId }),
  saveAs: (itemId: string, attachmentId: string) =>
    invoke<string>("attachment_save_as", { itemId, attachmentId }),
  remove: (itemId: string, attachmentId: string) =>
    invoke<void>("attachment_remove", { itemId, attachmentId }),
};

/** Human size for a row subtitle: "3 B", "12.4 KB", "25.0 MB". */
export function humanSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/**
 * Plain number array for the IPC bridge. Done once per file, after the size
 * check, so an oversized file never pays for the conversion.
 */
export function toByteArray(buffer: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buffer));
}
