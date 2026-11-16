import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { durationLabel } from "./format";
import { useNotify } from "../ui/Toast";

export interface CopyApi {
  /** Copy a stored field through the core (value never enters JS state). */
  copyField: (itemId: string, fieldId: string, label: string) => void;
  /** Copy a value the UI already holds (generated password, TOTP code). */
  copyText: (text: string, label: string) => void;
  /** Which control most recently succeeded, for its inline check state. */
  copiedKey: string | null;
}

/**
 * Copies go through the core so the clipboard wipe timer starts there. The
 * toast states the wipe deadline instead of implying the value is gone on its
 * own.
 */
export function useCopy(clipboardSeconds: number): CopyApi {
  const notify = useNotify();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );

  const flash = useCallback((key: string) => {
    setCopiedKey(key);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setCopiedKey(null), 1400);
  }, []);

  const detail = `Clears from the clipboard in ${durationLabel(clipboardSeconds)}`;

  const copyField = useCallback(
    (itemId: string, fieldId: string, label: string) => {
      void api
        .copyField(itemId, fieldId)
        .then(() => {
          flash(`field:${fieldId}`);
          notify(`Copied ${label}`, { detail, tone: "success" });
        })
        .catch(() => {
          notify(`Could not copy ${label}`, {
            detail: "The clipboard is held by another application.",
            tone: "danger",
          });
        });
    },
    [detail, flash, notify],
  );

  const copyText = useCallback(
    (text: string, label: string) => {
      void api
        .copyText(text)
        .then(() => {
          flash(`text:${label}`);
          notify(`Copied ${label}`, { detail, tone: "success" });
        })
        .catch(() => {
          notify(`Could not copy ${label}`, {
            detail: "The clipboard is held by another application.",
            tone: "danger",
          });
        });
    },
    [detail, flash, notify],
  );

  return { copyField, copyText, copiedKey };
}
