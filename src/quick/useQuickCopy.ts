import { useCallback, useEffect, useRef, useState } from "react";
import { errorText } from "../api";
import { quick } from "../lib/api-quick";
import type { ItemSummary } from "../types";
import type { CopyField, CopyFlash } from "./types";

const COPY_FLASH_MS = 1600;

/**
 * Copy-to-clipboard actions and the transient flash that confirms them. The
 * password value never enters this renderer: the core copies it.
 */
export function useQuickCopy() {
  const [copied, setCopied] = useState<CopyFlash | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const copyTimer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
    },
    [],
  );

  const copyField = useCallback((item: ItemSummary, field: CopyField) => {
    void quick
      .copyLogin(item.id, field)
      .then(() => {
        setCopied({ itemId: item.id, field });
        setCopyError(null);
        if (copyTimer.current) window.clearTimeout(copyTimer.current);
        copyTimer.current = window.setTimeout(
          () => setCopied(null),
          COPY_FLASH_MS,
        );
      })
      .catch((failure) => {
        setCopied(null);
        const missing =
          /field not found/i.test(String(failure)) &&
          (field === "username"
            ? "That item has no username saved."
            : "That item has no password saved.");
        setCopyError(missing || errorText(failure));
      });
  }, []);

  const reset = useCallback(() => {
    setCopied(null);
    setCopyError(null);
  }, []);

  return { copied, copyError, copyField, reset };
}
