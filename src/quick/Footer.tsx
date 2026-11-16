import { CircleAlert, Vault } from "lucide-react";
import type { QuickStatus } from "../lib/api-quick";
import { Kbd } from "../ui/Kbd";
import type { CopyFlash } from "./types";

/**
 * The palette's status strip: vault scope, the two keyboard hints and the
 * one-line status that reports copy, clipboard expiry or a taken hotkey.
 */
export function QuickFooter({
  vaultName,
  copyError,
  copied,
  status,
  clipboard,
}: {
  vaultName: string | null;
  copyError: string | null;
  copied: CopyFlash | null;
  status: QuickStatus | null;
  clipboard: string;
}) {
  return (
    <div className="palette-foot qa-foot">
      {vaultName ? (
        <span className="qa-foot-vault" title="Results are scoped to this vault">
          <Vault size={11} strokeWidth={1.6} aria-hidden="true" />
          {vaultName}
        </span>
      ) : null}
      <span>
        <Kbd>↑</Kbd> <Kbd>↓</Kbd> move
      </span>
      <span>
        <Kbd>Enter</Kbd> open
      </span>
      <span className="qa-foot-note" role="status" aria-live="polite">
        {copyError ? (
          <>
            <CircleAlert size={11} strokeWidth={1.6} aria-hidden="true" />
            {copyError}
          </>
        ) : copied ? (
          <>Clears from the clipboard in {clipboard}</>
        ) : status && !status.registered ? (
          <>
            <CircleAlert size={11} strokeWidth={1.6} aria-hidden="true" />
            {status.shortcut} is taken; open from the main window.
          </>
        ) : (
          "Search never reads secret values"
        )}
      </span>
    </div>
  );
}
