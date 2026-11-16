import { useCallback, useEffect, useRef, useState } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { api, errorText, hasCore } from "../api";
import {
  onQuickShown,
  onVaultLocked,
  quick,
  type QuickStatus,
} from "../lib/api-quick";
import { applyAccent, applyTheme, storedAccent, storedTheme } from "../lib/theme";
import type { VaultState } from "../types";

/**
 * Window-level state for the palette: vault state, hotkey registration and the
 * events that keep the window honest while it is hidden.
 */
export function useQuickSession({
  onShow,
  onLocked,
}: {
  /** Resets the surfaces that start clean on every appearance. */
  onShow: () => void;
  /** Drops per-session state when the core locks while the palette is open. */
  onLocked: () => void;
}) {
  const [vault, setVault] = useState<VaultState | null>(null);
  const [status, setStatus] = useState<QuickStatus | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);

  // The reset callbacks close over the other palette hooks, so the event
  // effects read them through a ref instead of re-subscribing every render.
  const resets = useRef({ onShow, onLocked });
  useEffect(() => {
    resets.current = { onShow, onLocked };
  });

  const loadState = useCallback(async () => {
    try {
      setVault(await api.state());
      setBootError(null);
    } catch (failure) {
      setBootError(errorText(failure));
    }
  }, []);

  // Boot: vault state plus whether the hotkey actually got registered.
  useEffect(() => {
    if (!hasCore()) {
      setBootError("The vault core is not reachable from this window.");
      return;
    }
    void loadState();
    void quick
      .status()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, [loadState]);

  // Every appearance starts clean: empty query, fresh lock state, first row
  // selected. `quick://shown` fires for the hotkey and for `quick_open`;
  // `vault://locked` keeps the palette honest when the watchdog locks while it
  // is open.
  useEffect(() => {
    if (!hasCore()) return;
    let disposed = false;
    const stops: UnlistenFn[] = [];
    const keep = (stop: UnlistenFn) => {
      if (disposed) stop();
      else stops.push(stop);
    };
    void onQuickShown(() => {
      // The palette stays alive between shows; pick up theme/accent changes the
      // main window made while it was hidden.
      applyTheme(storedTheme());
      applyAccent(storedAccent());
      resets.current.onShow();
      void loadState();
    }).then(keep);
    void onVaultLocked(() => {
      resets.current.onLocked();
      void loadState();
    }).then(keep);
    return () => {
      disposed = true;
      for (const stop of stops) stop();
    };
  }, [loadState]);

  // The palette never stays on top of another app it did not open for.
  useEffect(() => {
    if (!hasCore()) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      void quick.hide().catch(() => undefined);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const unlocked = vault !== null && !vault.locked;

  return { vault, setVault, status, bootError, loadState, unlocked };
}
