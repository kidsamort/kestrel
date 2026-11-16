import { useEffect, useRef } from "react";
import { api } from "../api";
import type { VaultState } from "../types";

/** Consecutive failed polls before the core counts as gone. */
const FAILURE_THRESHOLD = 3;

/**
 * Poll `vault_state` every `periodMs` and hand each snapshot to `onState`.
 * `null` disables the poll, which is how callers express "not in the state that
 * needs reconciling" without mounting a second component.
 *
 * Three failures in a row report `onDead` exactly once; a success clears the
 * count, so a core that answers again starts a fresh episode. After the alarm
 * the caller is expected to leave the pollable state (App flips `boot`), which
 * is what makes the next run start clean.
 */
export function useCorePoll(
  periodMs: number | null,
  onState: (state: VaultState) => void,
  onDead?: (error: unknown) => void,
): void {
  // The callbacks live in a ref on purpose: an interval must not restart — and
  // reset the failure count — only because the parent rebuilt a handler.
  const latest = useRef({ onState, onDead });
  useEffect(() => {
    latest.current = { onState, onDead };
  });

  useEffect(() => {
    if (periodMs === null) return;
    let failures = 0;
    let reported = false;
    const timer = window.setInterval(() => {
      api
        .state()
        .then((state) => {
          failures = 0;
          reported = false;
          latest.current.onState(state);
        })
        .catch((error) => {
          failures += 1;
          if (failures < FAILURE_THRESHOLD || reported) return;
          reported = true;
          latest.current.onDead?.(error);
        });
    }, periodMs);
    return () => window.clearInterval(timer);
  }, [periodMs]);
}
