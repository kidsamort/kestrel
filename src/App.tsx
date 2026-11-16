import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { CircleAlert, Clock3, ShieldCheck } from "lucide-react";
import { api, errorText, hasCore } from "./api";
import { clock } from "./lib/format";
import { useCorePoll } from "./lib/use-core-poll";
import {
  applyTheme,
  persistAccent,
  persistTheme,
  resolveTheme,
  storedAccent,
  storedTheme,
  type AccentId,
  type ThemeChoice,
} from "./lib/theme";
import type { VaultState } from "./types";
import Gate from "./Gate";
import VaultShell from "./VaultShell";
import WindowBar from "./WindowBar";
import { Button } from "./ui/Button";
import { BrandMark } from "./ui/BrandMark";
import { NoticeProvider, useNotify } from "./ui/Toast";
import { TooltipProvider } from "./ui/Tooltip";

export default function App() {
  return (
    <NoticeProvider>
      <TooltipProvider>
        <Root />
      </TooltipProvider>
    </NoticeProvider>
  );
}

type Boot = "loading" | "ready" | "error";

function Root() {
  const notify = useNotify();
  const [boot, setBoot] = useState<Boot>("loading");
  const [bootError, setBootError] = useState<string | null>(null);
  const [vault, setVault] = useState<VaultState | null>(null);
  const [lockedBy, setLockedBy] = useState<"idle" | "manual" | null>(null);
  const [theme, setTheme] = useState<ThemeChoice>(() => storedTheme());
  const [accent, setAccent] = useState<AccentId>(() => storedAccent());
  const [now, setNow] = useState(() => Date.now());

  const lastActivity = useRef(Date.now());
  const lastTouch = useRef(0);
  const seen = useRef(false);

  const unlocked = vault !== null && !vault.locked;

  /* ----------------------------------------------------------- booting */

  const bootOnce = useCallback(() => {
    setBoot("loading");
    setBootError(null);
    if (!hasCore()) {
      setBoot("error");
      setBootError(
        "This window is not running inside the Kestrel desktop shell, so the Rust core cannot be reached.",
      );
      return;
    }
    api
      .state()
      .then((state) => {
        setVault(state);
        setBoot("ready");
        seen.current = true;
      })
      .catch((error) => {
        setBoot("error");
        setBootError(errorText(error));
      });
  }, []);

  useEffect(() => {
    bootOnce();
  }, [bootOnce]);

  /* ------------------------------------------------------------ theme */

  useEffect(() => {
    applyTheme(theme);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      if (theme === "system") applyTheme("system");
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [theme]);

  const chooseTheme = useCallback((next: ThemeChoice) => {
    setTheme(next);
    persistTheme(next);
  }, []);

  const chooseAccent = useCallback((next: AccentId) => {
    setAccent(next);
    persistAccent(next);
  }, []);

  /* ------------------------------------------------- auto-lock tracking */

  useEffect(() => {
    const timeout = vault?.autolockSeconds ?? 0;
    if (!unlocked || timeout <= 0) return;

    lastActivity.current = Date.now();
    lastTouch.current = 0;

    const ping = () => {
      lastActivity.current = Date.now();
      const stamp = Date.now();
      if (stamp - lastTouch.current < 8000) return;
      lastTouch.current = stamp;
      api.touch().catch(() => undefined);
    };

    window.addEventListener("pointerdown", ping, true);
    window.addEventListener("keydown", ping, true);
    window.addEventListener("wheel", ping, { passive: true, capture: true });
    return () => {
      window.removeEventListener("pointerdown", ping, true);
      window.removeEventListener("keydown", ping, true);
      window.removeEventListener("wheel", ping, true);
    };
  }, [unlocked, vault?.autolockSeconds]);

  // One clock drives the titlebar meter and the pre-lock warning.
  useEffect(() => {
    if (!unlocked) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [unlocked]);

  // The core owns the deadline: it reports the instant it will lock, so the
  // meter does not drift with the renderer's touch lag. The local estimate is
  // only the first frame before `lockAt` arrives.
  const remaining =
    vault?.lockAt != null
      ? Math.max(0, Math.ceil((vault.lockAt - now) / 1000))
      : Math.max(
          0,
          (vault?.autolockSeconds ?? 0) -
            Math.floor((now - lastActivity.current) / 1000),
        );
  // Warn half the timeout out, capped at 30 s: enough time to react without
  // nagging during ordinary work.
  const warnAt = Math.min(30, Math.max(8, Math.round((vault?.autolockSeconds ?? 0) / 2)));
  const warning = unlocked && remaining <= warnAt;

  const stayUnlocked = () => {
    lastActivity.current = Date.now();
    lastTouch.current = Date.now();
    api.touch().catch(() => undefined);
    // The deadline is the core's, so re-read it instead of letting the meter
    // run out against a stale `lockAt`.
    api
      .state()
      .then(setVault)
      .catch(() => undefined);
    notify("Auto-lock postponed", { tone: "neutral" });
  };

  /* ------------------------------------------------------ lock / events */

  const lockNow = useCallback(() => {
    api
      .lock()
      .then((state) => {
        setVault(state);
        setLockedBy("manual");
        setNow(Date.now());
      })
      .catch((error) => {
        notify("Could not lock the vault", {
          detail: errorText(error),
          tone: "danger",
        });
      });
  }, [notify]);

  // The shell is only a view of Rust state, so a dead core otherwise looks
  // exactly like an idle vault: every poll must be able to say "gone".
  const onCoreDead = useCallback(
    (error: unknown) => {
      const detail = errorText(error);
      setBootError(detail);
      setBoot("error");
      notify("Lost contact with the vault core", { detail, tone: "danger" });
    },
    [notify],
  );

  // The gate owns one step that runs *after* the vault is unlocked: the
  // one-time recovery code. While that step is on screen the poll below must not
  // promote the app into the shell, or the code is shown for a moment and then
  // replaced by an empty vault.
  const [gatePending, setGatePending] = useState(false);

  const onUnlocked = useCallback((state: VaultState) => {
    setVault(state);
    setLockedBy(null);
    lastActivity.current = Date.now();
    lastTouch.current = 0;
    setNow(Date.now());
  }, []);

  // The Rust watchdog is the authority on locking, so an unlocked shell only
  // needs the periodic snapshot. While locked the palette window may unlock
  // behind our back, so that poll has to be much tighter.
  const reconcileUnlocked = useCallback((state: VaultState) => {
    setVault((current) => {
      if (!current) return state;
      if (state.locked && !current.locked) setLockedBy("idle");
      return state;
    });
  }, []);

  const reconcileLocked = useCallback(
    (state: VaultState) => {
      if (!state.locked && !gatePending) onUnlocked(state);
    },
    [gatePending, onUnlocked],
  );

  useCorePoll(
    boot === "ready" && unlocked ? 10_000 : null,
    reconcileUnlocked,
    onCoreDead,
  );
  useCorePoll(
    boot === "ready" && !unlocked ? 1_500 : null,
    reconcileLocked,
    onCoreDead,
  );

  useEffect(() => {
    if (!hasCore()) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    listen("vault://locked", () => {
      setLockedBy("idle");
      setVault((current) =>
        current ? { ...current, locked: true, itemCount: 0 } : current,
      );
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const onState = useCallback((state: VaultState) => {
    setVault(state);
  }, []);

  /* ------------------------------------------------------------ render */

  let body: React.ReactNode;

  if (boot === "loading") {
    body = (
      <div className="boot" role="status">
        <BrandMark size={26} />
        <span className="boot-text">Opening vault…</span>
      </div>
    );
  } else if (boot === "error" || !vault) {
    body = (
      <div className="fatal">
        <div className="fatal-card" role="alert">
          <span className="fatal-icon" aria-hidden>
            <CircleAlert size={20} strokeWidth={1.5} />
          </span>
          <span className="eyebrow">Core unreachable</span>
          <h1 className="display-sm">Kestrel cannot open the vault.</h1>
          <p className="fatal-copy">{bootError ?? "The core did not answer."}</p>
          <p className="fatal-hint">
            The interface is only a view: keys, storage and the auto-lock
            watchdog live in the Rust process. Start the desktop app
            (<code>kestrel.exe</code>) rather than the browser preview.
          </p>
          <Button variant="primary" size="sm" onClick={bootOnce}>
            Try again
          </Button>
        </div>
      </div>
    );
  } else if (vault.locked) {
    body = (
      <Gate
        state={vault}
        lockedBy={lockedBy}
        onUnlocked={onUnlocked}
        onPending={setGatePending}
      />
    );
  } else {
    body = (
      <VaultShell
        remainingSeconds={remaining}
        state={vault}
        onState={onState}
        onLock={lockNow}
        theme={theme}
        accent={accent}
        onTheme={chooseTheme}
        onAccent={chooseAccent}
      />
    );
  }

  return (
    <div
      className="app"
      data-resolved-theme={resolveTheme(theme)}
      data-lock-warning={warning ? "true" : "false"}
    >
      <WindowBar />
      {body}

      {warning ? (
        <div className="lock-warning" role="status">
          <span className="lock-warning-icon" aria-hidden>
            {remaining > 0 ? <Clock3 size={15} /> : <ShieldCheck size={15} />}
          </span>
          <div className="lock-warning-copy">
            <strong>
              {remaining > 0
                ? `Locking in ${clock(remaining)}`
                : "Locking the vault…"}
            </strong>
            <span>
              The core locks after{" "}
              {Math.round((vault?.autolockSeconds ?? 0) / 60) || 1} min of
              inactivity; any input restarts it.
            </span>
          </div>
          <Button
            variant="primary"
            size="sm"
            onClick={stayUnlocked}
            disabled={remaining === 0}
          >
            {remaining === 0 ? "Locked" : "Stay unlocked"}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
