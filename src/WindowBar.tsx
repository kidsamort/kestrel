import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  CircleAlert,
  CloudCheck,
  CloudOff,
  LoaderCircle,
  Minus,
  Square,
  TriangleAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  requestSyncView,
  sync,
  SYNC_CHANGED_EVENT,
  type SyncStatus,
} from "./lib/api-sync";
import { relativeTime } from "./lib/format";
import { BrandMark } from "./ui/BrandMark";

/** Resolved on use, not at import: the browser preview has no Tauri internals. */
const win = () => getCurrentWindow();

interface PillFace {
  label: string;
  tone: string;
  icon: LucideIcon;
}

/**
 * Every label the pill can show, in precedence order.
 *
 * `configured` wins because a device with no server cannot be synced, offline
 * or in conflict — saying so would describe a client that does not exist. A
 * conflict or an error outranks the spinner, and both outrank "Synced": an
 * indicator that rounded a conflict down to "Synced" would be actively
 * misleading. "Synced" is therefore the last resort — it needs a completed
 * exchange *and* an empty push queue.
 *
 * "Not synced yet" and "Pending" both paint in the muted treatment: neither is
 * a healthy sync, and neither is a fault. The word, and the title (which counts
 * the queued changes), carry the difference.
 */
export function pillFace(status: SyncStatus): PillFace {
  if (!status.configured) {
    return { label: "Not set up", tone: "is-unconfigured", icon: CloudOff };
  }
  if (status.state === "error") {
    return { label: "Error", tone: "is-error", icon: CircleAlert };
  }
  if (status.state === "conflict" || status.conflicts > 0) {
    return { label: "Conflict", tone: "is-conflict", icon: TriangleAlert };
  }
  if (status.state === "syncing") {
    return { label: "Syncing…", tone: "is-syncing", icon: LoaderCircle };
  }
  if (status.state === "offline") {
    return { label: "Offline", tone: "is-offline", icon: CloudOff };
  }
  if (status.lastSyncAt === null) {
    return { label: "Not synced yet", tone: "is-unconfigured", icon: CloudOff };
  }
  if (status.pendingPush > 0) {
    return { label: "Pending", tone: "is-offline", icon: CloudOff };
  }
  return { label: "Synced", tone: "is-synced", icon: CloudCheck };
}

/** The title carries the relative last-sync text the pill has no room for. */
function pillTitle(status: SyncStatus): string {
  const last = status.lastSyncAt
    ? `Last sync ${relativeTime(status.lastSyncAt)}`
    : "Never synced";
  if (!status.configured) return `Sync is not set up. ${last}`;
  const queued =
    status.pendingPush > 0
      ? ` · ${status.pendingPush} change${status.pendingPush === 1 ? "" : "s"} to push`
      : "";
  if (status.state === "error") {
    return `${status.error ?? "Sync failed"} · ${last}${queued}`;
  }
  if (status.state === "conflict" || status.conflicts > 0) {
    const waiting =
      status.conflicts > 0
        ? `${status.conflicts} conflict${
            status.conflicts === 1 ? "" : "s"
          } waiting for you`
        : "A conflict is waiting for you";
    return `${waiting} · ${last}${queued}`;
  }
  if (status.state === "syncing") return `Syncing now · ${last}${queued}`;
  if (status.state === "offline") {
    return `Offline; changes stay on this device · ${last}${queued}`;
  }
  if (status.lastSyncAt === null) return `${last}${queued}`;
  if (status.pendingPush > 0) {
    return `${status.pendingPush} change${
      status.pendingPush === 1 ? "" : "s"
    } waiting to be uploaded`;
  }
  return last;
}

/**
 * Window toolbar: brand, the vault switcher (a portal target filled by the
 * shell), the sync pill, the auto-lock countdown, a search slot, draggable
 * space, and the window buttons.
 */
export default function WindowBar() {
  const [status, setStatus] = useState<SyncStatus | null>(null);

  // Read on mount and after any command, never on a timer: a clock would keep
  // painting a stale state between syncs, which is the one thing this control
  // must not do. Commands announce themselves through `SYNC_CHANGED_EVENT`.
  useEffect(() => {
    let live = true;
    let latest = 0;

    const read = () => {
      const ticket = ++latest;
      sync
        .status()
        .then((next) => {
          // A slower reply must not overwrite a newer one, and nothing may
          // land after unmount.
          if (live && ticket === latest) setStatus(next);
        })
        .catch(() => {
          if (live && ticket === latest) setStatus(null);
        });
    };

    read();
    window.addEventListener(SYNC_CHANGED_EVENT, read);
    return () => {
      live = false;
      window.removeEventListener(SYNC_CHANGED_EVENT, read);
    };
  }, []);

  const face = status ? pillFace(status) : null;
  const Icon = face?.icon;

  return (
    <header className="titlebar">
      <div className="titlebar-brand" data-tauri-drag-region>
        <BrandMark />
        <span className="wordmark">Kestrel</span>
        {/* The shell portals the vault switcher here once it is unlocked. */}
        <span className="titlebar-vault" id="titlebar-vault" />
        {status && face && Icon ? (
          <button
            type="button"
            className={`sync-pill ${face.tone}`}
            title={pillTitle(status)}
            aria-label={`Sync status: ${face.label}. Open sync settings.`}
            onMouseDown={(event) => event.stopPropagation()}
            onClick={requestSyncView}
          >
            <Icon
              size={12}
              strokeWidth={1.6}
              aria-hidden
              className={`sync-pill-icon ${
                face.tone === "is-syncing" ? "sync-spin" : ""
              }`}
            />
            <span className="sync-pill-word">{face.label}</span>
          </button>
        ) : null}
        <span className="titlebar-meta" id="titlebar-meta" />
      </div>

      <div className="titlebar-drag" data-tauri-drag-region />

      <div
        className="titlebar-search"
        id="titlebar-search"
        onMouseDown={(event) => event.stopPropagation()}
      />

      <div className="titlebar-drag" data-tauri-drag-region />

      <div
        className="window-controls"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          type="button"
          className="wc"
          aria-label="Minimize window"
          onClick={() => win().minimize()}
        >
          <Minus size={13} strokeWidth={1.4} aria-hidden />
        </button>
        <button
          type="button"
          className="wc"
          aria-label="Maximize or restore window"
          onClick={() => win().toggleMaximize()}
        >
          <Square size={10} strokeWidth={1.4} aria-hidden />
        </button>
        <button
          type="button"
          className="wc wc-close"
          aria-label="Close window"
          onClick={() => win().close()}
        >
          <X size={13} strokeWidth={1.4} aria-hidden />
        </button>
      </div>
    </header>
  );
}
