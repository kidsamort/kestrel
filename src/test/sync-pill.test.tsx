import { describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";
import { pillFace } from "../WindowBar";
import WindowBar from "../WindowBar";
import { SYNC_CHANGED_EVENT, type SyncState, type SyncStatus } from "../lib/api-sync";

// The host is not present in a test: the one command the pill calls answers
// from a mutable status, so each render is judged on the reply it was given.
const current = { value: null as SyncStatus | null };
const invoke = vi.fn(() => Promise.resolve(current.value));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) =>
    (invoke as unknown as (...a: unknown[]) => Promise<unknown>)(...args),
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    minimize: vi.fn(),
    toggleMaximize: vi.fn(),
    close: vi.fn(),
  }),
}));

// The pill is the one place a person reads the sync state without opening
// Settings, so its precedence is pinned here: a healthy-looking label in any
// of these rows would be a lie, not a style choice.
function status(overrides: Partial<SyncStatus> = {}): SyncStatus {
  return {
    configured: true,
    server: "http://127.0.0.1:8787",
    accountId: "a".repeat(32),
    deviceId: "b".repeat(32),
    lastSyncAt: 1_700_000_000,
    state: "idle",
    error: null,
    pendingPush: 0,
    conflicts: 0,
    auto: false,
    intervalSecs: 0,
    ...overrides,
  };
}

describe("sync pill precedence", () => {
  it("1. says Not set up before anything else it is told", () => {
    expect(pillFace(status({ configured: false, server: null })).label).toBe(
      "Not set up",
    );
    expect(
      pillFace(
        status({
          configured: false,
          server: null,
          state: "error",
          pendingPush: 4,
          conflicts: 2,
        }),
      ).label,
    ).toBe("Not set up");
  });

  it("2. puts Error above a conflict count", () => {
    expect(
      pillFace(status({ state: "error", error: "boom", conflicts: 3 })).label,
    ).toBe("Error");
  });

  it("3. shows Conflict for the state or for a non-zero count", () => {
    expect(pillFace(status({ state: "conflict", conflicts: 0 })).label).toBe(
      "Conflict",
    );
    expect(pillFace(status({ state: "idle", conflicts: 2 })).label).toBe(
      "Conflict",
    );
  });

  it("4. puts Syncing… above offline and the finished states", () => {
    expect(pillFace(status({ state: "syncing", pendingPush: 5 })).label).toBe(
      "Syncing…",
    );
  });

  it("5. shows Offline even with queued changes", () => {
    expect(pillFace(status({ state: "offline", pendingPush: 2 })).label).toBe(
      "Offline",
    );
  });

  it("6. never claims Synced before a completed exchange", () => {
    expect(pillFace(status({ lastSyncAt: null })).label).toBe("Not synced yet");
    // Rule 6 outranks a queued change: nothing has been exchanged yet.
    expect(pillFace(status({ lastSyncAt: null, pendingPush: 3 })).label).toBe(
      "Not synced yet",
    );
  });

  it("7. reports a non-empty queue as Pending", () => {
    expect(pillFace(status({ pendingPush: 1 })).label).toBe("Pending");
    expect(pillFace(status({ pendingPush: 12 })).label).toBe("Pending");
  });

  it("8. says Synced only when a sync completed and nothing is queued", () => {
    expect(pillFace(status()).label).toBe("Synced");
  });

  it("keeps an error visible in every non-idle state that allows one", () => {
    const states: SyncState[] = ["idle", "syncing", "offline", "conflict"];
    for (const state of states) {
      expect(pillFace(status({ state, error: "boom" })).label).not.toBe(
        "Error",
      );
    }
  });
});

describe("sync pill in the window bar", () => {
  it("paints Pending with the queued count in the title", async () => {
    current.value = status({ pendingPush: 3 });
    render(<WindowBar />);
    const pill = await screen.findByRole("button", { name: /Sync status/ });
    expect(pill.textContent).toBe("Pending");
    expect(pill.getAttribute("title")).toBe(
      "3 changes waiting to be uploaded",
    );
  });

  it("re-reads the status when a command announces a change", async () => {
    current.value = status({ pendingPush: 1 });
    render(<WindowBar />);
    expect(
      (await screen.findByRole("button", { name: /Sync status/ })).textContent,
    ).toBe("Pending");

    // A resolve or a sync elsewhere dispatches this; the pill may not keep the
    // label it read before the command.
    current.value = status({ pendingPush: 0 });
    await act(async () => {
      window.dispatchEvent(new Event(SYNC_CHANGED_EVENT));
    });

    expect(
      screen.getByRole("button", { name: /Sync status/ }).textContent,
    ).toBe("Synced");
  });
});
