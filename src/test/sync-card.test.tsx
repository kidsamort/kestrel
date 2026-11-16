import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SyncCard from "../vault/settings/SyncCard";
import type { SyncStatus } from "../lib/api-sync";

// The host answers every `sync_*` command from one mutable status, so the card
// is judged on the reply it was given and on the command it actually sent.
const host = vi.hoisted(() => ({
  calls: [] as { command: string; args?: unknown }[],
  status: null as unknown,
  /** The one command that fails, and the message it fails with. */
  failOn: null as string | null,
  fail: null as unknown,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (command: string, args?: unknown) => {
    host.calls.push({ command, args });
    if (host.failOn === command) return Promise.reject(host.fail);
    return Promise.resolve(host.status);
  },
}));

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

function mount(next: SyncStatus) {
  host.status = next;
  host.calls.length = 0;
  host.failOn = null;
  host.fail = null;
  render(<SyncCard onReviewConflicts={() => {}} />);
  return screen.findByText(/Sync keeps the same items/);
}

describe("SyncCard device registration", () => {
  it("explains that an account is required and offers no dead button", async () => {
    await mount(status({ accountId: null }));
    expect(
      screen.queryByRole("button", { name: "Register this device" }),
    ).toBeNull();
    expect(screen.getByText(/Sync needs an account first/)).toBeTruthy();
    expect(screen.getByText(/Settings → Account/)).toBeTruthy();
  });

  it("registers this device and confirms it", async () => {
    await mount(status());
    const button = screen.getByRole("button", {
      name: "Register this device",
    });
    host.status = status();
    fireEvent.click(button);
    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain(
        "sync_register",
      ),
    );
    expect(
      await screen.findByText("This device is registered with the service."),
    ).toBeTruthy();
    // Idempotent: the same control stays, relabelled.
    expect(
      screen.getByRole("button", { name: "Register again" }),
    ).toBeTruthy();
  });

  it("shows a registration failure inline", async () => {
    await mount(status());
    host.failOn = "sync_register";
    host.fail = "unknown_device";
    fireEvent.click(
      screen.getByRole("button", { name: "Register this device" }),
    );
    expect(await screen.findByText("unknown_device")).toBeTruthy();
    expect(
      screen.queryByText("This device is registered with the service."),
    ).toBeNull();
  });
});

describe("SyncCard join and forget", () => {
  it("sends the three enrolment values under the command's argument names", async () => {
    await mount(status({ accountId: null }));
    fireEvent.change(screen.getByLabelText("Code"), {
      target: { value: "ABCD-1234" },
    });
    fireEvent.change(screen.getByLabelText("Sealed envelope"), {
      target: { value: "cafe" },
    });
    fireEvent.change(screen.getByLabelText("Sender agreement key"), {
      target: { value: "d".repeat(64) },
    });
    host.status = status();
    fireEvent.click(screen.getByRole("button", { name: "Join" }));

    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain(
        "sync_enroll_accept",
      ),
    );
    const call = host.calls.find(
      (entry) => entry.command === "sync_enroll_accept",
    );
    expect(call?.args).toEqual({
      code: "ABCD-1234",
      sealed: "cafe",
      senderAgreementPub: "d".repeat(64),
    });
  });

  it("asks before forgetting the server and the cursor", async () => {
    await mount(status());
    fireEvent.click(screen.getByRole("button", { name: "Forget server" }));
    expect(host.calls.map((call) => call.command)).not.toContain(
      "sync_forget",
    );
    expect(screen.getByText(/clears the sync cursor/)).toBeTruthy();

    host.status = status({
      configured: false,
      server: null,
      accountId: null,
      deviceId: null,
      lastSyncAt: null,
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Yes, forget the server" }),
    );
    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain("sync_forget"),
    );
  });
});

describe("SyncCard automatic sync", () => {
  it("maps each offered label to the seconds it sends", async () => {
    await mount(status({ auto: true, intervalSecs: 900 }));

    // The interval control is a listbox we draw, not a native select: open it
    // and read the rows the same way a person does.
    const trigger = await screen.findByRole("button", {
      name: "Automatic sync interval",
    });
    expect(trigger.textContent).toContain("Every 15 minutes");
    fireEvent.click(trigger);

    const rows = await screen.findAllByRole("option");
    expect(rows.map((row) => row.textContent)).toEqual([
      "Every 5 minutes",
      "Every 15 minutes",
      "Every hour",
    ]);
    expect(rows.map((row) => row.getAttribute("aria-selected"))).toEqual([
      "false",
      "true",
      "false",
    ]);

    host.status = status({ auto: true, intervalSecs: 3600 });
    fireEvent.mouseDown(rows[2]);
    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain(
        "sync_set_auto",
      ),
    );
    expect(
      host.calls.find((call) => call.command === "sync_set_auto")?.args,
    ).toEqual({ intervalSecs: 3600 });
    // The reply is what the card paints, not the value it just sent.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Automatic sync interval" })
          .textContent,
      ).toContain("Every hour"),
    );
  });

  it("turns on at the remembered period and off with zero", async () => {
    await mount(status());
    host.status = status({ auto: true, intervalSecs: 900 });
    const toggle = await screen.findByRole("switch", {
      name: "Sync automatically",
    });
    fireEvent.click(toggle);
    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain(
        "sync_set_auto",
      ),
    );
    expect(
      host.calls.find((call) => call.command === "sync_set_auto")?.args,
    ).toEqual({ intervalSecs: 900 });

    host.calls.length = 0;
    host.status = status({ auto: false, intervalSecs: 0 });
    fireEvent.click(toggle);
    await waitFor(() =>
      expect(host.calls.map((call) => call.command)).toContain(
        "sync_set_auto",
      ),
    );
    expect(
      host.calls.find((call) => call.command === "sync_set_auto")?.args,
    ).toEqual({ intervalSecs: 0 });
  });

  it("keeps the switch visible and gives the reason when it cannot run", async () => {
    await mount(status({ configured: false, server: null, accountId: null }));
    const noServer = await screen.findByRole("switch", {
      name: "Sync automatically",
    });
    expect(noServer).toBeDisabled();
    expect(
      screen.getByText(/Save a server address first: the timer/),
    ).toBeTruthy();
  });

  it("gives the missing-account reason on a configured vault", async () => {
    await mount(status({ accountId: null }));
    const noAccount = await screen.findByRole("switch", {
      name: "Sync automatically",
    });
    expect(noAccount).toBeDisabled();
    expect(screen.getByText(/has no account yet/)).toBeTruthy();
  });
});
