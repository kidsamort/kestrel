import { describe, expect, it, vi } from "vitest";
import { vaultErrorCode, vaultErrorText } from "../lib/api-vault";

// The bridge imports the Tauri invoke at module load; the mapping itself is
// pure, so the host is replaced rather than started.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("vaultErrorText", () => {
  it.each([
    [
      "already_exists",
      "A vault with this name is already in that folder. Pick another name or another folder.",
    ],
    ["weak_password", "A master password needs at least 10 characters."],
    ["not_found", "This file is not here any more."],
  ])("maps the core's %s code to an actionable sentence", (code, expected) => {
    expect(vaultErrorCode(code)).toBe(code);
    expect(vaultErrorText(code)).toBe(expected);
  });

  it("reads a code from an Error and from a detail suffix", () => {
    expect(vaultErrorText(new Error("already_exists"))).toBe(
      "A vault with this name is already in that folder. Pick another name or another folder.",
    );
    expect(vaultErrorText("weak_password: password must be at least 10 characters")).toBe(
      "A master password needs at least 10 characters.",
    );
    expect(vaultErrorText("not_found: C:\\vaults\\personal.db")).toBe(
      "This file is not here any more.",
    );
  });

  it("leaves plain core messages to the shared formatter", () => {
    expect(vaultErrorCode("disk is full")).toBeNull();
    expect(vaultErrorText("disk is full")).toBe("disk is full");
  });
});
