import { describe, expect, it, vi } from "vitest";
import { errorText } from "../api";

// `errorText` is pure, but `api.ts` imports the Tauri bridge at module load.
// Mock it so the test never touches the host.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("errorText", () => {
  it.each([
    ["authentication failed for vault", "That master password cannot decrypt this vault."],
    ["vault is locked", "The vault is locked. Unlock it to continue."],
    ["password must be at least 10 characters", "A master password needs at least 10 characters."],
    ["vault is not initialised", "No vault exists on this device yet. Create one to begin."],
    ["crypto error: key derivation failed", "Key derivation failed. Try again."],
    ["clipboard unavailable", "The clipboard is busy. Close other apps and try again."],
    ["item not found", "That item is no longer in the vault."],
  ])("maps %j to an actionable sentence", (raw, expected) => {
    expect(errorText(raw)).toBe(expected);
  });

  it("reads the message of an Error and matches case-insensitively", () => {
    expect(errorText(new Error("Authentication Failed"))).toBe(
      "That master password cannot decrypt this vault.",
    );
  });

  it("passes through unknown text and stringifies or defaults the rest", () => {
    expect(errorText("disk is full")).toBe("disk is full");
    expect(errorText(new Error("disk is full"))).toBe("disk is full");
    expect(errorText(42)).toBe("42");
    expect(errorText("")).toBe("Something went wrong.");
    expect(errorText(new Error(""))).toBe("Something went wrong.");
  });
});
