import { describe, expect, it } from "vitest";
import { formatFromFileName } from "../lib/api-portability";

describe("formatFromFileName", () => {
  it("detects every supported extension case-insensitively", () => {
    expect(formatFromFileName("vault.json")).toBe("json");
    expect(formatFromFileName("Vault.JSON")).toBe("json");
    expect(formatFromFileName("export.csv")).toBe("csv");
    expect(formatFromFileName("notes.CsV")).toBe("csv");
    expect(formatFromFileName("archive.1pux")).toBe("1pux");
    expect(formatFromFileName("ARCHIVE.1PUX")).toBe("1pux");
  });

  it("returns null when the extension is missing or unrecognised", () => {
    expect(formatFromFileName("vault")).toBeNull();
    expect(formatFromFileName("vault.json.bak")).toBeNull();
    expect(formatFromFileName("vault.tar.gz")).toBeNull();
    expect(formatFromFileName("")).toBeNull();
  });
});
