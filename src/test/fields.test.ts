import { describe, expect, it } from "vitest";
import {
  expiryHint,
  normalizeSeedPhrase,
  parseFieldDate,
  seedWarning,
  seedWordCount,
  seedWordCountOk,
} from "../lib/fields";

const WORDS =
  "zebra orbit lantern canyon velvet meadow copper falcon garden whisper marble tide";

function phrase(count: number): string {
  return Array.from({ length: count }, (_, i) => `word${i + 1}`).join(" ");
}

function iso(date: Date): string {
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${date.getFullYear()}-${month}-${day}`;
}

function daysFrom(now: Date, days: number): string {
  return iso(
    new Date(now.getFullYear(), now.getMonth(), now.getDate() + days),
  );
}

describe("normalizeSeedPhrase", () => {
  it("collapses every whitespace run to one space and trims the ends", () => {
    expect(normalizeSeedPhrase("  zebra\n\norbit\tlantern   canyon ")).toBe(
      "zebra orbit lantern canyon",
    );
    expect(normalizeSeedPhrase("\n\t ")).toBe("");
  });

  it("makes a phrase pasted with line breaks equal to the typed phrase", () => {
    expect(normalizeSeedPhrase(WORDS.replaceAll(" ", "\n"))).toBe(WORDS);
  });
});

describe("seedWordCount", () => {
  it("counts words after normalisation and treats empty as zero", () => {
    expect(seedWordCount("")).toBe(0);
    expect(seedWordCount(" \n\t ")).toBe(0);
    expect(seedWordCount(WORDS)).toBe(12);
    expect(seedWordCount(WORDS.replaceAll(" ", "\n  "))).toBe(12);
  });
});

describe("seedWordCountOk", () => {
  it("accepts only the BIP-39 lengths, plus the not-yet-filled field", () => {
    expect(seedWordCountOk("")).toBe(true);
    expect(seedWordCountOk("   ")).toBe(true);
    for (const valid of [12, 15, 18, 21, 24]) {
      expect(seedWordCountOk(phrase(valid))).toBe(true);
    }
    for (const invalid of [1, 11, 13, 23, 25]) {
      expect(seedWordCountOk(phrase(invalid))).toBe(false);
    }
  });
});

describe("seedWarning", () => {
  it("stays quiet for a standard length and warns without blocking otherwise", () => {
    expect(seedWarning("")).toBeNull();
    expect(seedWarning(phrase(24))).toBeNull();
    expect(seedWarning(phrase(13))).toBe(
      "Seed phrases are 12, 15, 18, 21 or 24 words.",
    );
  });
});

describe("parseFieldDate", () => {
  it("reads a date-only string as a local calendar date", () => {
    const parsed = parseFieldDate("2026-11-27");
    expect(parsed?.getFullYear()).toBe(2026);
    expect(parsed?.getMonth()).toBe(10);
    expect(parsed?.getDate()).toBe(27);
  });

  it("returns null for empty or unparseable input", () => {
    expect(parseFieldDate("")).toBeNull();
    expect(parseFieldDate("   ")).toBeNull();
    expect(parseFieldDate("not-a-date")).toBeNull();
  });
});

describe("expiryHint", () => {
  const now = new Date(2026, 10, 15); // 15 Nov 2026, local noon-ish

  it("says how long a future expiry has left, singularised", () => {
    expect(expiryHint(daysFrom(now, 12), "expires at", now)).toBe(
      "expires in 12 days",
    );
    expect(expiryHint(daysFrom(now, 1), "expiry", now)).toBe("expires in 1 day");
    expect(expiryHint(daysFrom(now, 30), "expires at", now)).toBe(
      "expires in 30 days",
    );
    expect(expiryHint(daysFrom(now, 0), "expires at", now)).toBe(
      "expires today",
    );
  });

  it("says how long ago an expiry passed, singularised", () => {
    expect(expiryHint(daysFrom(now, -3), "expires at", now)).toBe(
      "expired 3 days ago",
    );
    expect(expiryHint(daysFrom(now, -1), "expiry", now)).toBe(
      "expired 1 day ago",
    );
  });

  it("says nothing for a non-expiry label, an empty value or garbage", () => {
    expect(expiryHint("2026-11-27", "date of birth", now)).toBeNull();
    expect(expiryHint("", "expires at", now)).toBeNull();
    expect(expiryHint("not-a-date", "expires at", now)).toBeNull();
  });
});
