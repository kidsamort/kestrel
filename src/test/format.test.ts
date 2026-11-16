import { describe, expect, it } from "vitest";
import {
  clock,
  durationLabel,
  formatCardNumber,
  maskSecret,
  relativeTime,
} from "../lib/format";

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe("relativeTime", () => {
  it("treats a missing timestamp as unknown and never shows a future age", () => {
    expect(relativeTime(0)).toBe("unknown");
    // Clock skew can put the timestamp slightly ahead of `now`; the result
    // must clamp to "just now" rather than go negative.
    const now = 1_700_000_000_000;
    expect(relativeTime(Math.floor(now / 1000) + 500, now)).toBe("just now");
    expect(relativeTime(Math.floor(now / 1000) - 44, now)).toBe("just now");
  });

  it("switches from just-now to minutes at 45 seconds and singularises", () => {
    const now = 1_700_000_000_000;
    const at = (seconds: number) => now / 1000 - seconds;
    expect(relativeTime(at(45), now)).toBe("1 min ago");
    expect(relativeTime(at(60), now)).toBe("1 min ago");
    expect(relativeTime(at(119), now)).toBe("2 min ago");
    expect(relativeTime(at(HOUR - 1), now)).toBe("60 min ago");
  });

  it("rounds hours and days and falls back to a locale date past a week", () => {
    const now = 1_700_000_000_000;
    const at = (seconds: number) => now / 1000 - seconds;
    expect(relativeTime(at(HOUR), now)).toBe("1 hour ago");
    expect(relativeTime(at(2 * HOUR), now)).toBe("2 hours ago");
    expect(relativeTime(at(DAY), now)).toBe("1 day ago");
    expect(relativeTime(at(2 * DAY + HOUR), now)).toBe("2 days ago");
    // 6.96 days rounds up but is still inside the week window.
    expect(relativeTime(at(7 * DAY - HOUR), now)).toBe("7 days ago");

    const old = Math.floor(Date.UTC(2020, 5, 15) / 1000);
    const dateText = relativeTime(old, (old + 30 * DAY) * 1000);
    expect(dateText).toContain("2020");
    expect(dateText).not.toMatch(/ago/);
  });
});

describe("clock", () => {
  it("formats mm:ss, pads the seconds, and clamps negatives", () => {
    expect(clock(0)).toBe("0:00");
    expect(clock(65)).toBe("1:05");
    expect(clock(3599)).toBe("59:59");
    expect(clock(-5)).toBe("0:00");
    expect(clock(59.6)).toBe("1:00");
  });
});

describe("durationLabel", () => {
  it("keeps seconds under a minute, prefers whole hours, rounds minutes", () => {
    expect(durationLabel(0)).toBe("0 seconds");
    expect(durationLabel(59)).toBe("59 seconds");
    expect(durationLabel(60)).toBe("1 minute");
    expect(durationLabel(90)).toBe("2 minutes");
    expect(durationLabel(3600)).toBe("1 hour");
    expect(durationLabel(7200)).toBe("2 hours");
    expect(durationLabel(5400)).toBe("90 minutes");
  });
});

describe("formatCardNumber", () => {
  it("groups digits in fours but leaves non-numeric input untouched", () => {
    expect(formatCardNumber("1234567812345678")).toBe("1234 5678 1234 5678");
    expect(formatCardNumber("378282246310005")).toBe("3782 8224 6310 005");
    expect(formatCardNumber("1234 5678")).toBe("1234 5678");
    expect(formatCardNumber("1234-5678")).toBe("1234-5678");
    expect(formatCardNumber("")).toBe("");
  });
});

describe("maskSecret", () => {
  it("uses a fixed-width bullet run that never reveals the length of long secrets", () => {
    expect("•".repeat(8)).toBe(maskSecret(""));
    expect("•".repeat(8)).toBe(maskSecret("abc"));
    expect("•".repeat(10)).toBe(maskSecret("abcdefghij"));
    expect("•".repeat(18)).toBe(maskSecret("a".repeat(64)));
  });
});
