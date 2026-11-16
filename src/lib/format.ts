/** Small, pure formatting helpers. No component state, no side effects. */

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function relativeTime(unixSeconds: number, now = Date.now()): string {
  if (!unixSeconds) return "unknown";
  const diff = Math.max(0, Math.floor(now / 1000) - unixSeconds);
  if (diff < 45) return "just now";
  if (diff < HOUR) {
    const m = Math.max(1, Math.round(diff / MINUTE));
    return `${m} min ago`;
  }
  if (diff < DAY) {
    const h = Math.round(diff / HOUR);
    return `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  if (diff < 7 * DAY) {
    const d = Math.round(diff / DAY);
    return `${d} day${d === 1 ? "" : "s"} ago`;
  }
  const date = new Date(unixSeconds * 1000);
  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function clock(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

export function durationLabel(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds % HOUR === 0) {
    const h = seconds / HOUR;
    return `${h} hour${h === 1 ? "" : "s"}`;
  }
  const m = Math.round(seconds / MINUTE);
  return `${m} minute${m === 1 ? "" : "s"}`;
}

const CHARSETS: [RegExp, number][] = [
  [/[a-z]/, 26],
  [/[A-Z]/, 26],
  [/[0-9]/, 10],
  [/[^A-Za-z0-9]/, 33],
];

/**
 * Shannon entropy of an independently drawn string over the character classes
 * it uses. This is an estimate of the generator's output, not a measurement of
 * a human-chosen password — the UI always labels it as such.
 */
export function estimateBits(value: string): number {
  if (!value) return 0;
  const alphabet = CHARSETS.reduce(
    (total, [pattern, size]) => (pattern.test(value) ? total + size : total),
    0,
  );
  return Math.round(value.length * Math.log2(Math.max(2, alphabet)));
}

export interface Strength {
  bits: number;
  /** 0–4, for the segmented meter */
  level: number;
  label: string;
}

export function strengthOf(value: string): Strength {
  const bits = estimateBits(value);
  if (!value) return { bits: 0, level: 0, label: "Empty" };
  if (bits < 40) return { bits, level: 1, label: "Weak estimate" };
  if (bits < 60) return { bits, level: 2, label: "Fair estimate" };
  if (bits < 90) return { bits, level: 3, label: "Strong estimate" };
  return { bits, level: 4, label: "Very strong estimate" };
}

/** Group a card number in fours without changing the stored value. */
export function formatCardNumber(value: string): string {
  const digits = value.replace(/\s+/g, "");
  if (!/^\d+$/.test(digits)) return value;
  return digits.replace(/(.{4})/g, "$1 ").trim();
}

export function maskSecret(value: string): string {
  return "•".repeat(Math.min(18, Math.max(8, value.length)));
}

export function fileNameHost(url: string): string {
  try {
    const parsed = new URL(url.includes("://") ? url : `https://${url}`);
    return parsed.host.replace(/^www\./, "");
  } catch {
    return url;
  }
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
