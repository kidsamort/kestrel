/**
 * Behaviour for the two field kinds that are more than display hints.
 *
 * `seedPhrase` mirrors the Rust helpers in `src-tauri/core/src/model.rs`
 * (`normalize_seed_phrase`, `seed_word_count`, `seed_word_count_ok`); keep the
 * two in step. `date` stays a plain stored string — the detail pane shows the
 * value verbatim and only derives an expiry hint from it, so no stored value is
 * ever rewritten into a different format.
 */

const MS_PER_DAY = 86_400_000;

/** Word counts a BIP-39 mnemonic can have. */
export const SEED_WORD_COUNTS: number[] = [12, 15, 18, 21, 24];

/** Collapse whitespace runs to one space and trim, as the core does. */
export function normalizeSeedPhrase(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

/** Words after normalisation; 0 for an empty phrase. */
export function seedWordCount(value: string): number {
  const normalized = normalizeSeedPhrase(value);
  return normalized === "" ? 0 : normalized.split(" ").length;
}

/** An empty phrase is fine; anything not 12/15/18/21/24 words warns. */
export function seedWordCountOk(value: string): boolean {
  const count = seedWordCount(value);
  return count === 0 || SEED_WORD_COUNTS.includes(count);
}

/** The editor's non-blocking warning, or `null` when there is nothing to say. */
export function seedWarning(value: string): string | null {
  if (seedWordCountOk(value)) return null;
  return `Seed phrases are ${SEED_WORD_COUNTS.slice(0, -1).join(", ")} or ${
    SEED_WORD_COUNTS[SEED_WORD_COUNTS.length - 1]
  } words.`;
}

/** Labels that promise a date is an expiry (`expires at`, `expiry`, …). */
export function isExpiryLabel(label: string): boolean {
  return label.toLowerCase().includes("expir");
}

/**
 * Parse a stored date. `YYYY-MM-DD` is read as a local calendar date (the same
 * day the user sees, with no timezone shift), and an ISO timestamp is read by
 * its date half.
 *
 * Deliberately no `new Date(text)` fallback: the core's expiry rule
 * (`audit.rs::parse_date`) accepts exactly these two shapes. A renderer that
 * also accepted `25/11/2026` would print "expired 3 days ago" on an item the
 * The audit never reports — a false positive the user was already told about.
 * Returns `null` for empty or unrecognised input.
 */
export function parseFieldDate(value: string): Date | null {
  const text = value.trim();
  const match = /^(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?$/.exec(text);
  if (!match) return null;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return Number.isNaN(date.getTime()) ? null : date;
}

function startOfDay(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/**
 * “expires in 12 days”, “expired 3 days ago”, “expires today” — or `null` when
 * the label is not about expiry or the value is not a date. Day counts are
 * calendar-based, so a DST change never shifts them by one.
 */
export function expiryHint(
  value: string,
  label: string,
  now: Date = new Date(),
): string | null {
  if (!isExpiryLabel(label)) return null;
  const target = parseFieldDate(value);
  if (!target) return null;
  const days = Math.round(
    (startOfDay(target) - startOfDay(now)) / MS_PER_DAY,
  );
  if (days === 0) return "expires today";
  const amount = Math.abs(days);
  const unit = `${amount} day${amount === 1 ? "" : "s"}`;
  return days > 0 ? `expires in ${unit}` : `expired ${unit} ago`;
}
