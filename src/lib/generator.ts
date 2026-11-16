import type { GenerateOptions } from "../types";

/**
 * Mirrors `kestrel-core/src/generator.rs`: same character classes, same
 * ambiguity filter, same 72-word list. Used only to show the estimate the core
 * actually generates against — entropy is never inferred from the output text.
 */
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!#$%&*+-=?^_~";
const AMBIGUOUS = "Il1O0o";
const WORDS = 72;

function poolSize(source: string, avoidAmbiguous: boolean): number {
  if (!avoidAmbiguous) return source.length;
  return [...source].filter((char) => !AMBIGUOUS.includes(char)).length;
}

export function entropyFor(options: GenerateOptions): number {
  if (options.passphrase) {
    const words = Math.min(12, Math.max(3, options.words));
    return Math.round(words * Math.log2(WORDS));
  }
  const length = Math.min(128, Math.max(8, options.length));
  const alphabet =
    (options.lowercase ? poolSize(LOWER, options.avoidAmbiguous) : 0) +
    (options.uppercase ? poolSize(UPPER, options.avoidAmbiguous) : 0) +
    (options.digits ? poolSize(DIGITS, options.avoidAmbiguous) : 0) +
    (options.symbols ? poolSize(SYMBOLS, options.avoidAmbiguous) : 0);
  return Math.round(length * Math.log2(Math.max(2, alphabet)));
}

export function optionsAreValid(options: GenerateOptions): boolean {
  if (options.passphrase) return true;
  return (
    options.lowercase ||
    options.uppercase ||
    options.digits ||
    options.symbols
  );
}
