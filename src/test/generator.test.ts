import { describe, expect, it } from "vitest";
import { entropyFor, optionsAreValid } from "../lib/generator";
import { DEFAULT_GENERATE, type GenerateOptions } from "../types";

function options(overrides: Partial<GenerateOptions>): GenerateOptions {
  return { ...DEFAULT_GENERATE, ...overrides };
}

describe("entropyFor", () => {
  it("uses the 75-character alphabet for all four classes", () => {
    // 26 lower + 26 upper + 10 digits + 13 symbols = 75.
    expect(entropyFor(options({ length: 20 }))).toBe(
      Math.round(20 * Math.log2(75)),
    );
  });

  it("removes the ambiguous glyphs from every pool that contains them", () => {
    // lower 24 + upper 24 + digits 8 + symbols 13 = 69.
    expect(entropyFor(options({ length: 20, avoidAmbiguous: true }))).toBe(
      Math.round(20 * Math.log2(69)),
    );
  });

  it("clamps the password length to 8..128 and never goes below one bit per char", () => {
    expect(entropyFor(options({ length: 1 }))).toBe(
      Math.round(8 * Math.log2(75)),
    );
    expect(entropyFor(options({ length: 500 }))).toBe(
      Math.round(128 * Math.log2(75)),
    );
    // No classes selected: the core still draws from a 2-symbol fallback.
    expect(
      entropyFor(
        options({
          length: 10,
          lowercase: false,
          uppercase: false,
          digits: false,
          symbols: false,
        }),
      ),
    ).toBe(10);
  });

  it("derives passphrase entropy from the word count, clamped to 3..12", () => {
    const words = Math.log2(72);
    expect(entropyFor(options({ passphrase: true, words: 1 }))).toBe(
      Math.round(3 * words),
    );
    expect(entropyFor(options({ passphrase: true, words: 4 }))).toBe(
      Math.round(4 * words),
    );
    expect(entropyFor(options({ passphrase: true, words: 99 }))).toBe(
      Math.round(12 * words),
    );
  });
});

describe("optionsAreValid", () => {
  it("accepts passphrases, rejects empty class sets, accepts a single class", () => {
    expect(
      optionsAreValid(
        options({
          passphrase: true,
          lowercase: false,
          uppercase: false,
          digits: false,
          symbols: false,
        }),
      ),
    ).toBe(true);
    expect(
      optionsAreValid(
        options({
          lowercase: false,
          uppercase: false,
          digits: false,
          symbols: false,
        }),
      ),
    ).toBe(false);
    expect(
      optionsAreValid(
        options({
          lowercase: false,
          uppercase: false,
          digits: false,
          symbols: true,
        }),
      ),
    ).toBe(true);
  });
});
