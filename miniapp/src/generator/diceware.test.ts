import { describe, expect, it } from "vitest";
import { entropyBitsFor, generateDiceware, wordlistSize } from "./diceware";

describe("diceware generator", () => {
  it("both wordlists are the canonical 7776-word diceware size", () => {
    expect(wordlistSize("en")).toBe(7776);
    expect(wordlistSize("ru")).toBe(7776);
  });

  it("generates the requested number of words joined by the separator", () => {
    const { passphrase, wordCount } = generateDiceware({ wordCount: 5 });
    expect(wordCount).toBe(5);
    expect(passphrase.split("-")).toHaveLength(5);
  });

  it("supports a custom separator and capitalization", () => {
    const { passphrase } = generateDiceware({
      wordCount: 4,
      separator: " ",
      capitalize: true,
    });
    const words = passphrase.split(" ");
    expect(words).toHaveLength(4);
    for (const w of words) {
      expect(w[0]).toBe(w[0].toUpperCase());
    }
  });

  it("can append a random digit", () => {
    const { passphrase } = generateDiceware({ wordCount: 4, includeDigit: true });
    expect(/\d$/.test(passphrase)).toBe(true);
  });

  it("draws from the Russian wordlist when locale=ru", () => {
    const { passphrase } = generateDiceware({ wordCount: 4, locale: "ru" });
    // Cyrillic-only words (allow the "-" separator).
    expect(/^[а-яё-]+$/i.test(passphrase)).toBe(true);
  });

  it("rejects too-short passphrases (inadequate entropy)", () => {
    expect(() => generateDiceware({ wordCount: 2 })).toThrow(/at least 3/);
  });

  it("computes ~12.9 bits of entropy per word for a 7776-word list", () => {
    const bits = entropyBitsFor(6, 7776);
    expect(bits).toBeCloseTo(6 * Math.log2(7776), 5);
    expect(bits).toBeGreaterThan(77); // 6 words * ~12.92 bits ≈ 77.5 bits
  });

  it("is not obviously biased across many draws (basic sanity, not a full statistical test)", () => {
    const counts = new Map<string, number>();
    const N = 20_000;
    for (let i = 0; i < N; i++) {
      const firstWord = generateDiceware({ wordCount: 3 }).passphrase.split("-")[0];
      counts.set(firstWord, (counts.get(firstWord) ?? 0) + 1);
    }
    // With 7776 buckets and 20000 draws, expected ~2.57/bucket; no single
    // word should dominate if selection is uniform rejection-sampled.
    const max = Math.max(...counts.values());
    expect(max).toBeLessThan(N / 20); // generous bound, catches gross bias
  });

  it("produces different passphrases across calls (no fixed seed)", () => {
    const a = generateDiceware({ wordCount: 6 }).passphrase;
    const b = generateDiceware({ wordCount: 6 }).passphrase;
    expect(a).not.toBe(b);
  });
});
