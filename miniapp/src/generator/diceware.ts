/**
 * Diceware passphrase generator (BRIEF §6.3, §12: "не изобретать крипто" —
 * this reuses the standard diceware method with the official EFF wordlist
 * plus a matching Russian wordlist, snapshotted as static JSON assets by
 * scripts/build-wordlists.mjs from the `diceware-wordlist-en-eff` /
 * `diceware-wordlist-ru` packages).
 *
 * Diceware security comes from two things, both satisfied here:
 *   1. A CSPRNG source for word selection (crypto.getRandomValues, via
 *      randomIndex — rejection sampling, no modulo bias).
 *   2. Length (word count) over character complexity: strength scales with
 *      log2(listSize) bits per word, not with special-character stuffing.
 *
 * The word IDENTITY doesn't matter for security, only list size (7776 = 6^5,
 * ~12.9 bits/word) and uniform sampling do — so a locale swap (EN/RU) changes
 * nothing about the passphrase's strength.
 */
import en from "./wordlists/en.json";
import ru from "./wordlists/ru.json";
import { randomBytes } from "../crypto/primitives";

export type WordlistLocale = "en" | "ru";

const WORDLISTS: Record<WordlistLocale, readonly string[]> = {
  en: en as string[],
  ru: ru as string[],
};

export interface DicewareOptions {
  /** Number of words in the passphrase. BRIEF favours length over complexity. */
  wordCount: number;
  locale?: WordlistLocale;
  /** Separator between words. */
  separator?: string;
  /** Uppercase the first letter of each word (readability, not entropy). */
  capitalize?: boolean;
  /** Append a random digit (0-9) to the passphrase for sites that require one. */
  includeDigit?: boolean;
}

export interface DicewareResult {
  passphrase: string;
  wordCount: number;
  locale: WordlistLocale;
  /** Total entropy in bits, for display ("~103 bits"). */
  entropyBits: number;
}

/**
 * Uniform random index in [0, listSize) via rejection sampling over a CSPRNG
 * byte stream — avoids the modulo-bias that `randomByte % listSize` would
 * introduce (listSize=7776 doesn't evenly divide 256^k for small k).
 */
function uniformRandomIndex(listSize: number): number {
  if (listSize <= 0) throw new Error("uniformRandomIndex: listSize must be positive");
  const bitsNeeded = Math.ceil(Math.log2(listSize));
  const bytesNeeded = Math.ceil(bitsNeeded / 8);
  const mask = (1 << bitsNeeded) - 1;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const bytes = randomBytes(bytesNeeded);
    let value = 0;
    for (let i = 0; i < bytes.length; i++) value = (value << 8) | bytes[i];
    value &= mask;
    if (value < listSize) return value;
  }
}

function pickWord(list: readonly string[]): string {
  return list[uniformRandomIndex(list.length)];
}

export function entropyBitsFor(wordCount: number, listSize: number): number {
  return wordCount * Math.log2(listSize);
}

export function generateDiceware(options: DicewareOptions): DicewareResult {
  const {
    wordCount,
    locale = "en",
    separator = "-",
    capitalize = false,
    includeDigit = false,
  } = options;

  if (wordCount < 3) {
    throw new Error("generateDiceware: wordCount must be at least 3 for adequate entropy");
  }

  const list = WORDLISTS[locale];
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const w = pickWord(list);
    words.push(capitalize ? w[0].toUpperCase() + w.slice(1) : w);
  }

  let passphrase = words.join(separator);
  let entropyBits = entropyBitsFor(wordCount, list.length);

  if (includeDigit) {
    const digit = uniformRandomIndex(10);
    passphrase += String(digit);
    entropyBits += Math.log2(10);
  }

  return { passphrase, wordCount, locale, entropyBits: Math.round(entropyBits * 10) / 10 };
}

export function wordlistSize(locale: WordlistLocale): number {
  return WORDLISTS[locale].length;
}
