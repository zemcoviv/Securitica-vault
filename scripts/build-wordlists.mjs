#!/usr/bin/env node
/**
 * One-time extraction of diceware wordlists into static JSON assets.
 *
 * Source packages (BRIEF §6.3: "переиспользовать готовый diceware-генератор
 * (EFF + собранный RU-список"):
 *   - diceware-wordlist-en-eff  — EFF's official long wordlist (7776 words)
 *   - diceware-wordlist-ru     — the matching Russian wordlist (7776 words)
 *
 * We snapshot the word arrays into committed JSON under
 * miniapp/src/generator/wordlists/ instead of shipping the npm packages in
 * the browser bundle: this keeps the reveal-critical static bundle free of a
 * runtime dependency on third-party CommonJS code (BRIEF §9 supply-chain
 * concern) — only plain, diffable data is served to the client. Re-run this
 * script (`node scripts/build-wordlists.mjs`) after bumping either package.
 */
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const outDir = join(dirname(fileURLToPath(import.meta.url)), "..", "miniapp", "src", "generator", "wordlists");

function extract(pkgName) {
  const dice = require(pkgName);
  // Keys are 5-digit dice-roll strings ("11111".."66666"); sort by key so the
  // array order is stable and reproducible across regenerations.
  const words = Object.keys(dice)
    .sort()
    .map((k) => dice[k]);
  if (words.length !== 7776 || new Set(words).size !== 7776) {
    throw new Error(`${pkgName}: expected 7776 unique words, got ${words.length}`);
  }
  return words;
}

const en = extract("diceware-wordlist-en-eff");
const ru = extract("diceware-wordlist-ru");

writeFileSync(join(outDir, "en.json"), JSON.stringify(en) + "\n");
writeFileSync(join(outDir, "ru.json"), JSON.stringify(ru) + "\n");

console.log(`[build-wordlists] wrote ${en.length} EN words + ${ru.length} RU words to ${outDir}`);
