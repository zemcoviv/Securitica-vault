/**
 * BRIEF §11.6 — CSP / SRI audit. Run after `npm run build`.
 *
 * Asserts the built index.html:
 *   - has a CSP with no 'unsafe-inline' / 'unsafe-eval' in script-src,
 *   - pulls scripts only from 'self' or telegram.org (no third-party CDNs),
 *   - carries SRI integrity on every locally-served script/style.
 * Exits non-zero on any violation so CI fails loudly.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const distDir = process.argv[2] ?? "dist";
const html = readFileSync(join(distDir, "index.html"), "utf8");
const failures = [];

// --- CSP presence + no unsafe-inline scripts ---
const cspMatch = html.match(
  /<meta[^>]+http-equiv="Content-Security-Policy"[^>]+content="([^"]+)"/i,
);
if (!cspMatch) {
  failures.push("no Content-Security-Policy meta tag found");
} else {
  const csp = cspMatch[1];
  const scriptSrc = (csp.match(/script-src([^;]*)/) ?? [, ""])[1];
  if (/unsafe-inline/.test(scriptSrc)) {
    failures.push("script-src contains 'unsafe-inline'");
  }
  if (/unsafe-eval/.test(scriptSrc)) {
    failures.push("script-src contains 'unsafe-eval'");
  }
  // Allowed script origins: 'self' and telegram.org only.
  const tokens = scriptSrc.trim().split(/\s+/).filter(Boolean);
  for (const t of tokens) {
    if (!["'self'", "https://telegram.org"].includes(t)) {
      failures.push(`unexpected script-src origin: ${t}`);
    }
  }
}

// --- SRI on every local script/style ---
const localScripts = [...html.matchAll(/<script[^>]*\ssrc="(\/[^"]+)"[^>]*>/g)];
for (const m of localScripts) {
  if (!/integrity="sha\d{3}-/.test(m[0])) {
    failures.push(`local script missing SRI integrity: ${m[1]}`);
  }
}
const localStyles = [...html.matchAll(/<link[^>]*stylesheet[^>]*>/g)];
for (const m of localStyles) {
  if (/href="\//.test(m[0]) && !/integrity="sha\d{3}-/.test(m[0])) {
    failures.push(`local stylesheet missing SRI integrity`);
  }
}

if (failures.length) {
  console.error("[csp-audit] FAILED:\n  - " + failures.join("\n  - "));
  process.exit(1);
}
console.log("[csp-audit] OK — strict CSP, no unsafe-inline, SRI present.");
