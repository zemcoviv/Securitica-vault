/**
 * Post-build Subresource Integrity injector (BRIEF §9, §11.6).
 *
 * Vite emits hashed filenames but not SRI integrity attributes. A swapped JS
 * bundle is the main residual risk (exfiltration at reveal time), so we pin
 * every locally-served <script src> and <link rel=stylesheet> with a sha384
 * integrity hash + crossorigin, computed from the actual built bytes.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";

const distDir = process.argv[2] ?? "dist";
const indexPath = join(distDir, "index.html");
let html = readFileSync(indexPath, "utf8");

function sriFor(relPath) {
  const filePath = join(distDir, relPath.replace(/^\//, ""));
  const bytes = readFileSync(filePath);
  const digest = createHash("sha384").update(bytes).digest("base64");
  return `sha384-${digest}`;
}

// Local <script src="/assets/...">
html = html.replace(
  /<script([^>]*?)\ssrc="(\/[^"]+)"([^>]*)><\/script>/g,
  (m, pre, src, post) => {
    if (/integrity=/.test(m)) return m;
    const integrity = sriFor(src);
    return `<script${pre} src="${src}"${post} integrity="${integrity}" crossorigin="anonymous"></script>`;
  },
);

// Local <link rel="stylesheet" href="/assets/...">
html = html.replace(
  /<link([^>]*?)\shref="(\/[^"]+)"([^>]*)>/g,
  (m, pre, href, post) => {
    if (!/stylesheet/.test(m) || /integrity=/.test(m)) return m;
    const integrity = sriFor(href);
    return `<link${pre} href="${href}"${post} integrity="${integrity}" crossorigin="anonymous">`;
  },
);

writeFileSync(indexPath, html);
void dirname; // (kept for clarity; path helpers imported above)
console.log(`[inject-sri] integrity attributes written to ${indexPath}`);
