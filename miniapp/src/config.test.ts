/**
 * Regression test for a real deployment bug: server/Dockerfile always builds
 * the production bundle with VITE_SERVER_URL="" (same-origin, relative
 * paths — Caddy serves miniapp-server's /api/* alongside the static bundle
 * at one domain). main.ts used to read `config.serverUrl === ""` as "no thin
 * backend configured" and fell back to the old manual email+password form —
 * meaning EVERY real deployment silently skipped auto-provisioning and asked
 * for an email, exactly the Bitwarden-specialist UX BRIEF §1 was written to
 * eliminate. `hasThinBackend` must be driven by Vite's DEV/PROD distinction,
 * not by whether serverUrl happens to be the (valid, same-origin) empty
 * string.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

describe("config.hasThinBackend", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("is true in a production build even with serverUrl=\"\" (same-origin) — the real docker-compose case", async () => {
    vi.stubEnv("DEV", false);
    vi.stubEnv("VITE_SERVER_URL", "");
    const { config } = await import("./config");
    expect(config.serverUrl).toBe("");
    expect(config.hasThinBackend).toBe(true);
  });

  it("is false in dev mode with no VITE_SERVER_URL set (bare `npm run dev`)", async () => {
    vi.stubEnv("DEV", true);
    vi.stubEnv("VITE_SERVER_URL", "");
    const { config } = await import("./config");
    expect(config.hasThinBackend).toBe(false);
  });

  it("is true in dev mode when a developer points VITE_SERVER_URL at a real backend", async () => {
    vi.stubEnv("DEV", true);
    vi.stubEnv("VITE_SERVER_URL", "http://localhost:8000");
    const { config } = await import("./config");
    expect(config.hasThinBackend).toBe(true);
  });

  it("is true in a production build with a non-empty serverUrl too", async () => {
    vi.stubEnv("DEV", false);
    vi.stubEnv("VITE_SERVER_URL", "https://vault.example.com");
    const { config } = await import("./config");
    expect(config.hasThinBackend).toBe(true);
  });
});
