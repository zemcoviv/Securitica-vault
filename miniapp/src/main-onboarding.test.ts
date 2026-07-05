/**
 * End-to-end onboarding through main.ts itself, with the thin backend
 * configured (VITE_SERVER_URL set) — the actual path a real Telegram user
 * takes (BRIEF §1: no email field, no Vaultwarden UI, no KDF choice).
 *
 * Everything main.ts talks to (thin backend /api/provision(/complete),
 * Vaultwarden's register/token/sync) is a single mocked global fetch; no
 * network is used. This is deliberately a wiring test — the crypto and each
 * endpoint already have dedicated unit tests (vault/register.test.ts,
 * tests/security/test_provisioning.py); this proves main.ts assembles them
 * into the right screen at the right time.
 */
// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { encryptBytes } from "./crypto/encstring";
import { deriveMasterKey, DEFAULT_ARGON2_CONFIG } from "./crypto/keys";
import { randomBytes } from "./crypto/primitives";

const PASSWORD = "a-freshly-chosen-master-passphrase";
const TELEGRAM_USER_ID = 424242;
const SYNTHETIC_EMAIL = `tg${TELEGRAM_USER_ID}@securitica.local`;

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

interface Captured {
  url: string;
  method: string;
  body: string;
}

describe("onboarding wiring in main.ts (thin backend configured)", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
    document.body.replaceChildren();
  });

  it("a brand-new Telegram user sees only a password field, then reaches the vault list", async () => {
    vi.stubEnv("VITE_SERVER_URL", "https://server.test");
    vi.stubEnv("VITE_VAULTWARDEN_URL", "https://vault.test");

    document.body.innerHTML = '<main id="app"></main>';

    // Stub Telegram WebApp with initData carrying our test user id.
    (window as unknown as { Telegram: unknown }).Telegram = {
      WebApp: {
        initData: `user=%7B%22id%22%3A${TELEGRAM_USER_ID}%2C%22first_name%22%3A%22Ada%22%7D&auth_date=1`,
        initDataUnsafe: { user: { id: TELEGRAM_USER_ID, first_name: "Ada" } },
        colorScheme: "dark",
        themeParams: {},
        ready: () => {},
        expand: () => {},
      },
    };

    let stored: { mpHash: string; key: string } | null = null;
    const captured: Captured[] = [];

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const method = init?.method ?? "GET";
      const body = typeof init?.body === "string" ? init.body : "";
      captured.push({ url, method, body });

      if (url.endsWith("/api/provision")) {
        return json({ ok: true, email: SYNTHETIC_EMAIL, status: "new" });
      }
      if (url.endsWith("/api/provision/complete")) {
        return json({ ok: true });
      }
      if (url.endsWith("/api/events")) {
        return json({ ok: true, notified: true });
      }
      if (url.endsWith("/api/accounts/register")) {
        const parsed = JSON.parse(body);
        stored = { mpHash: parsed.masterPasswordHash, key: parsed.key };
        return json({});
      }
      if (url.endsWith("/identity/accounts/prelogin")) {
        return json({
          kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          kdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
          kdfMemory: DEFAULT_ARGON2_CONFIG.memoryMiB,
          kdfParallelism: DEFAULT_ARGON2_CONFIG.parallelism,
        });
      }
      if (url.endsWith("/identity/connect/token")) {
        const params = new URLSearchParams(body);
        if (!stored || params.get("password") !== stored.mpHash) {
          return new Response("invalid_grant", { status: 400 });
        }
        return json({
          access_token: "test-token",
          expires_in: 3600,
          token_type: "Bearer",
          Key: stored.key,
          Kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          KdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
        });
      }
      if (url.includes("/api/sync")) {
        return json({ ciphers: [], profile: { email: SYNTHETIC_EMAIL } });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    await import("./main");

    // The provisioning call is async; wait for the password-only form.
    await vi.waitFor(() => expect(document.querySelector("form")).toBeTruthy());

    // No email field anywhere — the whole point of this flow.
    expect(document.querySelector('input[type="email"]')).toBeNull();
    const passwordInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(passwordInput).not.toBeNull();
    expect(document.body.textContent).toContain("Choose a master password");

    passwordInput.value = PASSWORD;
    document
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

    await vi.waitFor(() => expect(document.querySelector(".bar")).toBeTruthy(), {
      timeout: 5000,
    });

    // Registration actually happened, with only ciphertext/hash on the wire.
    const registerCall = captured.find((r) => r.url.endsWith("/api/accounts/register"));
    expect(registerCall).toBeDefined();
    expect(registerCall!.body.includes(PASSWORD)).toBe(false);

    // provision/complete was reported so a future open shows "existing".
    expect(captured.some((r) => r.url.endsWith("/api/provision/complete"))).toBe(true);
  });

  it("a returning user sees only a password field pre-resolved to their email", async () => {
    vi.stubEnv("VITE_SERVER_URL", "https://server.test");
    vi.stubEnv("VITE_VAULTWARDEN_URL", "https://vault.test");
    document.body.innerHTML = '<main id="app"></main>';

    (window as unknown as { Telegram: unknown }).Telegram = {
      WebApp: {
        initData: `user=%7B%22id%22%3A${TELEGRAM_USER_ID}%7D&auth_date=1`,
        initDataUnsafe: { user: { id: TELEGRAM_USER_ID } },
        colorScheme: "dark",
        themeParams: {},
        ready: () => {},
        expand: () => {},
      },
    };

    const { stretchedKey } = await deriveMasterKey(
      SYNTHETIC_EMAIL,
      PASSWORD,
      DEFAULT_ARGON2_CONFIG,
    );
    const rawUserKey = randomBytes(64);
    const protectedUserKey = await encryptBytes(stretchedKey, rawUserKey);

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = typeof init?.body === "string" ? init.body : "";

      if (url.endsWith("/api/provision")) {
        return json({ ok: true, email: SYNTHETIC_EMAIL, status: "existing" });
      }
      if (url.endsWith("/identity/accounts/prelogin")) {
        return json({
          kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          kdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
          kdfMemory: DEFAULT_ARGON2_CONFIG.memoryMiB,
          kdfParallelism: DEFAULT_ARGON2_CONFIG.parallelism,
        });
      }
      if (url.endsWith("/identity/connect/token")) {
        void body;
        return json({
          access_token: "test-token",
          expires_in: 3600,
          token_type: "Bearer",
          Key: protectedUserKey,
          Kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          KdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
        });
      }
      if (url.includes("/api/sync")) {
        return json({ ciphers: [], profile: { email: SYNTHETIC_EMAIL } });
      }
      if (url.endsWith("/api/events")) {
        return json({ ok: true });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    await import("./main");
    await vi.waitFor(() => expect(document.querySelector("form")).toBeTruthy());

    expect(document.querySelector('input[type="email"]')).toBeNull();
    expect(document.body.textContent).not.toContain("Choose a master password");
    const passwordInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    passwordInput.value = PASSWORD;
    document
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

    await vi.waitFor(() => expect(document.querySelector(".bar")).toBeTruthy(), {
      timeout: 5000,
    });
  });

  it("REGRESSION: the real docker-compose build config (DEV=false, VITE_SERVER_URL=\"\") auto-provisions instead of asking for an email", { timeout: 15000 }, async () => {
    // server/Dockerfile always builds with VITE_SERVER_URL="" — same-origin,
    // relative paths, exactly what Caddy serves. main.ts used to read that
    // empty string as "no thin backend" and show the old manual
    // email+password form in EVERY real deployment. Reproduce the exact
    // production build inputs here so this can't silently come back.
    vi.stubEnv("DEV", false);
    vi.stubEnv("VITE_SERVER_URL", "");
    vi.stubEnv("VITE_VAULTWARDEN_URL", "/vault");

    document.body.innerHTML = '<main id="app"></main>';
    (window as unknown as { Telegram: unknown }).Telegram = {
      WebApp: {
        initData: `user=%7B%22id%22%3A${TELEGRAM_USER_ID}%2C%22first_name%22%3A%22Ada%22%7D&auth_date=1`,
        initDataUnsafe: { user: { id: TELEGRAM_USER_ID, first_name: "Ada" } },
        colorScheme: "dark",
        themeParams: {},
        ready: () => {},
        expand: () => {},
      },
    };

    let stored: { mpHash: string; key: string } | null = null;
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      // Relative paths, exactly as a real same-origin browser fetch would send.
      const url = typeof input === "string" ? input : input.toString();
      const body = typeof init?.body === "string" ? init.body : "";

      if (url === "/api/provision") return json({ ok: true, email: SYNTHETIC_EMAIL, status: "new" });
      if (url === "/api/provision/complete") return json({ ok: true });
      if (url === "/api/events") return json({ ok: true, notified: true });
      if (url === "/vault/api/accounts/register") {
        const parsed = JSON.parse(body);
        stored = { mpHash: parsed.masterPasswordHash, key: parsed.key };
        return json({});
      }
      if (url === "/vault/identity/accounts/prelogin") {
        return json({
          kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          kdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
          kdfMemory: DEFAULT_ARGON2_CONFIG.memoryMiB,
          kdfParallelism: DEFAULT_ARGON2_CONFIG.parallelism,
        });
      }
      if (url === "/vault/identity/connect/token") {
        const params = new URLSearchParams(body);
        if (!stored || params.get("password") !== stored.mpHash) {
          return new Response("invalid_grant", { status: 400 });
        }
        return json({
          access_token: "test-token",
          expires_in: 3600,
          token_type: "Bearer",
          Key: stored.key,
          Kdf: DEFAULT_ARGON2_CONFIG.kdfType,
          KdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
        });
      }
      if (url.startsWith("/vault/api/sync")) {
        return json({ ciphers: [], profile: { email: SYNTHETIC_EMAIL } });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    await import("./main");
    await vi.waitFor(() => expect(document.querySelector("form")).toBeTruthy());

    // The bug: this used to render the manual email+password form instead.
    expect(document.querySelector('input[type="email"]')).toBeNull();
    expect(document.body.textContent).toContain("Choose a master password");

    const passwordInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    passwordInput.value = PASSWORD;
    document
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

    await vi.waitFor(() => expect(document.querySelector(".bar")).toBeTruthy(), {
      timeout: 12000,
    });
  });
});
