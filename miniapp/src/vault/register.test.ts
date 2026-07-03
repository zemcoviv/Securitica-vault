import { describe, expect, it } from "vitest";
import { RegisterConflictError, VaultwardenClient } from "../api/client";
import { decryptToBytes } from "../crypto/encstring";
import { deriveMasterKey, DEFAULT_ARGON2_CONFIG } from "../crypto/keys";
import { registerAndUnlock } from "./register";

const EMAIL = "tg12345@securitica.local";
const MASTER_PASSWORD = "a-freshly-chosen-master-passphrase";

interface CapturedRequest {
  url: string;
  method: string;
  body: string;
}

function buildFakeServer(opts: {
  captured: CapturedRequest[];
  registerShouldConflict?: boolean;
}): { fetchImpl: typeof fetch; getStoredAccount: () => { key: string } | null } {
  let stored: { mpHash: string; key: string } | null = null;
  let accessToken = "";

  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? init.body : "";
    opts.captured.push({ url, method, body });

    const json = (obj: unknown, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json" },
      });

    if (url.endsWith("/api/accounts/register")) {
      if (opts.registerShouldConflict || stored) {
        return json({ message: "Registration not allowed or user already exists" }, 400);
      }
      const parsed = JSON.parse(body);
      stored = { mpHash: parsed.masterPasswordHash, key: parsed.key };
      return json({});
    }
    if (url.endsWith("/identity/accounts/prelogin")) {
      // Must mirror whatever KDF the account was ACTUALLY registered with
      // (registerAndUnlock always uses DEFAULT_ARGON2_CONFIG) — a real
      // Vaultwarden returns the account's real config here, not a fixed one.
      return json({
        kdf: DEFAULT_ARGON2_CONFIG.kdfType,
        kdfIterations: DEFAULT_ARGON2_CONFIG.iterations,
        kdfMemory: DEFAULT_ARGON2_CONFIG.memoryMiB,
        kdfParallelism: DEFAULT_ARGON2_CONFIG.parallelism,
      });
    }
    if (url.endsWith("/identity/connect/token")) {
      const params = new URLSearchParams(body);
      const providedHash = params.get("password");
      if (!stored || providedHash !== stored.mpHash) {
        return new Response("invalid_grant", { status: 400 });
      }
      accessToken = "test-token";
      return json({
        access_token: accessToken,
        expires_in: 3600,
        token_type: "Bearer",
        Key: stored.key,
        Kdf: DEFAULT_ARGON2_CONFIG.kdfType,
        KdfIterations: 1,
      });
    }
    if (url.includes("/api/sync")) {
      return json({ ciphers: [], profile: { email: EMAIL } });
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;

  return { fetchImpl, getStoredAccount: () => stored };
}

describe("registerAndUnlock", () => {
  it("registers a fresh account and unlocks it without a second Argon2id run", async () => {
    const captured: CapturedRequest[] = [];
    const { fetchImpl } = buildFakeServer({ captured });
    const client = new VaultwardenClient({
      baseUrl: "https://vault.test",
      deviceIdentifier: "test-device",
      fetchImpl,
    });

    const result = await registerAndUnlock(client, EMAIL, MASTER_PASSWORD, "Test User");

    expect(result.email).toBe(EMAIL);
    expect(result.items).toEqual([]);
    expect(result.userKey.encKey.length).toBe(32);
    expect(result.userKey.macKey.length).toBe(32);

    // Only one prelogin call: the direct login below register() does NOT
    // re-run prelogin (that only happens inside the conflict-fallback path).
    const preloginCalls = captured.filter((r) => r.url.includes("prelogin"));
    expect(preloginCalls).toHaveLength(0);
  });

  it("never sends the master password or raw key material — only ciphertext and a public key", async () => {
    const captured: CapturedRequest[] = [];
    const { fetchImpl } = buildFakeServer({ captured });
    const client = new VaultwardenClient({
      baseUrl: "https://vault.test",
      deviceIdentifier: "test-device",
      fetchImpl,
    });

    await registerAndUnlock(client, EMAIL, MASTER_PASSWORD, "Test User");

    const registerCall = captured.find((r) => r.url.endsWith("/api/accounts/register"));
    expect(registerCall).toBeDefined();
    const payload = JSON.parse(registerCall!.body);

    expect(JSON.stringify(payload)).not.toContain(MASTER_PASSWORD);
    expect(payload.key).toMatch(/^2\./); // EncString, ciphertext
    expect(payload.keys.encryptedPrivateKey).toMatch(/^2\./); // EncString, ciphertext
    expect(typeof payload.keys.publicKey).toBe("string"); // public, fine in the clear
    expect(payload.masterPasswordHash).not.toBe(MASTER_PASSWORD);

    for (const req of captured) {
      expect(req.body.includes(MASTER_PASSWORD)).toBe(false);
    }
  });

  it("the registered account's protected user key actually unwraps with the typed password", async () => {
    const captured: CapturedRequest[] = [];
    const { fetchImpl, getStoredAccount } = buildFakeServer({ captured });
    const client = new VaultwardenClient({
      baseUrl: "https://vault.test",
      deviceIdentifier: "test-device",
      fetchImpl,
    });

    await registerAndUnlock(client, EMAIL, MASTER_PASSWORD, "Test User");
    const stored = getStoredAccount();
    expect(stored).not.toBeNull();

    const { stretchedKey } = await deriveMasterKey(EMAIL, MASTER_PASSWORD, DEFAULT_ARGON2_CONFIG);
    // Should decrypt without throwing — proves the envelope really was
    // wrapped under a stretched key derived from this exact password.
    await expect(decryptToBytes(stretchedKey, stored!.key)).resolves.toBeInstanceOf(Uint8Array);
  });

  it("falls back to a normal login when the account already exists (conflict)", async () => {
    const captured: CapturedRequest[] = [];
    // Pre-provision the "existing" account via one registration...
    const { fetchImpl } = buildFakeServer({ captured });
    const client = new VaultwardenClient({
      baseUrl: "https://vault.test",
      deviceIdentifier: "test-device",
      fetchImpl,
    });
    await registerAndUnlock(client, EMAIL, MASTER_PASSWORD);
    captured.length = 0; // reset the capture log

    // ...then call registerAndUnlock again with the SAME client/fetch (the
    // fake server now reports a conflict on /register), simulating a client
    // that thinks it still needs to register.
    const result = await registerAndUnlock(client, EMAIL, MASTER_PASSWORD);
    expect(result.email).toBe(EMAIL);

    // This time it MUST go through prelogin (the conflict fallback calls
    // the real unlock(), which re-derives from the account's actual KDF).
    const preloginCalls = captured.filter((r) => r.url.includes("prelogin"));
    expect(preloginCalls.length).toBeGreaterThanOrEqual(1);
  });

  it("propagates non-conflict registration errors", async () => {
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/api/accounts/register")) {
        return new Response("boom", { status: 500 });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;
    const client = new VaultwardenClient({
      baseUrl: "https://vault.test",
      deviceIdentifier: "test-device",
      fetchImpl,
    });

    await expect(registerAndUnlock(client, EMAIL, MASTER_PASSWORD)).rejects.not.toBeInstanceOf(
      RegisterConflictError,
    );
  });
});
