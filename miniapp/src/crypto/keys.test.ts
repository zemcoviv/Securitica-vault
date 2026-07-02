import { describe, expect, it } from "vitest";
import {
  computeMasterPasswordHash,
  decryptUserKey,
  deriveMasterKey,
  DEFAULT_ARGON2_CONFIG,
  KdfType,
} from "./keys";
import { encryptBytes, splitSymmetricKey } from "./encstring";
import { randomBytes } from "./primitives";

// Keep Argon2 cheap for CI; production params come from prelogin (BRIEF §5.1).
const FAST_KDF = {
  kdfType: KdfType.Argon2id,
  iterations: 1,
  memoryMiB: 8,
  parallelism: 1,
} as const;

describe("key derivation (§5 unlock chain)", () => {
  it("derives a 32-byte master key and a 32/32 stretched key", async () => {
    const { masterKey, stretchedKey } = await deriveMasterKey(
      "user@example.com",
      "master-pass",
      FAST_KDF,
    );
    expect(masterKey.length).toBe(32);
    expect(stretchedKey.encKey.length).toBe(32);
    expect(stretchedKey.macKey.length).toBe(32);
    // enc and mac halves must differ (distinct HKDF info strings).
    expect(Buffer.from(stretchedKey.encKey).equals(Buffer.from(stretchedKey.macKey))).toBe(
      false,
    );
  });

  it("is deterministic and email-normalising", async () => {
    const a = await deriveMasterKey("User@Example.com ", "pw", FAST_KDF);
    const b = await deriveMasterKey("user@example.com", "pw", FAST_KDF);
    expect(Buffer.from(a.masterKey).equals(Buffer.from(b.masterKey))).toBe(true);
  });

  it("produces a base64 master password hash distinct from the master key", async () => {
    const { masterKey } = await deriveMasterKey("u@e.com", "pw", FAST_KDF);
    const hash = await computeMasterPasswordHash(masterKey, "pw");
    expect(typeof hash).toBe("string");
    expect(Buffer.from(hash, "base64").length).toBe(32);
    // The hash sent to the server must not equal the master key itself.
    expect(Buffer.from(hash, "base64").equals(Buffer.from(masterKey))).toBe(false);
  });

  it("rejects PBKDF2 vaults (Argon2id required)", async () => {
    await expect(
      deriveMasterKey("u@e.com", "pw", {
        kdfType: KdfType.PBKDF2_SHA256,
        iterations: 600000,
      }),
    ).rejects.toThrow(/Argon2id/);
  });

  it("unwraps a protected user key end-to-end (simulated server setup)", async () => {
    // Simulate account setup: server stores a protected user key produced by
    // wrapping a random 64-byte user key with the stretched master key.
    const { stretchedKey } = await deriveMasterKey("u@e.com", "pw", FAST_KDF);
    const rawUserKey = randomBytes(64);
    const protectedUserKey = await encryptBytes(stretchedKey, rawUserKey);

    // Unlock path recovers exactly that user key.
    const userKey = await decryptUserKey(stretchedKey, protectedUserKey);
    const expected = splitSymmetricKey(rawUserKey);
    expect(Buffer.from(userKey.encKey).equals(Buffer.from(expected.encKey))).toBe(true);
    expect(Buffer.from(userKey.macKey).equals(Buffer.from(expected.macKey))).toBe(true);
  });

  it("§5.4 extension point: a second factor changes the derived master key", async () => {
    const withoutFactor = await deriveMasterKey("u@e.com", "pw", FAST_KDF);
    const withFactor = await deriveMasterKey(
      "u@e.com",
      "pw",
      FAST_KDF,
      randomBytes(32),
    );
    expect(
      Buffer.from(withoutFactor.masterKey).equals(Buffer.from(withFactor.masterKey)),
    ).toBe(false);
  });

  it("§5.4 extension point: the same second factor is deterministic", async () => {
    const factor = randomBytes(32);
    const a = await deriveMasterKey("u@e.com", "pw", FAST_KDF, factor);
    const b = await deriveMasterKey("u@e.com", "pw", FAST_KDF, factor);
    expect(Buffer.from(a.masterKey).equals(Buffer.from(b.masterKey))).toBe(true);
  });

  it("exposes Argon2id defaults matching BRIEF §5.1", () => {
    expect(DEFAULT_ARGON2_CONFIG.kdfType).toBe(KdfType.Argon2id);
    expect(DEFAULT_ARGON2_CONFIG.memoryMiB).toBe(256);
    expect(DEFAULT_ARGON2_CONFIG.iterations).toBe(3);
    expect(DEFAULT_ARGON2_CONFIG.parallelism).toBe(4);
  });
});
