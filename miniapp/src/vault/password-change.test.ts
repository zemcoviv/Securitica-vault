import { describe, expect, it, vi } from "vitest";
import { changeMasterPassword } from "./password-change";
import { KdfType } from "../crypto/keys";
import { decryptToBytes, joinSymmetricKey, splitSymmetricKey } from "../crypto/encstring";
import { randomBytes } from "../crypto/primitives";
import { deriveMasterKey } from "../crypto/keys";
import type { VaultwardenClient } from "../api/client";

const FAST_KDF = {
  kdfType: KdfType.Argon2id,
  iterations: 1,
  memoryMiB: 8,
  parallelism: 1,
};

describe("§5.3 master password change", () => {
  it("re-wraps the SAME user key under a newly-derived stretched key", async () => {
    const email = "user@example.com";
    const userKey = splitSymmetricKey(randomBytes(64));

    let captured: Parameters<VaultwardenClient["changeMasterPassword"]>[0] | null = null;
    const fakeClient = {
      changeMasterPassword: vi.fn(async (params) => {
        captured = params;
      }),
    } as unknown as VaultwardenClient;

    await changeMasterPassword(fakeClient, {
      email,
      oldMasterPassword: "old-pass",
      newMasterPassword: "new-pass-much-longer",
      kdf: FAST_KDF,
      userKey,
    });

    expect(fakeClient.changeMasterPassword).toHaveBeenCalledOnce();
    expect(captured).not.toBeNull();
    const { oldMasterPasswordHash, newMasterPasswordHash, newProtectedUserKey } = captured!;

    // Hashes must differ (different passwords -> different masterKeys).
    expect(oldMasterPasswordHash).not.toBe(newMasterPasswordHash);

    // The envelope must unwrap, under the NEW derivation, to the SAME user key
    // — proving no cipher needs re-encryption, only the envelope changed.
    const { stretchedKey: newStretched } = await deriveMasterKey(
      email,
      "new-pass-much-longer",
      FAST_KDF,
    );
    const unwrapped = splitSymmetricKey(
      await decryptToBytes(newStretched, newProtectedUserKey),
    );
    expect(Buffer.from(unwrapped.encKey).equals(Buffer.from(userKey.encKey))).toBe(true);
    expect(Buffer.from(unwrapped.macKey).equals(Buffer.from(userKey.macKey))).toBe(true);

    // The OLD stretched key must NOT unwrap the new envelope (proves the
    // envelope was actually re-wrapped, not left as-is).
    const { stretchedKey: oldStretched } = await deriveMasterKey(email, "old-pass", FAST_KDF);
    await expect(decryptToBytes(oldStretched, newProtectedUserKey)).rejects.toThrow();
  });

  it("joinSymmetricKey is the exact inverse of splitSymmetricKey", () => {
    const raw = randomBytes(64);
    const split = splitSymmetricKey(raw);
    const rejoined = joinSymmetricKey(split);
    expect(Buffer.from(rejoined).equals(Buffer.from(raw))).toBe(true);
  });
});
