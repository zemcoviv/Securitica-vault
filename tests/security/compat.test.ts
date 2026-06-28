/**
 * BRIEF §11.5 — compatibility.
 *
 * A full proof ("a record made in the Mini App decrypts in the official
 * Bitwarden client and vice-versa") is the M3 manual acceptance against a live
 * Vaultwarden. As the automated CI guard, we verify our EncString type-2
 * implementation is byte-compatible with an INDEPENDENT reference built on
 * Node's `crypto` (OpenSSL) — a different code path from our SubtleCrypto one.
 *
 * Any Bitwarden client implements exactly this envelope: AES-256-CBC then
 * HMAC-SHA256 over iv||ct, serialised as 2.<iv>|<ct>|<mac>. If both directions
 * interop with an OpenSSL-based reference, they interop with Bitwarden.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decryptToString,
  encryptString,
  parseEncString,
  splitSymmetricKey,
  type SymmetricKey,
} from "../../miniapp/src/crypto/encstring";

const b64 = (b: Buffer) => b.toString("base64");

/** Independent (OpenSSL) encrypt → EncString type 2. */
function referenceEncrypt(key: SymmetricKey, plaintext: string): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", Buffer.from(key.encKey), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const mac = createHmac("sha256", Buffer.from(key.macKey))
    .update(Buffer.concat([iv, ct]))
    .digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

/** Independent (OpenSSL) MAC-verify + decrypt of an EncString type 2. */
function referenceDecrypt(key: SymmetricKey, enc: string): string {
  const { iv, ciphertext, mac } = parseEncString(enc);
  const expected = createHmac("sha256", Buffer.from(key.macKey))
    .update(Buffer.concat([Buffer.from(iv), Buffer.from(ciphertext)]))
    .digest();
  if (!expected.equals(Buffer.from(mac))) throw new Error("ref MAC mismatch");
  const decipher = createDecipheriv("aes-256-cbc", Buffer.from(key.encKey), Buffer.from(iv));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext)),
    decipher.final(),
  ]).toString("utf8");
}

describe("§11.5 EncString interop with an independent reference", () => {
  const key = splitSymmetricKey(new Uint8Array(randomBytes(64)));
  const samples = ["hunter2", "пароль-фраза", "with|pipes.and.dots", "🔐 emoji"];

  it("our decrypt reads ciphertext produced by the OpenSSL reference", async () => {
    for (const s of samples) {
      const enc = referenceEncrypt(key, s);
      expect(await decryptToString(key, enc)).toBe(s);
    }
  });

  it("the OpenSSL reference reads ciphertext produced by our encrypt", async () => {
    for (const s of samples) {
      const enc = await encryptString(key, s);
      expect(referenceDecrypt(key, enc)).toBe(s);
    }
  });
});
