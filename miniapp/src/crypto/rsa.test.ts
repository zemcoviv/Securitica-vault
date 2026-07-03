import { describe, expect, it } from "vitest";
import { decryptToBytes, splitSymmetricKey } from "./encstring";
import { randomBytes } from "./primitives";
import { generateAccountKeyPair } from "./rsa";

describe("account RSA keypair (Bitwarden registration requirement)", () => {
  it("generates a public key and an EncString-wrapped private key", async () => {
    const userKey = splitSymmetricKey(randomBytes(64));
    const { publicKeyB64, encryptedPrivateKey } = await generateAccountKeyPair(userKey);

    expect(publicKeyB64.length).toBeGreaterThan(200); // SPKI DER for RSA-2048, base64
    expect(encryptedPrivateKey.startsWith("2.")).toBe(true); // EncString type 2

    // Public key must decode to valid SPKI DER importable back as a key.
    const der = Uint8Array.from(atob(publicKeyB64), (c) => c.charCodeAt(0));
    const imported = await crypto.subtle.importKey(
      "spki",
      der,
      { name: "RSA-OAEP", hash: "SHA-1" },
      true,
      ["encrypt"],
    );
    expect(imported.type).toBe("public");
  });

  it("the private key decrypts to valid PKCS8 DER under the same userKey", async () => {
    const userKey = splitSymmetricKey(randomBytes(64));
    const { encryptedPrivateKey } = await generateAccountKeyPair(userKey);

    const pkcs8 = await decryptToBytes(userKey, encryptedPrivateKey);
    const imported = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "RSA-OAEP", hash: "SHA-1" },
      true,
      ["decrypt"],
    );
    expect(imported.type).toBe("private");
  });

  it("the wrong userKey fails to decrypt the private key (MAC check)", async () => {
    const userKey = splitSymmetricKey(randomBytes(64));
    const otherKey = splitSymmetricKey(randomBytes(64));
    const { encryptedPrivateKey } = await generateAccountKeyPair(userKey);

    await expect(decryptToBytes(otherKey, encryptedPrivateKey)).rejects.toThrow();
  });

  it("generates a fresh keypair every call", async () => {
    const userKey = splitSymmetricKey(randomBytes(64));
    const a = await generateAccountKeyPair(userKey);
    const b = await generateAccountKeyPair(userKey);
    expect(a.publicKeyB64).not.toBe(b.publicKeyB64);
  });
});
