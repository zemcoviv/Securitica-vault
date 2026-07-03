/**
 * Account RSA keypair (Bitwarden registration requirement).
 *
 * Every Bitwarden account carries an RSA-2048 keypair (RSA-OAEP/SHA-1, the
 * long-standing Bitwarden convention) used for org/collection sharing and
 * emergency access. Securitica never uses these keys itself — no org
 * features are in scope — but `POST /api/accounts/register` requires them,
 * and omitting them would leave an account an official Bitwarden client
 * might later treat as malformed if the user ever enables sharing.
 *
 * The private key is protected exactly like any other cipher field: AES-256
 * EncString type 2 under the account's userKey (BRIEF §5.2), never the
 * master key. The public key isn't a secret — it's sent to the server in
 * the clear, same as any public key.
 */
import { encryptBytes, type SymmetricKey } from "./encstring";

const subtle: SubtleCrypto = globalThis.crypto.subtle;

const RSA_ALGORITHM: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: "SHA-1",
};

export interface AccountKeyPair {
  /** Base64 SPKI-encoded public key — not a secret, sent as-is. */
  publicKeyB64: string;
  /** EncString type 2: the PKCS8 private key, encrypted under userKey. */
  encryptedPrivateKey: string;
}

function toBase64(bytes: ArrayBuffer): string {
  let binary = "";
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary);
}

/**
 * Generate a fresh account RSA keypair and wrap the private key under the
 * given (freshly-generated, not-yet-registered) userKey.
 */
export async function generateAccountKeyPair(
  userKey: SymmetricKey,
): Promise<AccountKeyPair> {
  const { publicKey, privateKey } = await subtle.generateKey(RSA_ALGORITHM, true, [
    "encrypt",
    "decrypt",
  ]);

  const publicKeyDer = await subtle.exportKey("spki", publicKey);
  const privateKeyDer = await subtle.exportKey("pkcs8", privateKey);

  const encryptedPrivateKey = await encryptBytes(
    userKey,
    new Uint8Array(privateKeyDer),
  );

  return {
    publicKeyB64: toBase64(publicKeyDer),
    encryptedPrivateKey,
  };
}
