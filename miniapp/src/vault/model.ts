/**
 * Vault model — decrypt a sync response into a list of records, in memory only.
 *
 * BRIEF §6.3 / M1: "отображение расшифрованного списка записей". Decryption
 * uses the user key (never the server). Cipher fields arrive as EncStrings; we
 * decrypt name + username for the list and lazily decrypt the password only at
 * reveal time (M2). For M1 the password EncString is retained but NOT decrypted
 * eagerly, minimising the plaintext window.
 */
import { decryptToString, type SymmetricKey } from "../crypto/encstring";
import type { CipherResponse, SyncResponse } from "../api/client";

export interface VaultItem {
  id: string;
  /** Decrypted display name. */
  name: string;
  /** Decrypted username, if present. */
  username: string | null;
  /** First decrypted URI host, for display. */
  uriHost: string | null;
  /** Encrypted password EncString — decrypted only on demand (M2 reveal). */
  encryptedPassword: string | null;
  revisionDate: string;
}

async function safeDecrypt(
  userKey: SymmetricKey,
  enc: string | null | undefined,
): Promise<string | null> {
  if (!enc) return null;
  try {
    return await decryptToString(userKey, enc);
  } catch {
    // A single corrupt field must not blank the whole list.
    return null;
  }
}

function hostOf(uri: string | null): string | null {
  if (!uri) return null;
  try {
    return new URL(uri).host || uri;
  } catch {
    return uri;
  }
}

async function decryptCipher(
  userKey: SymmetricKey,
  cipher: CipherResponse,
): Promise<VaultItem> {
  const firstUri = cipher.login?.uris?.[0]?.uri ?? null;
  return {
    id: cipher.id,
    name: (await safeDecrypt(userKey, cipher.name)) ?? "(no name)",
    username: await safeDecrypt(userKey, cipher.login?.username),
    uriHost: hostOf(await safeDecrypt(userKey, firstUri)),
    encryptedPassword: cipher.login?.password ?? null,
    revisionDate: cipher.revisionDate,
  };
}

/** Decrypt all login-type ciphers (type 1) into display items. */
export async function decryptVault(
  userKey: SymmetricKey,
  sync: SyncResponse,
): Promise<VaultItem[]> {
  const items = await Promise.all(
    sync.ciphers
      .filter((c) => c.type === 1 /* login */)
      .map((c) => decryptCipher(userKey, c)),
  );
  return items.sort((a, b) => a.name.localeCompare(b.name));
}
