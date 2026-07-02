/**
 * Unlock orchestration (§5 + §6.3, M1).
 *
 *   master password ──derive──▶ masterKey ──stretch──▶ stretchedKey
 *        │                          │                        │
 *        └── mpHash (auth only) ────┘                        ▼
 *                                                    login → protectedUserKey
 *                                                            │  unwrap
 *                                                            ▼
 *                                                         userKey ──▶ decrypt list
 *
 * On success, masterKey / stretchedKey are wiped immediately — only the userKey
 * is retained in memory, and only until auto-lock (BRIEF §6.3).
 */
import { VaultwardenClient } from "../api/client";
import {
  computeMasterPasswordHash,
  decryptUserKey,
  deriveMasterKey,
  type KdfConfig,
} from "../crypto/keys";
import { wipe } from "../crypto/primitives";
import type { SymmetricKey } from "../crypto/encstring";
import { decryptVault, type VaultItem } from "./model";

export interface UnlockResult {
  userKey: SymmetricKey;
  items: VaultItem[];
  /** email + KDF config in effect — needed later for a master password change. */
  email: string;
  kdf: KdfConfig;
  /** The wrapped user-key envelope (ciphertext) — needed later for export (§10 M4). */
  protectedUserKey: string;
}

export async function unlock(
  client: VaultwardenClient,
  email: string,
  masterPassword: string,
): Promise<UnlockResult> {
  // 1. prelogin → KDF params (Argon2id).
  const kdf = await client.prelogin(email);

  // 2-3. derive + stretch.
  const { masterKey, stretchedKey } = await deriveMasterKey(
    email,
    masterPassword,
    kdf,
  );

  try {
    // 4. authenticator hash (the only derived value sent to the server).
    const mpHash = await computeMasterPasswordHash(masterKey, masterPassword);

    // 5. login → wrapped user key, then unwrap locally.
    const { protectedUserKey } = await client.login(email, mpHash);
    const userKey = await decryptUserKey(stretchedKey, protectedUserKey);

    // 6. sync + decrypt list in memory.
    const sync = await client.sync();
    const items = await decryptVault(userKey, sync);
    return {
      userKey,
      items,
      email: email.trim().toLowerCase(),
      kdf,
      protectedUserKey,
    };
  } finally {
    // Master/stretched key are no longer needed once the user key is unwrapped.
    wipe(masterKey, stretchedKey.encKey, stretchedKey.macKey);
  }
}
