/**
 * Account registration (BRIEF §1: the bot is for a broad audience, Bitwarden
 * itself is not — the Mini App must create the Vaultwarden account directly,
 * with no email field, no KDF choice, no admin panel in the user's path).
 *
 * KDF is always DEFAULT_ARGON2_CONFIG (BRIEF §5.1) — there is no user-visible
 * setting to get wrong. The server only accepts this registration for an
 * email with a pending Invitation record; see server/vaultwarden_admin.py for
 * how that invitation is created ahead of time (SIGNUPS_ALLOWED stays false).
 */
import { RegisterConflictError, type VaultwardenClient } from "../api/client";
import { splitSymmetricKey, encryptBytes, type SymmetricKey } from "../crypto/encstring";
import { computeMasterPasswordHash, deriveMasterKey, DEFAULT_ARGON2_CONFIG } from "../crypto/keys";
import { randomBytes, wipe } from "../crypto/primitives";
import { generateAccountKeyPair } from "../crypto/rsa";
import { decryptVault, type VaultItem } from "./model";
import { unlock, type UnlockResult } from "./unlock";

export async function registerAndUnlock(
  client: VaultwardenClient,
  email: string,
  masterPassword: string,
  name?: string,
): Promise<UnlockResult> {
  const kdf = DEFAULT_ARGON2_CONFIG;
  const { masterKey, stretchedKey } = await deriveMasterKey(email, masterPassword, kdf);
  const rawUserKey = randomBytes(64);
  const userKey: SymmetricKey = splitSymmetricKey(rawUserKey);
  let userKeyConsumed = false;

  try {
    const mpHash = await computeMasterPasswordHash(masterKey, masterPassword);
    const protectedUserKey = await encryptBytes(stretchedKey, rawUserKey);
    const { publicKeyB64, encryptedPrivateKey } = await generateAccountKeyPair(userKey);

    try {
      await client.register({
        email,
        masterPasswordHash: mpHash,
        key: protectedUserKey,
        kdf,
        keys: { publicKeyB64, encryptedPrivateKey },
        name,
      });
    } catch (err) {
      if (!(err instanceof RegisterConflictError)) throw err;
      // The account already exists — most likely a previous registration
      // attempt completed but our own /api/provision/complete bookkeeping
      // never got the news. Defer entirely to the normal login path, which
      // re-fetches whatever KDF config that existing account actually uses,
      // rather than assuming our just-generated key material applies to it.
      return await unlock(client, email, masterPassword);
    }

    // Fresh registration: we already hold everything unlock() would
    // re-derive from scratch, so log in directly instead of paying for a
    // second (expensive, memory-hard) Argon2id run.
    userKeyConsumed = true;
    await client.login(email, mpHash);
    const sync = await client.sync();
    const items: VaultItem[] = await decryptVault(userKey, sync);
    return {
      userKey,
      items,
      email: email.trim().toLowerCase(),
      kdf,
      protectedUserKey,
    };
  } finally {
    wipe(masterKey, stretchedKey.encKey, stretchedKey.macKey, rawUserKey);
    if (!userKeyConsumed) wipe(userKey.encKey, userKey.macKey);
  }
}
