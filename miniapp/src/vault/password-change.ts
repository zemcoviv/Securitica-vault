/**
 * Master password change (BRIEF §5.3, M4):
 * "Перевыпуск masterKey/stretchedKey и перешифровка ТОЛЬКО userKey (envelope),
 * без переш­ифровки всех записей."
 *
 * The user key itself never changes — only the envelope wrapping it is
 * re-encrypted under a freshly-derived stretched key. Every cipher stays
 * exactly as it was; this is why a password change is cheap regardless of
 * vault size.
 */
import type { VaultwardenClient } from "../api/client";
import { encryptBytes, joinSymmetricKey, type SymmetricKey } from "../crypto/encstring";
import {
  computeMasterPasswordHash,
  deriveMasterKey,
  type KdfConfig,
} from "../crypto/keys";
import { wipe } from "../crypto/primitives";

export interface ChangeMasterPasswordParams {
  email: string;
  oldMasterPassword: string;
  newMasterPassword: string;
  /** The KDF config currently in effect (from prelogin at unlock time). */
  kdf: KdfConfig;
  /** The live, unwrapped user key — unchanged by this operation. */
  userKey: SymmetricKey;
}

export async function changeMasterPassword(
  client: VaultwardenClient,
  params: ChangeMasterPasswordParams,
): Promise<void> {
  const { email, oldMasterPassword, newMasterPassword, kdf, userKey } = params;

  const oldDerived = await deriveMasterKey(email, oldMasterPassword, kdf);
  const newDerived = await deriveMasterKey(email, newMasterPassword, kdf);

  try {
    const oldMasterPasswordHash = await computeMasterPasswordHash(
      oldDerived.masterKey,
      oldMasterPassword,
    );
    const newMasterPasswordHash = await computeMasterPasswordHash(
      newDerived.masterKey,
      newMasterPassword,
    );

    // Re-wrap the SAME user key under the newly-derived stretched key. No
    // cipher is re-encrypted — this is the whole point of the envelope design.
    const newProtectedUserKey = await encryptBytes(
      newDerived.stretchedKey,
      joinSymmetricKey(userKey),
    );

    await client.changeMasterPassword({
      oldMasterPasswordHash,
      newMasterPasswordHash,
      newProtectedUserKey,
    });
  } finally {
    wipe(
      oldDerived.masterKey,
      oldDerived.stretchedKey.encKey,
      oldDerived.stretchedKey.macKey,
      newDerived.masterKey,
      newDerived.stretchedKey.encKey,
      newDerived.stretchedKey.macKey,
    );
  }
}
