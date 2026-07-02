/**
 * Create/edit flow (BRIEF §6.3, §10 M3): "Создание пароля = генерация →
 * шифрование userKey → push в Vaultwarden как EncString."
 *
 * Only ciphertext ever reaches VaultwardenClient.createCipher/updateCipher —
 * every field is encrypted here, in the WebView, before the API call.
 *
 * Password and notes use a "blank means unchanged" convention on edit: we
 * never decrypt the stored password just to prefill a form (that would be an
 * un-gated reveal), and notes are only decrypted for editing behind the same
 * biometric gate the M2 reveal flow uses — they may hold recovery codes.
 */
import type { VaultwardenClient } from "../api/client";
import { encryptString, type SymmetricKey } from "../crypto/encstring";

export interface ItemFormValues {
  name: string;
  username: string;
  /** Empty string means "leave the existing password unchanged" when editing. */
  password: string;
  uri: string;
  /** Empty string means "leave the existing notes unchanged" when editing. */
  notes: string;
}

async function encryptOrNull(
  userKey: SymmetricKey,
  value: string,
): Promise<string | null> {
  const trimmed = value.trim();
  return trimmed ? encryptString(userKey, trimmed) : null;
}

/** Create a brand-new item. Every non-empty field is encrypted before sending. */
export async function createItem(
  client: VaultwardenClient,
  userKey: SymmetricKey,
  values: ItemFormValues,
): Promise<{ id: string }> {
  return client.createCipher({
    name: await encryptString(userKey, values.name.trim() || "(no name)"),
    username: await encryptOrNull(userKey, values.username),
    password: await encryptOrNull(userKey, values.password),
    uri: await encryptOrNull(userKey, values.uri),
    notes: await encryptOrNull(userKey, values.notes),
  });
}

/**
 * Update an existing item. `keepPassword`/`keepNotes` are the item's current
 * EncStrings, reused verbatim when the corresponding form field was left
 * blank — this is how "unchanged" is expressed without ever decrypting the
 * old value.
 */
export async function updateItem(
  client: VaultwardenClient,
  userKey: SymmetricKey,
  id: string,
  values: ItemFormValues,
  existing: { password: string | null; notes: string | null },
): Promise<void> {
  const password = values.password.trim()
    ? await encryptString(userKey, values.password.trim())
    : existing.password;
  const notes = values.notes.trim()
    ? await encryptString(userKey, values.notes.trim())
    : existing.notes;

  await client.updateCipher(id, {
    name: await encryptString(userKey, values.name.trim() || "(no name)"),
    username: await encryptOrNull(userKey, values.username),
    password,
    uri: await encryptOrNull(userKey, values.uri),
    notes,
  });
}
