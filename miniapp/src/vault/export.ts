/**
 * Offline vault export (BRIEF §9, §10 M4: "экспорт восстанавливается офлайн").
 *
 * The export is a repackaging of what Vaultwarden already stores: the
 * `protectedUserKey` envelope and every cipher's EncStrings, plus the KDF
 * parameters and email needed to re-derive keys. Nothing is decrypted to
 * build it — it is exactly as ciphertext-only as sync traffic (§11.1). What
 * changes hands is a *backup of the encrypted state*, not a recovery
 * shortcut: restoring it still requires the master password, offline, via
 * the same crypto core (deriveMasterKey → decryptUserKey → decryptVault) —
 * no server contact needed to decrypt.
 */
import type { VaultwardenClient, CipherResponse } from "../api/client";
import { decryptUserKey } from "../crypto/keys";
import { deriveMasterKey, type KdfConfig } from "../crypto/keys";
import { decryptVault, type VaultItem } from "./model";

export const EXPORT_VERSION = 1 as const;

export interface VaultExport {
  version: typeof EXPORT_VERSION;
  email: string;
  kdf: KdfConfig;
  /** EncString — ciphertext, wrapped under the CURRENT stretched key. */
  protectedUserKey: string;
  /** Raw ciphers as Vaultwarden returns them — every field still an EncString. */
  ciphers: CipherResponse[];
  exportedAt: string;
}

/** Build the export payload. Encrypts nothing new; decrypts nothing. */
export async function buildExport(
  client: VaultwardenClient,
  email: string,
  kdf: KdfConfig,
  protectedUserKey: string,
): Promise<VaultExport> {
  const sync = await client.sync();
  return {
    version: EXPORT_VERSION,
    email,
    kdf,
    protectedUserKey,
    ciphers: sync.ciphers,
    exportedAt: new Date().toISOString(),
  };
}

/** Trigger a browser download of the export as a JSON file. */
export function downloadExport(data: VaultExport): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `securitica-vault-export-${data.exportedAt.replace(/[:.]/g, "-")}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Offline restore proof: decrypt an export using ONLY the master password and
 * the crypto core — no network call. This is what an operator would run to
 * verify a backup (or what a future CLI/import feature would reuse).
 */
export async function restoreExport(
  data: VaultExport,
  masterPassword: string,
): Promise<VaultItem[]> {
  const { stretchedKey } = await deriveMasterKey(data.email, masterPassword, data.kdf);
  const userKey = await decryptUserKey(stretchedKey, data.protectedUserKey);
  return decryptVault(userKey, { ciphers: data.ciphers });
}
