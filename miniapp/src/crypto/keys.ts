/**
 * Key derivation — the §5 unlock chain, Bitwarden-compatible.
 *
 *   1. prelogin(email)                 -> KDF params (Argon2id, BRIEF §5.1)
 *   2. masterKey   = Argon2id(masterPassword, salt = SHA-256(email))      (32B)
 *   3. stretched   = HKDF-Expand(masterKey, "enc"/"mac")  -> encKey||macKey (64B)
 *   4. mpHash      = PBKDF2-SHA256(masterKey, masterPassword, 1 iter)     (auth)
 *   5. userKey     = decrypt(protectedUserKey, stretchedKey)              (64B)
 *   6. ciphers decrypted with userKey
 *
 * INVARIANTS (BRIEF §2):
 *  - masterPassword, masterKey, stretchedKey and userKey MUST NOT leave the
 *    WebView. Only `masterPasswordHash` (an authenticator, not a key) is sent.
 *  - The server cannot derive encryption keys from masterPasswordHash.
 */
import { decryptToBytes, splitSymmetricKey, type SymmetricKey } from "./encstring";
import {
  Argon2Params,
  deriveArgon2id,
  hkdfExpand,
  pbkdf2,
  toBase64,
  utf8ToBytes,
} from "./primitives";

/** KDF identifiers as returned by Vaultwarden's prelogin endpoint. */
export enum KdfType {
  PBKDF2_SHA256 = 0,
  Argon2id = 1,
}

export interface KdfConfig {
  kdfType: KdfType;
  iterations: number;
  /** Argon2 only: memory in MiB (as Vaultwarden reports it). */
  memoryMiB?: number;
  /** Argon2 only: parallelism. */
  parallelism?: number;
}

/** BRIEF §5.1 defaults — tune per device, never below OWASP minimum. */
export const DEFAULT_ARGON2_CONFIG: KdfConfig = {
  kdfType: KdfType.Argon2id,
  iterations: 3,
  memoryMiB: 256,
  parallelism: 4,
};

export interface MasterKeyBundle {
  /** 32-byte Argon2id output. Wipe after stretching + hashing. */
  masterKey: Uint8Array;
  /** Stretched enc||mac, used to unwrap the protected user key. */
  stretchedKey: SymmetricKey;
}

function toArgon2Params(cfg: KdfConfig): Argon2Params {
  if (cfg.kdfType !== KdfType.Argon2id) {
    throw new Error(
      "Securitica requires Argon2id (BRIEF §5.1 forbids PBKDF2 for new vaults)",
    );
  }
  return {
    memoryKiB: (cfg.memoryMiB ?? 256) * 1024,
    iterations: cfg.iterations,
    parallelism: cfg.parallelism ?? 4,
  };
}

/**
 * Steps 2 + 3: derive the master key and stretch it.
 *
 * `secondFactor` is the BRIEF §5.4 extension point ("второй фактор в KDF" —
 * a device-local secret, analogous to 1Password's Secret Key, mixed into
 * derivation so a bare server dump can never be brute-forced offline). It is
 * NOT required for the MVP and defaults to absent — when provided, it is
 * concatenated onto the password bytes before Argon2id, so a dump of
 * Vaultwarden's DB alone (without the device secret) is insufficient to
 * attempt master-password guesses. Sourcing it (WebAuthn PRF, secure device
 * storage, or a QR handoff from a trusted device, per §5.4) is deliberately
 * left to a future phase; only the derivation hook is wired here.
 */
export async function deriveMasterKey(
  email: string,
  masterPassword: string,
  cfg: KdfConfig,
  secondFactor?: Uint8Array,
): Promise<MasterKeyBundle> {
  const normalizedEmail = email.trim().toLowerCase();
  const passwordBytes = utf8ToBytes(masterPassword);
  const input = secondFactor
    ? new Uint8Array([...passwordBytes, 0, ...secondFactor])
    : passwordBytes;

  const masterKey = await deriveArgon2id(
    input,
    utf8ToBytes(normalizedEmail),
    toArgon2Params(cfg),
  );

  // HKDF-Expand with ASCII info "enc" / "mac" — the Bitwarden stretch.
  const encKey = await hkdfExpand(masterKey, utf8ToBytes("enc"), 32);
  const macKey = await hkdfExpand(masterKey, utf8ToBytes("mac"), 32);

  return { masterKey, stretchedKey: { encKey, macKey } };
}

/**
 * Step 4: masterPasswordHash = PBKDF2-SHA256(masterKey, masterPassword, 1).
 * Base64-encoded; this is the ONLY derived value sent to the server, purely as
 * a login authenticator (BRIEF §8 visibility matrix).
 */
export async function computeMasterPasswordHash(
  masterKey: Uint8Array,
  masterPassword: string,
): Promise<string> {
  const hash = await pbkdf2(masterKey, utf8ToBytes(masterPassword), 1, 32);
  return toBase64(hash);
}

/**
 * Step 5: unwrap the protected user key (an EncString) with the stretched
 * master key. Returns the 64-byte user SymmetricKey used for all ciphers.
 */
export async function decryptUserKey(
  stretchedKey: SymmetricKey,
  protectedUserKey: string,
): Promise<SymmetricKey> {
  const raw = await decryptToBytes(stretchedKey, protectedUserKey);
  return splitSymmetricKey(raw);
}
