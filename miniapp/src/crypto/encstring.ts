/**
 * EncString — Bitwarden's serialised symmetric-encryption envelope.
 *
 * We implement only **type 2** (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC):
 *
 *     2.<iv_b64>|<ct_b64>|<mac_b64>
 *
 * INVARIANT (BRIEF §5.2): type 2 is mandatory for record encryption. Using
 * XChaCha20/GCM here would break compatibility with Bitwarden clients, so it is
 * forbidden for ciphers. Encrypt-then-MAC: the MAC covers iv || ciphertext and
 * is verified (constant time) BEFORE any decryption is attempted.
 *
 * A SymmetricCryptoKey is 64 bytes: encKey(32) || macKey(32).
 */
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  bytesToUtf8,
  constantTimeEqual,
  fromBase64,
  hmacSha256,
  randomBytes,
  toBase64,
  utf8ToBytes,
} from "./primitives";

export const ENC_TYPE_AES256_CBC_HMAC = 2;

export interface SymmetricKey {
  /** 32-byte AES-256 key. */
  encKey: Uint8Array;
  /** 32-byte HMAC-SHA256 key. */
  macKey: Uint8Array;
}

/** Split a raw 64-byte key into its enc/mac halves. */
export function splitSymmetricKey(raw: Uint8Array): SymmetricKey {
  if (raw.length !== 64) {
    throw new Error(`SymmetricKey must be 64 bytes, got ${raw.length}`);
  }
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) };
}

/** Inverse of splitSymmetricKey — recombine enc||mac into 64 raw bytes. */
export function joinSymmetricKey(key: SymmetricKey): Uint8Array {
  const raw = new Uint8Array(64);
  raw.set(key.encKey, 0);
  raw.set(key.macKey, 32);
  return raw;
}

export interface ParsedEncString {
  type: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
}

export function parseEncString(value: string): ParsedEncString {
  const dot = value.indexOf(".");
  if (dot === -1) throw new Error("EncString: missing type prefix");
  const type = Number(value.slice(0, dot));
  if (type !== ENC_TYPE_AES256_CBC_HMAC) {
    throw new Error(
      `EncString: unsupported type ${type} (only type 2 is allowed, BRIEF §5.2)`,
    );
  }
  const parts = value.slice(dot + 1).split("|");
  if (parts.length !== 3) {
    throw new Error("EncString type 2: expected iv|ct|mac");
  }
  return {
    type,
    iv: fromBase64(parts[0]),
    ciphertext: fromBase64(parts[1]),
    mac: fromBase64(parts[2]),
  };
}

function serialize(p: Omit<ParsedEncString, "type">): string {
  return `${ENC_TYPE_AES256_CBC_HMAC}.${toBase64(p.iv)}|${toBase64(
    p.ciphertext,
  )}|${toBase64(p.mac)}`;
}

/** MAC input is the concatenation iv || ciphertext (encrypt-then-MAC). */
async function computeMac(
  macKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const data = new Uint8Array(iv.length + ciphertext.length);
  data.set(iv, 0);
  data.set(ciphertext, iv.length);
  return hmacSha256(macKey, data);
}

/** Encrypt raw bytes into an EncString type 2. */
export async function encryptBytes(
  key: SymmetricKey,
  plaintext: Uint8Array,
): Promise<string> {
  const iv = randomBytes(16);
  const ciphertext = await aesCbcEncrypt(key.encKey, iv, plaintext);
  const mac = await computeMac(key.macKey, iv, ciphertext);
  return serialize({ iv, ciphertext, mac });
}

export async function encryptString(
  key: SymmetricKey,
  plaintext: string,
): Promise<string> {
  return encryptBytes(key, utf8ToBytes(plaintext));
}

/**
 * Verify the MAC (constant time) and decrypt. Throws on MAC mismatch WITHOUT
 * attempting decryption — never expose padding-oracle behaviour.
 */
export async function decryptToBytes(
  key: SymmetricKey,
  encString: string,
): Promise<Uint8Array> {
  const { iv, ciphertext, mac } = parseEncString(encString);
  const expectedMac = await computeMac(key.macKey, iv, ciphertext);
  if (!constantTimeEqual(mac, expectedMac)) {
    throw new Error("EncString: MAC verification failed");
  }
  return aesCbcDecrypt(key.encKey, iv, ciphertext);
}

export async function decryptToString(
  key: SymmetricKey,
  encString: string,
): Promise<string> {
  return bytesToUtf8(await decryptToBytes(key, encString));
}
