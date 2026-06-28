/**
 * Low-level crypto primitives.
 *
 * INVARIANT (BRIEF §2): none of these outputs — master key, stretched key,
 * user key, or any plaintext — may ever be serialised into a request to the
 * server or the bot. They live only inside the WebView memory.
 *
 * We deliberately do NOT roll our own ciphers: AES-CBC / HMAC / HKDF / PBKDF2
 * come from the platform SubtleCrypto, and Argon2id from hash-wasm (audited
 * WASM build). The composition follows the documented Bitwarden scheme so the
 * vault stays readable by official Bitwarden clients (BRIEF §5, ADR-001).
 */
import { argon2id } from "hash-wasm";

const subtle: SubtleCrypto = globalThis.crypto.subtle;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return textDecoder.decode(b);
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  // btoa exists in browsers; Node 22 provides it globally too.
  return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Constant-time comparison to avoid leaking MAC validation timing. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

/**
 * Best-effort memory hygiene. JS gives no zeroisation guarantee (honest
 * limitation, BRIEF §7) but we overwrite key buffers as soon as we are done
 * with them to shrink the window in which plaintext key material is resident.
 */
export function wipe(...buffers: (Uint8Array | undefined | null)[]): void {
  for (const b of buffers) if (b) b.fill(0);
}

// ---------------------------------------------------------------------------
// Hashes / MACs
// ---------------------------------------------------------------------------

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

// ---------------------------------------------------------------------------
// KDFs
// ---------------------------------------------------------------------------

export interface Argon2Params {
  /** Memory cost in KiB. BRIEF §5 default: 262144 (256 MiB). */
  memoryKiB: number;
  /** Time cost (iterations). BRIEF §5 default: 3. */
  iterations: number;
  /** Parallelism (lanes). BRIEF §5 default: 4. */
  parallelism: number;
}

/**
 * masterKey = Argon2id(masterPassword, salt = SHA-256(email)).
 *
 * Bitwarden hashes the email into a 32-byte salt for Argon2 (the email itself
 * is used directly only for the legacy PBKDF2 path). We mirror that exactly so
 * derivation stays interoperable.
 */
export async function deriveArgon2id(
  password: Uint8Array,
  emailSalt: Uint8Array,
  params: Argon2Params,
): Promise<Uint8Array> {
  const salt = await sha256(emailSalt);
  const hash = await argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memoryKiB,
    hashLength: 32,
    outputType: "binary",
  });
  return hash as Uint8Array;
}

/** PBKDF2-HMAC-SHA256, raw bytes out. Used for the master password hash. */
export async function pbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey("raw", password, "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * HKDF-Expand (RFC 5869, expand step only) with SHA-256.
 *
 * Bitwarden stretches the 32-byte master key with HKDF-Expand using ASCII info
 * strings "enc" and "mac". SubtleCrypto's HKDF performs extract+expand and
 * cannot skip extraction, so we implement expand directly over HMAC-SHA256.
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const hashLen = 32;
  const n = Math.ceil(lengthBytes / hashLen);
  if (n > 255) throw new Error("hkdfExpand: requested length too large");
  const out = new Uint8Array(n * hashLen);
  let previous = new Uint8Array(0);
  for (let i = 0; i < n; i++) {
    const input = new Uint8Array(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = i + 1;
    previous = await hmacSha256(prk, input);
    out.set(previous, i * hashLen);
  }
  return out.slice(0, lengthBytes);
}

// ---------------------------------------------------------------------------
// AES-256-CBC
// ---------------------------------------------------------------------------

export async function aesCbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, [
    "encrypt",
  ]);
  const ct = await subtle.encrypt({ name: "AES-CBC", iv }, k, plaintext);
  return new Uint8Array(ct);
}

export async function aesCbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", key, { name: "AES-CBC" }, false, [
    "decrypt",
  ]);
  const pt = await subtle.decrypt({ name: "AES-CBC", iv }, k, ciphertext);
  return new Uint8Array(pt);
}
