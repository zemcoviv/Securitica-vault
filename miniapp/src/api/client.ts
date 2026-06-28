/**
 * Bitwarden API client → Vaultwarden.
 *
 * INVARIANT (BRIEF §2, §6.4): sync goes **directly** client → Vaultwarden. The
 * only derived value ever placed on the wire is `masterPasswordHash` (a login
 * authenticator). No master password, no key material, no plaintext.
 *
 * Endpoints used in M1:
 *   POST /identity/accounts/prelogin     -> KDF parameters
 *   POST /identity/connect/token         -> access token + protected user key
 *   GET  /api/sync                        -> ciphers (all EncStrings)
 */
import { KdfConfig, KdfType } from "../crypto/keys";

export interface VaultwardenClientOptions {
  /** Base URL of the Vaultwarden deployment, e.g. https://vault.example.com */
  baseUrl: string;
  /** Stable per-install device id (uuid). Identity only — never key material. */
  deviceIdentifier: string;
  fetchImpl?: typeof fetch;
}

interface PreloginResponse {
  kdf: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
}

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  /** Protected (wrapped) user key — an EncString. Ciphertext only. */
  Key: string;
  Kdf: number;
  KdfIterations: number;
  KdfMemory?: number;
  KdfParallelism?: number;
}

export interface CipherResponse {
  id: string;
  type: number;
  revisionDate: string;
  /** EncString or null. */
  name: string | null;
  login?: {
    username: string | null;
    password: string | null;
    uris?: { uri: string | null }[] | null;
  } | null;
  notes?: string | null;
}

export interface SyncResponse {
  ciphers: CipherResponse[];
  profile?: { email?: string };
}

export class VaultwardenClient {
  private readonly baseUrl: string;
  private readonly deviceIdentifier: string;
  private readonly fetchImpl: typeof fetch;
  private accessToken: string | null = null;

  constructor(opts: VaultwardenClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.deviceIdentifier = opts.deviceIdentifier;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async prelogin(email: string): Promise<KdfConfig> {
    const res = await this.fetchImpl(`${this.baseUrl}/identity/accounts/prelogin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
    if (!res.ok) throw new Error(`prelogin failed: ${res.status}`);
    const data = (await res.json()) as PreloginResponse;
    return {
      kdfType: data.kdf as KdfType,
      iterations: data.kdfIterations,
      memoryMiB: data.kdfMemory,
      parallelism: data.kdfParallelism,
    };
  }

  /**
   * Password-grant login. `masterPasswordHash` is the base64 authenticator from
   * keys.ts — NOT a key. Returns the protected user key for client-side unwrap.
   */
  async login(
    email: string,
    masterPasswordHash: string,
  ): Promise<{ protectedUserKey: string }> {
    const body = new URLSearchParams({
      grant_type: "password",
      username: email.trim().toLowerCase(),
      password: masterPasswordHash,
      scope: "api offline_access",
      client_id: "web",
      deviceType: "9", // Web / unknown
      deviceIdentifier: this.deviceIdentifier,
      deviceName: "securitica-miniapp",
    });
    const res = await this.fetchImpl(`${this.baseUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!res.ok) {
      throw new Error(`login failed: ${res.status}`);
    }
    const data = (await res.json()) as TokenResponse;
    this.accessToken = data.access_token;
    return { protectedUserKey: data.Key };
  }

  /**
   * Push a new cipher. The caller supplies ALREADY-ENCRYPTED EncStrings — this
   * method never sees plaintext (BRIEF §2). Used by the vault create flow (M3)
   * and exercised by the §11.1 canary test.
   */
  async createCipher(encrypted: {
    name: string;
    username: string | null;
    password: string | null;
    uri: string | null;
  }): Promise<{ id: string }> {
    if (!this.accessToken) throw new Error("createCipher: not authenticated");
    const body = {
      type: 1,
      name: encrypted.name,
      login: {
        username: encrypted.username,
        password: encrypted.password,
        uris: encrypted.uri ? [{ uri: encrypted.uri, match: null }] : [],
      },
    };
    const res = await this.fetchImpl(`${this.baseUrl}/api/ciphers`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`createCipher failed: ${res.status}`);
    const data = (await res.json()) as { id: string };
    return { id: data.id };
  }

  async sync(): Promise<SyncResponse> {
    if (!this.accessToken) throw new Error("sync: not authenticated");
    const res = await this.fetchImpl(
      `${this.baseUrl}/api/sync?excludeDomains=true`,
      { headers: { Authorization: `Bearer ${this.accessToken}` } },
    );
    if (!res.ok) throw new Error(`sync failed: ${res.status}`);
    return (await res.json()) as SyncResponse;
  }

  /** Forget the access token (called on auto-lock). */
  clearSession(): void {
    this.accessToken = null;
  }
}
