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

/**
 * Thrown by register() when Vaultwarden reports the account already exists
 * (e.g. a previous registration attempt completed but our own
 * provision-complete bookkeeping never got the news). Callers should treat
 * this as "try logging in with what the user just typed instead."
 */
export class RegisterConflictError extends Error {}

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
   * Create a brand-new account (BRIEF §1 onboarding: the Mini App drives this
   * directly, no Vaultwarden/Bitwarden UI). Confirmed against Vaultwarden
   * 1.32.7 source: this handler lives in src/api/core/accounts.rs, mounted
   * under /api (NOT /identity) — unlike prelogin/connect-token, which are
   * genuinely under /identity.
   *
   * Every field here is either ciphertext (`key`, `keys.encryptedPrivateKey`),
   * a public key, or an authenticator hash — never a plaintext secret
   * (BRIEF §2). The server only allows this to succeed for an email with a
   * pending Invitation record (SIGNUPS_ALLOWED stays false; see
   * server/vaultwarden_admin.py for how that invitation is created).
   */
  async register(params: {
    email: string;
    masterPasswordHash: string;
    /** Protected user key envelope (EncString) — ciphertext. */
    key: string;
    kdf: KdfConfig;
    keys: { publicKeyB64: string; encryptedPrivateKey: string };
    name?: string;
  }): Promise<void> {
    const res = await this.fetchImpl(`${this.baseUrl}/api/accounts/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: params.email.trim().toLowerCase(),
        masterPasswordHash: params.masterPasswordHash,
        key: params.key,
        kdf: params.kdf.kdfType,
        kdfIterations: params.kdf.iterations,
        kdfMemory: params.kdf.memoryMiB,
        kdfParallelism: params.kdf.parallelism,
        keys: {
          publicKey: params.keys.publicKeyB64,
          encryptedPrivateKey: params.keys.encryptedPrivateKey,
        },
        name: params.name ?? null,
      }),
    });
    if (res.ok) return;
    const bodyText = await res.text().catch(() => "");
    if (res.status === 400 && /already exists|not allowed/i.test(bodyText)) {
      throw new RegisterConflictError(bodyText || "account already exists");
    }
    throw new Error(`register failed: ${res.status}`);
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
   * Every field here MUST already be an EncString (or null) — the caller
   * (vault/edit.ts) encrypts with the userKey before this is ever called.
   * Neither createCipher nor updateCipher sees, logs, or transforms plaintext
   * (BRIEF §2). Exercised by the §11.1/§11.2 canary tests.
   */
  private cipherBody(encrypted: {
    name: string;
    username: string | null;
    password: string | null;
    uri: string | null;
    notes: string | null;
  }) {
    return {
      type: 1,
      name: encrypted.name,
      notes: encrypted.notes,
      login: {
        username: encrypted.username,
        password: encrypted.password,
        uris: encrypted.uri ? [{ uri: encrypted.uri, match: null }] : [],
      },
    };
  }

  /** Push a new cipher. Used by the vault create flow (M3). */
  async createCipher(encrypted: {
    name: string;
    username: string | null;
    password: string | null;
    uri: string | null;
    notes: string | null;
  }): Promise<{ id: string }> {
    if (!this.accessToken) throw new Error("createCipher: not authenticated");
    const res = await this.fetchImpl(`${this.baseUrl}/api/ciphers`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(this.cipherBody(encrypted)),
    });
    if (!res.ok) throw new Error(`createCipher failed: ${res.status}`);
    const data = (await res.json()) as { id: string };
    return { id: data.id };
  }

  /** Update an existing cipher in place. Used by the vault edit flow (M3). */
  async updateCipher(
    id: string,
    encrypted: {
      name: string;
      username: string | null;
      password: string | null;
      uri: string | null;
      notes: string | null;
    },
  ): Promise<void> {
    if (!this.accessToken) throw new Error("updateCipher: not authenticated");
    const res = await this.fetchImpl(`${this.baseUrl}/api/ciphers/${id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(this.cipherBody(encrypted)),
    });
    if (!res.ok) throw new Error(`updateCipher failed: ${res.status}`);
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

  /**
   * Master password change (BRIEF §5.3): only the wrapped `newProtectedUserKey`
   * envelope is reissued — no cipher is touched, and neither hash is a key
   * (they're PBKDF2 authenticators the server already can't invert into
   * encryption keys). Vaultwarden invalidates existing sessions on success, so
   * callers should force a fresh unlock afterwards.
   */
  async changeMasterPassword(params: {
    oldMasterPasswordHash: string;
    newMasterPasswordHash: string;
    newProtectedUserKey: string;
  }): Promise<void> {
    if (!this.accessToken) throw new Error("changeMasterPassword: not authenticated");
    const res = await this.fetchImpl(`${this.baseUrl}/api/accounts/password`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        masterPasswordHash: params.oldMasterPasswordHash,
        newMasterPasswordHash: params.newMasterPasswordHash,
        key: params.newProtectedUserKey,
      }),
    });
    if (!res.ok) throw new Error(`changeMasterPassword failed: ${res.status}`);
  }

  /** Forget the access token (called on auto-lock). */
  clearSession(): void {
    this.accessToken = null;
  }
}
