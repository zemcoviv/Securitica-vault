# Security model

## Server / bot visibility matrix (BRIEF §8)

| Artifact | Server / bot sees it? |
|---|---|
| Master phrase | **No** |
| masterKey / stretchedKey / userKey (plaintext) | **No** |
| masterPasswordHash (for auth) | Yes — login only; no keys derived from it |
| protected userKey (envelope) | Yes — ciphertext |
| Records (EncString) | Yes — ciphertext |
| Record names / URLs | Encrypted client-side as EncStrings (sensitive fields MUST be encrypted) |
| Sync metadata (id, revisionDate) | Yes |
| initData / Telegram identity | Yes |
| Synthetic account email (`tg<id>@securitica.local`) | Yes — derived from Telegram id, not a secret |
| Account RSA keypair — public key | Yes — public by definition |
| Account RSA keypair — private key | Yes — ciphertext only (EncString under userKey) |
| `VW_ADMIN_TOKEN` (Vaultwarden admin) | Held by `miniapp-server` only — new in BRIEF §1 onboarding; see below |

## Invariants enforced in code

- **No own crypto primitives.** AES-CBC / HMAC / HKDF / PBKDF2 come from
  platform SubtleCrypto; Argon2id from the audited `hash-wasm` WASM build. The
  composition follows the documented Bitwarden scheme
  (`miniapp/src/crypto/`).
- **EncString type 2 only** for records (`encstring.ts` rejects other types).
  Encrypt-then-MAC; the MAC is verified in constant time *before* decryption.
- **Only `masterPasswordHash` leaves the device** among derived values
  (`vault/unlock.ts`). Verified continuously by the §11.1 canary test.
- **initData verified server-side** with HMAC + `auth_date` TTL
  (`server/initdata.py`); the client never trusts its own check for auth.
- **Account-event alerts carry metadata only** — `server/notifications.py`'s
  `AccountEvent` has exactly five fields (kind, time, ip, geo, device); the
  thin backend re-verifies `initData` before sending anything and ignores any
  other field a client request body might contain (verified by
  `tests/security/test_events.py`, including a canary-smuggling attempt).
  Neither the bot process nor the notification path has any route to a
  cipher, key, or master phrase.
- **Strict CSP + SRI** on the static bundle (`infra/Caddyfile`,
  `scripts/inject-sri.mjs`), audited in CI (§11.6).
- **No reveal without a fresh biometric confirmation** — `reveal/biometry.ts`
  gates every decrypt-and-display through `Telegram.WebApp.BiometryManager`
  (native Face/Touch ID) or a WebAuthn user-verification fallback; "denied"
  and "unavailable" both fail closed (`reveal/engine.ts`). Verified by the
  §11.4 test.
- **Reveal is DOM-scoped and self-scrubbing** — the plaintext lives only in
  the text node the caller hands to `revealInto`; on release (hold mode),
  timeout (20 s fallback), or auto-lock, the node is blanked *and* removed,
  and the decrypted byte buffer is wiped (`reveal/engine.ts`,
  `vault/autolock.ts:stopAllActiveReveals`).
- **Release-before-gate-resolves is handled, not lost** — `reveal/ui.ts`
  tracks a release requested while the biometric gate/decrypt is still in
  flight and honors it the instant a handle exists, instead of leaving the
  secret visible indefinitely. This matters most for the WebAuthn fallback,
  whose OS dialog structurally requires letting go of the hold button first
  (`miniapp/src/reveal/ui.test.ts`).
- **The thin backend trusts X-Forwarded-For only from its one real caller** —
  `server/main.py` wraps the app in uvicorn's `ProxyHeadersMiddleware` so
  `request.client` reflects Caddy's forwarded client IP rather than Caddy's
  own container address; without it, the per-IP rate limiter collapses into
  one shared bucket and every account-event alert reports the same wrong IP
  (`tests/security/test_proxy_headers.py`).
- **Clipboard auto-clear is non-destructive** — `reveal/clipboard.ts` only
  overwrites the clipboard if it still holds exactly what we put there,
  so it can't clobber something the user copied from elsewhere in the
  interim.
- **Editing never requires an un-gated decrypt of an existing secret** —
  `vault/edit.ts` uses "blank field means unchanged": the stored password
  EncString is reused verbatim unless the user types or generates a new one.
  Editing *existing* notes (which may hold recovery codes, BRIEF §1) is
  gated behind the same biometric confirmation as reveal (`vault/edit-ui.ts`).
- **The generator draws from real diceware wordlists via CSPRNG** —
  `generator/diceware.ts` uses rejection sampling over `crypto.getRandomValues`
  (no modulo bias) against the official EFF long wordlist and a matching
  Russian list, snapshotted as static JSON so the bundle never executes
  third-party CommonJS at runtime.
- **Master password change re-wraps only the envelope** (§5.3) —
  `vault/password-change.ts` derives fresh master/stretched keys and
  re-encrypts the *same* userKey under them; no cipher is touched, and a
  test proves the old stretched key can no longer unwrap the new envelope.
- **Offline export never decrypts anything** — `vault/export.ts` repackages
  the `protectedUserKey` envelope and every cipher's EncStrings exactly as
  Vaultwarden returns them; restoring requires the master password and runs
  entirely through the local crypto core, with no network call at all
  (proven by an automated test that restores with no fetch implementation
  present).
- **§5.4 extension point, not enabled by default** — `deriveMasterKey` accepts
  an optional `secondFactor` byte string, mixed into the Argon2id input
  alongside the master password. Sourcing it (WebAuthn PRF, secure device
  storage, or a trusted-device QR handoff) is left to a future phase; the
  derivation hook and its determinism are covered by tests today so wiring a
  real source later doesn't require touching the crypto core.
- **Account provisioning never routes a secret through the invite step** —
  `server/vaultwarden_admin.py` only ever sends an email address to
  Vaultwarden's admin API; `/api/provision` accepts nothing but `initData`,
  so a client cannot smuggle any other value into the invite call
  (`tests/security/test_provisioning.py`). Registration itself
  (`vault/register.ts`) follows the exact same ciphertext-only discipline as
  every other write — proven by an extension of the same canary pattern
  (`miniapp/src/vault/register.test.ts`).

## New privileged secret: `VW_ADMIN_TOKEN` in `miniapp-server` (BRIEF §1)

Account auto-provisioning (BRIEF §1 — the Mini App creates the Vaultwarden
account directly, no admin panel, no email field, no KDF choice) requires
`miniapp-server` to hold Vaultwarden's admin token and call its admin API
server-to-server. This is a **new trade-off**, not present before this
feature: previously the thin backend held no privileged secret at all.

- **What it can do:** create/invite Vaultwarden user accounts.
- **What it still cannot do:** decrypt a single cipher, key, or master
  phrase — Vaultwarden's admin panel has no path to plaintext vault
  contents, by the same zero-knowledge design that protects everything
  else in this document.
- **Blast radius if `miniapp-server` is compromised:** an attacker could
  invite/create accounts, but not read anyone's passwords. This is
  meaningfully worse than the pre-onboarding-feature posture (a compromised
  thin backend used to be able to do nothing privileged at all), and is the
  explicit, disclosed cost of removing Bitwarden-level UX friction for a
  general Telegram audience.
- The admin token travels **only** over the internal docker network
  (`VAULTWARDEN_INTERNAL_URL`, never through Caddy) and never appears in any
  request to or from the Mini App client.

## Honest limitation (BRIEF §7)

JavaScript gives **no guarantee** of memory zeroisation. While a value is being
shown or autofilled, the plaintext lives in WebView memory. The trust boundary
is the Telegram client + the device OS. This is **weaker** than an audited
native client (e.g. KeePassXC) and **must not** be marketed as equivalent to
native memory isolation. We mitigate by:

- deriving keys only inside the WebView and wiping intermediate key buffers
  (`crypto/primitives.ts:wipe`, called in `unlock.ts`),
- auto-locking on inactivity and zeroing the user key (`vault/autolock.ts`),
- minimising the reveal window: biometry gate, press-and-hold / 20 s fallback
  timer, DOM scrub, clipboard auto-clear (`reveal/`),
- a strict CSP + SRI so a swapped bundle (the main residual risk — exfiltration
  at reveal time) cannot load third-party script.

## Secrets handling

`BOT_TOKEN`, the DB password, `VW_ADMIN_TOKEN`, and TLS keys are provided via
environment / secrets (`.env`, `infra/vaultwarden.env.local`) and are **never**
committed. `.gitignore` blocks the obvious paths; rotate any value that lands
in history. `VW_ADMIN_TOKEN` is shared between the `vaultwarden` and
`miniapp-server` services (docker-compose.yml) — rotating it requires
restarting both.
