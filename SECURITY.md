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
- **Bot carries metadata only** (`bot/notify.py`); it has no path to vault
  contents, keys, or plaintext.
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
- **Clipboard auto-clear is non-destructive** — `reveal/clipboard.ts` only
  overwrites the clipboard if it still holds exactly what we put there,
  so it can't clobber something the user copied from elsewhere in the
  interim.

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

`BOT_TOKEN`, the DB password, the Vaultwarden admin token, and TLS keys are
provided via environment / secrets (`.env`, `infra/vaultwarden.env.local`) and
are **never** committed. `.gitignore` blocks the obvious paths; rotate any
value that lands in history.
