# Securitica Vault

A zero-knowledge password manager with a **Telegram Mini App** front end, built
on a self-hosted **Vaultwarden** (Bitwarden-compatible) backend.

> **ADR-001 — don't reinvent cryptography.** The Mini App is *another client*
> to the Bitwarden protocol, not a new product. The vault therefore stays
> readable by the official Bitwarden apps as a fallback (no single point of
> failure, no vendor lock-in).

This repository implements **M0** (infrastructure) and **M1** (unlock →
decrypted record list) of the build brief, plus the automated security tests
that guard the invariants.

---

## The one invariant that matters

**The trust boundary is the Mini App WebView.** All cryptography and the only
moment plaintext exists happen inside the client. Concretely:

- The server and bot **never** see the master phrase, any derived key
  (master / stretched / user key), or any plaintext record.
- The only derived value sent to the server is `masterPasswordHash` — a login
  authenticator, **not** a key. The server cannot derive encryption keys from it.
- `initData` from Telegram authenticates **identity** for sync/rate-limit only.
  It is **never** key material — a stolen Telegram account must not decrypt the
  vault.
- Telegram transport is treated as an untrusted CDN.

See [`SECURITY.md`](./SECURITY.md) for the full server-visibility matrix and the
honest limitations of an in-WebView client.

---

## Architecture

```
Telegram client ──launch──▶ Mini App (WebView, our domain)
                                │  master password ──▶ Argon2id ──▶ keys (in memory)
                                │
   ┌── identity (initData) ─────┤
   ▼                            ▼  ciphertext only (EncString)
thin backend                 Vaultwarden ──▶ PostgreSQL
(initData verify,            (Bitwarden API)
 static, rate-limit)
   ▲
   └── Caddy (TLS, CSP, HSTS) ──┘

bot (aiogram): launcher + metadata-only notifications, allowlisted. No vault access.
```

| Component | Tech | Path |
|---|---|---|
| Backend / sync | Vaultwarden + PostgreSQL | `docker-compose.yml`, `infra/` |
| Mini App client | TypeScript + Vite, SubtleCrypto + Argon2 (hash-wasm) | `miniapp/` |
| Thin backend | FastAPI (initData verify, static, rate-limit) | `server/` |
| Bot | aiogram v3 (launcher + notifications, allowlist) | `bot/` |
| Edge | Caddy (TLS, CSP, HSTS) | `infra/Caddyfile` |

### Crypto chain (§5, Bitwarden-compatible)

```
prelogin(email) ─▶ KDF params (Argon2id)
masterKey   = Argon2id(masterPassword, salt = SHA-256(email))           (32 B)
stretched   = HKDF-Expand(masterKey, "enc") || HKDF-Expand(masterKey,"mac") (64 B)
mpHash      = PBKDF2-SHA256(masterKey, masterPassword, 1)   ← sent to server (auth only)
userKey     = decrypt(protectedUserKey, stretched)                       (64 B)
records     = decrypt(EncString type 2, userKey)   // AES-256-CBC + HMAC, encrypt-then-MAC
```

Record encryption is **EncString type 2** only (`2.<iv>|<ct>|<mac>`).
XChaCha20/GCM is deliberately rejected for ciphers — it would break Bitwarden
compatibility (`miniapp/src/crypto/encstring.ts`).

---

## Running it

### Dev — Mini App + tests (no Docker needed)

```bash
npm install
npm run typecheck     # strict TS
npm run build         # Vite build + SRI injection
npm test              # crypto unit + §11.1 canary + §11.5 compat
npm run dev           # local Vite server (outside Telegram, no initData)

pip install pytest
pytest tests/security/test_initdata.py   # §11.3 initData tamper
```

### Full stack — Docker Compose (M0)

```bash
cp .env.example .env          # fill DB_PASSWORD, BOT_TOKEN, ALLOWLIST_CHAT_IDS
docker compose up -d --build
```

Then: register a user via Vaultwarden invite (signups are closed), confirm you
can log in from an **official Bitwarden client** against `/vault`, and `/start`
the bot from an allowlisted chat to get the launch button.

> Set your real domain in `infra/Caddyfile`, `infra/vaultwarden.env`
> (`DOMAIN`), and `MINIAPP_URL`. Keep `connect-src` in the CSP aligned with
> where the client talks (default: same-origin `/vault`).

---

## Security tests (BRIEF §11)

| # | What | Where | Runner |
|---|---|---|---|
| 11.1 | No plaintext in traffic to the server (canary) | `tests/security/no-plaintext.test.ts` | vitest |
| 11.3 | initData tamper / expiry rejected | `tests/security/test_initdata.py` | pytest |
| 11.4 | Reveal-lifecycle: DOM/clipboard scrubbed after timeout; no biometry ⇒ no reveal | `tests/security/reveal-lifecycle.test.ts` | vitest (jsdom) |
| 11.5 | EncString interop with an independent reference | `tests/security/compat.test.ts` | vitest |
| 11.6 | CSP has no `unsafe-inline`; SRI present | `tests/security/csp-audit.mjs` | node (post-build) |

**The §11.1 proof.** The canary test instruments the client with a fetch
interceptor, runs the full M1 lifecycle plus a cipher create whose every field
carries a unique `CANARY_PLAINTEXT_<rand>` marker, and asserts the marker
appears in **no** request body, URL, or header — while the EncString that
*should* carry it is present. Run `npm test` and look for the
`[§11.1] intercepted outgoing traffic` dump: every payload is either an
EncString (`2.iv|ct|mac`) or the base64 auth hash. No plaintext crosses the
WebView boundary.

---

## Status / roadmap

- **M0 — infra:** ✅ compose (Vaultwarden + PG + Caddy + bot + thin backend),
  signups closed, bot skeleton with allowlist.
- **M1 — unlock + read-only:** ✅ initData verify → Argon2id derivation →
  login + sync → decrypted record list. §11.1 canary passing.
- **M2 — ephemeral reveal:** ✅ biometry gate (`Telegram.WebApp.BiometryManager`
  with a WebAuthn user-verification fallback, `reveal/biometry.ts`),
  press-and-hold reveal with a 20 s fallback timer, DOM scrub on release/timeout
  (`reveal/engine.ts`), clipboard copy with non-destructive auto-clear
  (`reveal/clipboard.ts`). Auto-lock force-scrubs any in-progress reveal
  (`vault/autolock.ts`). §11.4 reveal-lifecycle passing.
- **M3 — create/edit + generator + autofill:** _not yet_. The crypto + API
  paths (`createCipher`, `encryptString`) already exist and are exercised by the
  canary test. "Autofill over reveal" (§7.6) applies within M3's own forms — a
  Mini App has no OS-level autofill hook into other apps.
- **M4 — notifications + recovery + hardening:** notification formatter
  (`bot/notify.py`) is metadata-only and in place; recovery + optional KDF
  second factor pending.
