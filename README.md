# Securitica Vault

A zero-knowledge password manager with a **Telegram Mini App** front end, built
on a self-hosted **Vaultwarden** (Bitwarden-compatible) backend.

> **ADR-001 — don't reinvent cryptography.** The Mini App is *another client*
> to the Bitwarden protocol, not a new product. The vault therefore stays
> readable by the official Bitwarden apps as a fallback (no single point of
> failure, no vendor lock-in).

This repository implements **M0** (infrastructure), **M1** (unlock → decrypted
record list), **M2** (ephemeral reveal) and **M3** (create/edit + generator) of
the build brief, plus the automated security tests that guard the invariants.

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

### Generator (§6.3, M3)

`miniapp/src/generator/diceware.ts` implements the diceware method: uniform
CSPRNG word selection (rejection sampling, no modulo bias) over the **official
EFF long wordlist** and a matching **Russian wordlist** — both the real
`diceware-wordlist-en-eff` / `diceware-wordlist-ru` npm packages, snapshotted
into static JSON (`miniapp/src/generator/wordlists/`, regenerate with
`npm run build:wordlists`) so the browser bundle never runs third-party
CommonJS code. Security comes from length (7776 = 6⁵ words, ~12.9 bits/word),
not character complexity — a locale switch (EN/RU) changes nothing about
strength since only list size and uniform sampling matter.

---

## Running it

### Dev — Mini App + tests (no Docker needed)

```bash
npm install
npm run typecheck     # strict TS
npm run build         # Vite build + SRI injection
npm test              # crypto unit + generator + §11.1 canary + §11.4 reveal + §11.5 compat
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

**Common first-run gotchas:**

- **Bot shows no menu / "Access denied" on `/start`.** `ALLOWLIST_CHAT_IDS` in
  `.env` must contain *your actual Telegram numeric user id* (get it from
  e.g. @userinfobot), not left blank — an empty allowlist rejects everyone
  (BRIEF §6.2). On startup the bot also registers the "/" command list and
  the persistent Menu button (☰ next to the message box) via
  `set_my_commands`/`set_chat_menu_button` — restart the bot container after
  changing `MINIAPP_URL` for the Menu button to pick up the new URL.
- **Unlock fails with "Securitica requires Argon2id".** Vaultwarden/Bitwarden
  accounts default to **PBKDF2-SHA256** unless you explicitly pick Argon2id
  at signup — and this client only supports Argon2id vaults (BRIEF §5.1).
  Fix it in the account, not the code: official web vault or Bitwarden
  app → **Settings → Security → Keys → KDF algorithm → Argon2id** → enter
  your master password to confirm. This re-wraps the same `userKey` under a
  new envelope (§5.3) — no data is lost.

---

## Security tests (BRIEF §11)

| # | What | Where | Runner |
|---|---|---|---|
| 11.1 | No plaintext in traffic to the server (canary, create + update) | `tests/security/no-plaintext.test.ts` | vitest |
| — | Account-event alerts carry metadata only, even if a client smuggles extra fields | `tests/security/test_events.py` | pytest |
| 11.3 | initData tamper / expiry rejected | `tests/security/test_initdata.py` | pytest |
| 11.4 | Reveal-lifecycle: DOM/clipboard scrubbed after timeout; no biometry ⇒ no reveal | `tests/security/reveal-lifecycle.test.ts` | vitest (jsdom) |
| 11.5 | EncString interop with an independent reference | `tests/security/compat.test.ts` | vitest |
| 11.6 | CSP has no `unsafe-inline`; SRI present | `tests/security/csp-audit.mjs` | node (post-build) |
| — | Offline export restores with only the master password, no network | `tests/security/export-restore.test.ts` | vitest |
| — | Press-and-hold release-before-gate-resolves race is handled, not lost | `miniapp/src/reveal/ui.test.ts` | vitest (jsdom) |
| — | Thin backend honors X-Forwarded-For (per-IP rate limit, correct alert IP) | `tests/security/test_proxy_headers.py` | pytest |
| — | No listener accumulation across list re-renders | `miniapp/src/main.test.ts` | vitest (jsdom) |

**The §11.1 proof.** The canary test instruments the client with a fetch
interceptor, runs the full M1 lifecycle plus a cipher create **and** a
subsequent update (M3), each with every field carrying a unique
`CANARY_PLAINTEXT_<rand>` marker, and asserts the marker appears in **no**
request body, URL, or header — while the EncString that *should* carry it is
present. Run `npm test` and look for the `[§11.1] intercepted outgoing
traffic` dump: every payload is either an EncString (`2.iv|ct|mac`) or the
base64 auth hash. No plaintext crosses the WebView boundary.

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
- **M3 — create/edit + generator + autofill:** ✅ create/edit forms
  (`vault/edit-ui.ts`) encrypting every field client-side before
  `createCipher`/`updateCipher` (`vault/edit.ts`); password and notes use a
  "blank means unchanged" convention so editing never requires an un-gated
  decrypt of the existing secret; editing *existing* notes is biometry-gated
  (they may hold recovery codes). Diceware generator (`generator/diceware.ts`)
  with the real EFF + RU wordlists feeds the password field directly —
  "autofill over reveal" (§7.6) applied as: a value you are actively creating
  goes straight into your own form field, no separate reveal/clipboard step.
  §11.1 canary extended to cover the update flow.
- **M4 — notifications + recovery + hardening:** ✅ account-event alerts
  (`server/notifications.py`) sent directly by the thin backend — which
  already holds `BOT_TOKEN` for initData verification — to Telegram's Bot API
  on login/export/master-password-change, metadata only (time, IP, optional
  GeoLite2 geo, device string); `POST /api/events` re-verifies `initData`
  server-side before sending anything. Master password change (`vault/
  password-change.ts`) re-wraps only the userKey envelope (§5.3) — no cipher
  is touched. Encrypted offline export (`vault/export.ts`) repackages
  ciphertext Vaultwarden already stores (protectedUserKey + raw EncStrings);
  restoring needs only the master password and the crypto core, no server
  contact (proven by an automated offline round-trip test). Optional §5.4
  second-factor-in-KDF extension point wired into `deriveMasterKey` (unused by
  default, documented, not required for MVP). CSP/SRI audit (§11.6) has been
  continuously enforced since M2.
