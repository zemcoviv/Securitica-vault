/**
 * Runtime configuration. Hosts are injected at build time via Vite env vars so
 * no secrets are baked in (there are none here — only public origins).
 *
 *   VITE_SERVER_URL       — our thin backend (initData verify + static)
 *   VITE_VAULTWARDEN_URL  — the Vaultwarden origin (client talks to it directly)
 *
 * Defaults assume same-origin server and a /vault reverse-proxy path behind
 * Caddy; override per deployment. Keep connect-src in the CSP in sync.
 *
 * `serverUrl: ""` is a valid, correct value in production — it means "same
 * origin, relative paths" (exactly how Caddy serves miniapp-server's /api/*
 * alongside the static bundle). It must NOT be read as "no thin backend
 * configured": every real deployment (server/Dockerfile always builds with
 * VITE_SERVER_URL="") has one. `hasThinBackend` uses Vite's own DEV/PROD
 * distinction instead — false for every `vite build` output (what Docker
 * ships), true only for a bare `npm run dev` with no backend wired up.
 */
export const config = {
  serverUrl: import.meta.env.VITE_SERVER_URL ?? "",
  vaultwardenUrl: import.meta.env.VITE_VAULTWARDEN_URL ?? "/vault",
  autoLockMs: Number(import.meta.env.VITE_AUTOLOCK_MS ?? 60_000),
  hasThinBackend: !import.meta.env.DEV || (import.meta.env.VITE_SERVER_URL ?? "") !== "",
};

/** Stable per-install device id (identity only; never key material). */
export function getDeviceIdentifier(): string {
  const KEY = "securitica.deviceId";
  let id = localStorage.getItem(KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(KEY, id);
  }
  return id;
}
