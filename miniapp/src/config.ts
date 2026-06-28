/**
 * Runtime configuration. Hosts are injected at build time via Vite env vars so
 * no secrets are baked in (there are none here — only public origins).
 *
 *   VITE_SERVER_URL       — our thin backend (initData verify + static)
 *   VITE_VAULTWARDEN_URL  — the Vaultwarden origin (client talks to it directly)
 *
 * Defaults assume same-origin server and a /vault reverse-proxy path behind
 * Caddy; override per deployment. Keep connect-src in the CSP in sync.
 */
export const config = {
  serverUrl: import.meta.env.VITE_SERVER_URL ?? "",
  vaultwardenUrl: import.meta.env.VITE_VAULTWARDEN_URL ?? "/vault",
  autoLockMs: Number(import.meta.env.VITE_AUTOLOCK_MS ?? 60_000),
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
