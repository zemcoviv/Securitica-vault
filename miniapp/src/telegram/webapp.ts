/**
 * Telegram Mini App bridge.
 *
 * INVARIANT (BRIEF §2): `initData` authenticates the *identity* for sync /
 * rate-limit only. It is NEVER key material. Telegram transport is treated as
 * an untrusted CDN — confidentiality must not depend on it. initData is
 * verified **server-side** (server/initdata.py); the client never trusts its
 * own check for auth decisions.
 */

interface TelegramWebApp {
  initData: string;
  initDataUnsafe: {
    user?: { id: number; username?: string; first_name?: string };
  };
  colorScheme: "light" | "dark";
  themeParams: Record<string, string>;
  ready(): void;
  expand(): void;
  BiometryManager?: {
    isInited: boolean;
    isBiometricAvailable: boolean;
    init(cb?: () => void): void;
    authenticate(
      params: { reason?: string },
      cb: (ok: boolean) => void,
    ): void;
  };
}

declare global {
  interface Window {
    Telegram?: { WebApp?: TelegramWebApp };
  }
}

export function getWebApp(): TelegramWebApp | null {
  return window.Telegram?.WebApp ?? null;
}

/** Raw initData query string, to be POSTed to our server for verification. */
export function getInitData(): string {
  return getWebApp()?.initData ?? "";
}

/**
 * `initDataUnsafe.user.first_name` is client-supplied and NOT server-verified
 * (that's exactly what "unsafe" means here) — it is display metadata only,
 * used as a friendly default account name at registration. Never treat this
 * as an authenticated identity; that's what verified `initData` is for.
 */
export function getTelegramFirstName(): string | undefined {
  return getWebApp()?.initDataUnsafe.user?.first_name;
}

export function applyTheme(): void {
  const wa = getWebApp();
  if (!wa) return;
  document.documentElement.dataset.theme = wa.colorScheme;
  for (const [k, v] of Object.entries(wa.themeParams)) {
    document.documentElement.style.setProperty(`--tg-${k}`, v);
  }
}

export function initTelegram(): void {
  const wa = getWebApp();
  if (!wa) return;
  wa.ready();
  wa.expand();
  applyTheme();
}
