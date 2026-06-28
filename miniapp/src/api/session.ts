/**
 * Thin-backend session: POST the raw Telegram initData to OUR server, which
 * verifies the HMAC + auth_date TTL (server/initdata.py) and rate-limits.
 *
 * This authenticates identity only (BRIEF §6.3). It returns nothing secret and
 * gates nothing cryptographic — the vault still requires the master password.
 */
export interface SessionResult {
  ok: boolean;
  userId?: number;
  error?: string;
}

export async function verifySession(
  serverBaseUrl: string,
  initData: string,
  fetchImpl: typeof fetch = fetch,
): Promise<SessionResult> {
  const res = await fetchImpl(`${serverBaseUrl.replace(/\/+$/, "")}/api/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ initData }),
  });
  if (res.status === 429) return { ok: false, error: "rate_limited" };
  if (!res.ok) return { ok: false, error: `verify_failed_${res.status}` };
  const data = (await res.json()) as { ok: boolean; userId?: number };
  return { ok: data.ok, userId: data.userId };
}
