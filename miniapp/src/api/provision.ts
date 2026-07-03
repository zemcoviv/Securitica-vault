/**
 * Account provisioning against the thin backend (BRIEF §1: the user never
 * sees Vaultwarden, an email field, or a KDF setting). The server resolves
 * Telegram identity to a synthetic email and — for a brand-new user — an
 * admin-created invitation, so the client can register() immediately after.
 *
 * This purely decides which first-run screen to show; it never carries or
 * gates a secret (see server/main.py's /api/provision docstring).
 */
export type ProvisionStatus = "new" | "existing";

export interface ProvisionResult {
  ok: boolean;
  email?: string;
  status?: ProvisionStatus;
  error?: string;
}

export async function provisionAccount(
  serverBaseUrl: string,
  initData: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ProvisionResult> {
  const res = await fetchImpl(`${serverBaseUrl.replace(/\/+$/, "")}/api/provision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ initData }),
  });
  if (res.status === 429) return { ok: false, error: "rate_limited" };
  if (!res.ok) return { ok: false, error: `provision_failed_${res.status}` };
  const data = (await res.json()) as {
    ok: boolean;
    email?: string;
    status?: ProvisionStatus;
  };
  return { ok: data.ok, email: data.email, status: data.status };
}

/** Tell the server registration completed, so future provisionAccount calls
 * report "existing" instead of re-inviting. Best-effort: a failure here just
 * means the next open re-provisions (harmless, idempotent on the server). */
export async function completeProvisioning(
  serverBaseUrl: string,
  initData: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  try {
    await fetchImpl(`${serverBaseUrl.replace(/\/+$/, "")}/api/provision/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ initData }),
    });
  } catch {
    // Best-effort; see doc comment above.
  }
}
