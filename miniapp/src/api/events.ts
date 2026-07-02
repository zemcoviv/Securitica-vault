/**
 * Metadata-only account-event reporting to the thin backend (BRIEF §6.2,
 * §10 M4). Never carries a secret — only a closed `kind` enum and a short
 * device label (the browser's user-agent string, capped). The server
 * re-verifies `initData` itself; this call is best-effort and never blocks
 * or fails the caller's own flow (login/export/password-change already
 * succeeded by the time this fires).
 */
export type AccountEventKind = "login" | "export" | "master_password_changed";

export async function reportAccountEvent(
  serverBaseUrl: string,
  initData: string,
  kind: AccountEventKind,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  if (!serverBaseUrl) return; // no thin backend configured (e.g. local dev)
  try {
    await fetchImpl(`${serverBaseUrl.replace(/\/+$/, "")}/api/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        initData,
        kind,
        device: navigator.userAgent.slice(0, 120),
      }),
    });
  } catch {
    // Best-effort notification only — never surface this to the user.
  }
}
