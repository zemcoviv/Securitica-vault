/**
 * Clipboard auto-clear (BRIEF §7 step 5).
 *
 * If a secret was copied, we overwrite the clipboard after a timer with
 * something harmless (empty string) — but ONLY if the clipboard still holds
 * exactly what we put there. Never blind-clear: another app's copy in the
 * interim must not be clobbered, and we must not assume clipboard read
 * access is granted (Clipboard API read requires a permission we may not
 * have; failures are swallowed since there is nothing actionable to do).
 */
const AUTO_CLEAR_MS = 20_000;

let pendingClear: ReturnType<typeof setTimeout> | null = null;

export async function copyWithAutoClear(
  value: string,
  clearAfterMs = AUTO_CLEAR_MS,
): Promise<void> {
  await navigator.clipboard.writeText(value);

  if (pendingClear) clearTimeout(pendingClear);
  pendingClear = setTimeout(() => {
    void clearIfUnchanged(value);
  }, clearAfterMs);
}

async function clearIfUnchanged(expected: string): Promise<void> {
  try {
    const current = await navigator.clipboard.readText();
    if (current === expected) {
      await navigator.clipboard.writeText("");
    }
  } catch {
    // No clipboard-read permission (common on Telegram WebView) — best
    // effort only; overwriting blindly risks destroying the user's own copy
    // of something unrelated, so we do nothing rather than guess.
  }
}

/** Cancel any pending auto-clear (e.g. the item was locked/navigated away). */
export function cancelPendingClear(): void {
  if (pendingClear) {
    clearTimeout(pendingClear);
    pendingClear = null;
  }
}
