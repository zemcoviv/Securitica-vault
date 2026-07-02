/**
 * Ephemeral reveal engine (BRIEF §7).
 *
 * Flow, entirely client-side:
 *   1. Biometric gate (biometry.ts) — no pass, no reveal.
 *   2. Decrypt the EncString with the in-memory userKey.
 *   3. Preferred mode: press-and-hold (visible only while held). Fallback:
 *      20s timer with a visible countdown.
 *   4. On release/timeout: scrub the DOM node (`textContent=""` then remove)
 *      and drop the decrypted reference.
 *
 * Honest limitation (BRIEF §7, README/SECURITY.md): JS gives no memory
 * zeroisation guarantee. We wipe what we control (the decrypted byte buffer)
 * and minimise the window the decoded string is reachable, but a decoded JS
 * string cannot itself be overwritten in place.
 */
import { decryptToBytes, type SymmetricKey } from "../crypto/encstring";
import { bytesToUtf8, wipe } from "../crypto/primitives";
import { requireBiometricConfirmation } from "./biometry";

export const HOLD_MODE = "hold" as const;
export const TIMER_MODE = "timer" as const;
export type RevealMode = typeof HOLD_MODE | typeof TIMER_MODE;

export const REVEAL_TIMEOUT_MS = 20_000;

export type BiometryDeniedReason = "denied" | "unavailable";

export interface RevealHandle {
  /** True while the plaintext is currently visible in the DOM. */
  readonly active: boolean;
  /** Force an immediate scrub (e.g. user navigates away, auto-lock fires). */
  stop(): void;
}

/**
 * Every reveal in progress registers here so auto-lock (or any "panic scrub")
 * can force-close all of them, not just the one the user is touching.
 */
const activeReveals = new Set<RevealHandle>();

/** Force-scrub every reveal currently in progress. Called by auto-lock. */
export function stopAllActiveReveals(): void {
  for (const handle of [...activeReveals]) handle.stop();
}

export interface RevealOptions {
  mode: RevealMode;
  /** Called each tick with remaining ms, timer mode only (drives the countdown UI). */
  onTick?: (remainingMs: number) => void;
  /** Called once the DOM has been scrubbed and the reveal has fully ended. */
  onEnd?: () => void;
  /** Called if the biometric gate rejects the reveal, instead of starting it. */
  onDenied?: (reason: BiometryDeniedReason) => void;
}

/**
 * Gate + decrypt + display a secret into `target.textContent`, then scrub it.
 *
 * `target` must be a container the caller owns exclusively for the duration
 * of the reveal — it is removed from the DOM (not just cleared) on teardown,
 * matching BRIEF §7.4 ("затирание текстового узла DOM + удаление узла").
 */
export async function revealInto(
  target: HTMLElement,
  encryptedValue: string,
  userKey: SymmetricKey,
  options: RevealOptions,
): Promise<RevealHandle> {
  const gate = await requireBiometricConfirmation();
  if (gate !== "ok") {
    options.onDenied?.(gate === "unavailable" ? "unavailable" : "denied");
    return { active: false, stop() {} };
  }

  const plainBytes = await decryptToBytes(userKey, encryptedValue);
  let plainText: string | null = bytesToUtf8(plainBytes);
  wipe(plainBytes); // we control this buffer; drop it immediately after decoding

  let ended = false;
  let tickTimer: ReturnType<typeof setInterval> | null = null;
  let timeoutTimer: ReturnType<typeof setTimeout> | null = null;

  const scrub = () => {
    if (ended) return;
    ended = true;
    activeReveals.delete(handle);
    if (tickTimer) clearInterval(tickTimer);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    // BRIEF §7.4: blank the text node, then remove it; drop the JS reference.
    target.textContent = "";
    target.remove();
    plainText = null;
    options.onEnd?.();
  };

  const handle: RevealHandle = {
    get active() {
      return !ended;
    },
    stop: scrub,
  };
  activeReveals.add(handle);

  target.textContent = plainText;

  if (options.mode === TIMER_MODE) {
    const start = Date.now();
    options.onTick?.(REVEAL_TIMEOUT_MS);
    tickTimer = setInterval(() => {
      const remaining = Math.max(0, REVEAL_TIMEOUT_MS - (Date.now() - start));
      options.onTick?.(remaining);
    }, 250);
    timeoutTimer = setTimeout(scrub, REVEAL_TIMEOUT_MS);
  }
  // In HOLD_MODE the caller drives `stop()` from pointerup/pointerleave/blur.

  return handle;
}
