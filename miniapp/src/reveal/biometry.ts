/**
 * Biometry gate before any secret reveal (BRIEF §7 step 1).
 *
 * INVARIANT: without a successful verification, there is no reveal. This is
 * a UX/replay-friction gate, not a key-derivation step — the userKey is
 * already in memory after unlock (§5). Biometry here proves "this is the
 * device holder" immediately before plaintext becomes visible, shrinking the
 * window an attacker who has taken over an unlocked, unattended session can
 * exploit.
 *
 * Preferred: Telegram.WebApp.BiometryManager (native Face/Touch ID via the
 * Telegram client). Fallback: WebAuthn user-verification (platform
 * authenticator), for WebViews without BiometryManager support.
 */
import { getWebApp } from "../telegram/webapp";

export type BiometryOutcome = "ok" | "denied" | "unavailable";

function authenticateViaTelegram(reason: string): Promise<BiometryOutcome> {
  return new Promise((resolve) => {
    const wa = getWebApp();
    const bio = wa?.BiometryManager;
    if (!bio) {
      resolve("unavailable");
      return;
    }

    const run = () => {
      if (!bio.isBiometricAvailable) {
        resolve("unavailable");
        return;
      }
      bio.authenticate({ reason }, (ok) => resolve(ok ? "ok" : "denied"));
    };

    if (bio.isInited) {
      run();
    } else {
      bio.init(run);
    }
  });
}

/**
 * WebAuthn user-verification fallback. We don't need a registered credential
 * tied to the vault — `navigator.credentials.get` with `userVerification:
 * "required"` and no allowCredentials still forces the platform authenticator
 * (Face/Touch ID, Windows Hello, device PIN) to confirm presence, which is
 * exactly the friction we need. A thrown/aborted call means "denied".
 */
async function authenticateViaWebAuthn(): Promise<BiometryOutcome> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    return "unavailable";
  }
  try {
    const available =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.();
    if (available === false) return "unavailable";

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge,
        userVerification: "required",
        timeout: 30_000,
      },
    });
    return credential ? "ok" : "denied";
  } catch {
    return "denied";
  }
}

/**
 * Gate a reveal action. Resolves "ok" only on a genuine, fresh verification.
 * Callers MUST NOT proceed to decrypt/display on any other outcome.
 */
export async function requireBiometricConfirmation(
  reason = "Confirm to reveal this secret",
): Promise<BiometryOutcome> {
  const viaTelegram = await authenticateViaTelegram(reason);
  if (viaTelegram !== "unavailable") return viaTelegram;
  return authenticateViaWebAuthn();
}
