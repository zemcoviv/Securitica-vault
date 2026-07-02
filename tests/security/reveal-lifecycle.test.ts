/**
 * BRIEF §11.4 — reveal-lifecycle.
 *
 * "После таймаута: DOM не содержит значения; буфер очищен. Без биометрии
 * показ невозможен."
 *
 * We mock the biometry gate deterministically (its own logic — Telegram
 * BiometryManager vs WebAuthn fallback — is exercised structurally in
 * biometry.ts; here we only need "ok" / "denied" to drive the engine) and use
 * fake timers to fast-forward the 20s window instead of actually waiting.
 */
// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../miniapp/src/reveal/biometry", () => ({
  requireBiometricConfirmation: vi.fn(),
}));

import { encryptString, splitSymmetricKey } from "../../miniapp/src/crypto/encstring";
import { randomBytes } from "../../miniapp/src/crypto/primitives";
import { requireBiometricConfirmation } from "../../miniapp/src/reveal/biometry";
import { copyWithAutoClear } from "../../miniapp/src/reveal/clipboard";
import {
  HOLD_MODE,
  REVEAL_TIMEOUT_MS,
  TIMER_MODE,
  revealInto,
  stopAllActiveReveals,
} from "../../miniapp/src/reveal/engine";

const gate = vi.mocked(requireBiometricConfirmation);
const SECRET = "hunter2-correct-battery";

async function makeEncrypted(): Promise<{ key: ReturnType<typeof splitSymmetricKey>; enc: string }> {
  const key = splitSymmetricKey(randomBytes(64));
  const enc = await encryptString(key, SECRET);
  return { key, enc };
}

describe("§11.4 reveal-lifecycle", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    gate.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.replaceChildren();
  });

  it("without a successful biometric confirmation, there is no reveal", async () => {
    gate.mockResolvedValue("denied");
    const { key, enc } = await makeEncrypted();
    const target = document.createElement("span");
    document.body.append(target);

    let deniedReason = "";
    const handle = await revealInto(target, enc, key, {
      mode: TIMER_MODE,
      onDenied: (reason) => {
        deniedReason = reason;
      },
    });

    expect(handle.active).toBe(false);
    expect(deniedReason).toBe("denied");
    // The secret was never written into the DOM at all.
    expect(target.textContent).toBe("");
    expect(document.body.innerHTML.includes(SECRET)).toBe(false);
  });

  it("unavailable biometry also blocks the reveal (fail closed)", async () => {
    gate.mockResolvedValue("unavailable");
    const { key, enc } = await makeEncrypted();
    const target = document.createElement("span");
    document.body.append(target);

    const handle = await revealInto(target, enc, key, { mode: TIMER_MODE });
    expect(handle.active).toBe(false);
    expect(document.body.innerHTML.includes(SECRET)).toBe(false);
  });

  it("after the 20s timeout, the DOM no longer contains the value", async () => {
    gate.mockResolvedValue("ok");
    const { key, enc } = await makeEncrypted();
    const target = document.createElement("span");
    document.body.append(target);

    const handle = await revealInto(target, enc, key, { mode: TIMER_MODE });
    expect(handle.active).toBe(true);
    expect(target.textContent).toBe(SECRET);
    expect(document.body.contains(target)).toBe(true);

    await vi.advanceTimersByTimeAsync(REVEAL_TIMEOUT_MS);

    expect(handle.active).toBe(false);
    expect(target.textContent).toBe(""); // node blanked
    expect(document.body.contains(target)).toBe(false); // node removed
    expect(document.body.innerHTML.includes(SECRET)).toBe(false);
  });

  it("stop() (hold-mode release) scrubs the DOM immediately, before any timeout", async () => {
    gate.mockResolvedValue("ok");
    const { key, enc } = await makeEncrypted();
    const target = document.createElement("span");
    document.body.append(target);

    const handle = await revealInto(target, enc, key, { mode: HOLD_MODE });
    expect(target.textContent).toBe(SECRET);

    handle.stop();

    expect(handle.active).toBe(false);
    expect(target.textContent).toBe("");
    expect(document.body.contains(target)).toBe(false);
  });

  it("stopAllActiveReveals() force-scrubs every in-progress reveal (auto-lock hook)", async () => {
    gate.mockResolvedValue("ok");
    const a = await makeEncrypted();
    const b = await makeEncrypted();
    const targetA = document.createElement("span");
    const targetB = document.createElement("span");
    document.body.append(targetA, targetB);

    const handleA = await revealInto(targetA, a.enc, a.key, { mode: HOLD_MODE });
    const handleB = await revealInto(targetB, b.enc, b.key, { mode: HOLD_MODE });
    expect(targetA.textContent).toBe(SECRET);
    expect(targetB.textContent).toBe(SECRET);

    stopAllActiveReveals();

    expect(handleA.active).toBe(false);
    expect(handleB.active).toBe(false);
    expect(document.body.contains(targetA)).toBe(false);
    expect(document.body.contains(targetB)).toBe(false);
  });

  it("clipboard is auto-cleared after the timeout if untouched", async () => {
    const store = { value: "" };
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn(async (v: string) => {
          store.value = v;
        }),
        readText: vi.fn(async () => store.value),
      },
    });

    await copyWithAutoClear(SECRET, REVEAL_TIMEOUT_MS);
    expect(store.value).toBe(SECRET);

    await vi.advanceTimersByTimeAsync(REVEAL_TIMEOUT_MS);

    expect(store.value).toBe("");
  });

  it("clipboard auto-clear does NOT clobber a different value the user copied meanwhile", async () => {
    const store = { value: "" };
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn(async (v: string) => {
          store.value = v;
        }),
        readText: vi.fn(async () => store.value),
      },
    });

    await copyWithAutoClear(SECRET, REVEAL_TIMEOUT_MS);
    store.value = "something-else-the-user-copied"; // out-of-band change

    await vi.advanceTimersByTimeAsync(REVEAL_TIMEOUT_MS);

    expect(store.value).toBe("something-else-the-user-copied");
  });
});
