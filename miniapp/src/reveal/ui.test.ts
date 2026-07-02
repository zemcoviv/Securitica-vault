/**
 * Regression test for the press-and-hold race condition (security review
 * finding): if the pointer is released while the biometric gate is still
 * pending — guaranteed on the WebAuthn fallback path, since its OS dialog
 * requires letting go of the physical button first — the release must not
 * be lost. The secret must be scrubbed the instant the gate resolves, never
 * left displayed indefinitely.
 */
// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./biometry", () => ({
  requireBiometricConfirmation: vi.fn(),
}));

import { encryptString, splitSymmetricKey } from "../crypto/encstring";
import { randomBytes } from "../crypto/primitives";
import { requireBiometricConfirmation } from "./biometry";
import { buildRevealField } from "./ui";

const gate = vi.mocked(requireBiometricConfirmation);
const SECRET = "s3cr3t-race-condition-value";

// WebCrypto's subtle.decrypt et al. don't always settle on pure microtasks
// (Node's implementation can hop through a macrotask), so mix in real
// zero-delay timeouts rather than only chaining Promise.resolve().
async function flushMicrotasks(times = 10): Promise<void> {
  for (let i = 0; i < times; i++) {
    await Promise.resolve();
    await new Promise((r) => setTimeout(r, 0));
  }
}

describe("press-and-hold: release-before-gate-resolves race", () => {
  afterEach(() => {
    document.body.replaceChildren();
    gate.mockReset();
  });

  it("scrubs the secret immediately once the gate resolves if released early", async () => {
    let resolveGate!: (v: "ok") => void;
    gate.mockReturnValue(
      new Promise((resolve) => {
        resolveGate = resolve;
      }),
    );

    const key = splitSymmetricKey(randomBytes(64));
    const enc = await encryptString(key, SECRET);
    const field = buildRevealField(enc, key);
    document.body.append(field);

    const holdBtn = field.querySelector(".reveal-hold") as HTMLButtonElement;

    // Fast press-release: the gate is still pending when pointerup fires.
    holdBtn.dispatchEvent(new Event("pointerdown"));
    holdBtn.dispatchEvent(new Event("pointerup"));
    await flushMicrotasks();

    expect(field.textContent).not.toContain(SECRET);

    // The gate resolves "ok" AFTER the release already happened.
    resolveGate("ok");
    await flushMicrotasks();

    // Must be scrubbed immediately, not left visible indefinitely.
    expect(field.textContent).not.toContain(SECRET);
    expect(document.body.innerHTML).not.toContain(SECRET);
  });

  it("still reveals normally when the gate resolves before release (no race)", async () => {
    gate.mockResolvedValue("ok");

    const key = splitSymmetricKey(randomBytes(64));
    const enc = await encryptString(key, SECRET);
    const field = buildRevealField(enc, key);
    document.body.append(field);

    const holdBtn = field.querySelector(".reveal-hold") as HTMLButtonElement;
    holdBtn.dispatchEvent(new Event("pointerdown"));
    await flushMicrotasks();

    expect(field.textContent).toContain(SECRET);

    holdBtn.dispatchEvent(new Event("pointerup"));
    await flushMicrotasks();

    expect(field.textContent).not.toContain(SECRET);
  });

  it("a second press after a lost release still works (no stuck state)", async () => {
    let resolveFirstGate!: (v: "ok") => void;
    gate.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveFirstGate = resolve;
      }),
    );

    const key = splitSymmetricKey(randomBytes(64));
    const enc = await encryptString(key, SECRET);
    const field = buildRevealField(enc, key);
    document.body.append(field);
    const holdBtn = field.querySelector(".reveal-hold") as HTMLButtonElement;

    // First press: released early, gate resolves late -> auto-scrubbed.
    holdBtn.dispatchEvent(new Event("pointerdown"));
    holdBtn.dispatchEvent(new Event("pointerup"));
    await flushMicrotasks();
    resolveFirstGate("ok");
    await flushMicrotasks();
    expect(field.textContent).not.toContain(SECRET);

    // Second press: this time hold it — must still work (not stuck denied/open).
    gate.mockResolvedValueOnce("ok");
    holdBtn.dispatchEvent(new Event("pointerdown"));
    await flushMicrotasks();
    expect(field.textContent).toContain(SECRET);

    holdBtn.dispatchEvent(new Event("pointerup"));
    await flushMicrotasks();
    expect(field.textContent).not.toContain(SECRET);
  });
});
