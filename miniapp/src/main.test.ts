/**
 * Regression test (security review finding): renderList() used to call
 * app.addEventListener("pointerdown"/"keydown", ...) on every invocation —
 * i.e. on every create/edit/export/password-change round trip — without ever
 * removing the previous listeners, leaking one more pair onto the persistent
 * #app element each time. The fix registers them exactly once, at module
 * load. This test drives the real app through several list re-renders and
 * asserts the listener count never grows past 1.
 */
// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { encryptBytes } from "./crypto/encstring";
import { deriveMasterKey, KdfType } from "./crypto/keys";
import { randomBytes } from "./crypto/primitives";

const EMAIL = "leak-test@example.com";
const PASSWORD = "correct-horse-battery-staple";
const FAST_KDF = {
  kdf: KdfType.Argon2id,
  kdfIterations: 1,
  kdfMemory: 8,
  kdfParallelism: 1,
};

async function clickButtonWithText(text: string): Promise<void> {
  const btn = [...document.querySelectorAll("button")].find(
    (b) => b.textContent === text,
  );
  if (!btn) throw new Error(`no button with text "${text}"`);
  btn.click();
}

describe("main.ts: no listener accumulation across re-renders", () => {
  it("registers pointerdown/keydown on #app exactly once, no matter how many times the list re-renders", async () => {
    document.body.innerHTML = '<main id="app"></main>';
    const appEl = document.getElementById("app")!;
    const addSpy = vi.spyOn(appEl, "addEventListener");

    // --- fake Vaultwarden, mirroring the tests/security/no-plaintext.test.ts fixture ---
    const { stretchedKey } = await deriveMasterKey(EMAIL, PASSWORD, {
      kdfType: KdfType.Argon2id,
      iterations: 1,
      memoryMiB: 8,
      parallelism: 1,
    });
    const rawUserKey = randomBytes(64);
    const protectedUserKey = await encryptBytes(stretchedKey, rawUserKey);

    const json = (obj: unknown) =>
      new Response(JSON.stringify(obj), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const method = init?.method ?? "GET";
      if (url.includes("/identity/accounts/prelogin")) return json(FAST_KDF);
      if (url.includes("/identity/connect/token")) {
        return json({
          access_token: "test-token",
          expires_in: 3600,
          token_type: "Bearer",
          Key: protectedUserKey,
          Kdf: KdfType.Argon2id,
          KdfIterations: 1,
        });
      }
      if (url.includes("/api/sync")) return json({ ciphers: [], profile: { email: EMAIL } });
      if (method === "POST" && url.includes("/api/ciphers")) return json({ id: "new-id" });
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    await import("./main");

    // Unlock.
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    emailInput.value = EMAIL;
    pwInput.value = PASSWORD;
    document
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

    await vi.waitFor(() => expect(document.querySelector(".bar")).toBeTruthy());

    const pointerdownCount = () =>
      addSpy.mock.calls.filter((c) => c[0] === "pointerdown").length;
    const keydownCount = () => addSpy.mock.calls.filter((c) => c[0] === "keydown").length;

    expect(pointerdownCount()).toBe(1);
    expect(keydownCount()).toBe(1);

    // Drive several list re-renders: "+ Add" -> "Cancel", repeated. Each
    // cancel calls refreshList() -> renderList() again.
    for (let i = 0; i < 4; i++) {
      await clickButtonWithText("+ Add");
      await vi.waitFor(() => expect(document.querySelector(".item-form")).toBeTruthy());
      await clickButtonWithText("Cancel");
      await vi.waitFor(() => expect(document.querySelector(".bar")).toBeTruthy());
    }

    // Must still be exactly 1 each — not accumulated to 5.
    expect(pointerdownCount()).toBe(1);
    expect(keydownCount()).toBe(1);
  });
});
