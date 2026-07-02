/**
 * Mini App entry — M1 unlock/sync + M2 ephemeral reveal.
 *
 * Create/edit + generator (M3) are still out of scope; the list is read-only.
 * Passwords are only ever decrypted for the duration of a gated reveal
 * (reveal/engine.ts) — never eagerly when the list renders.
 */
import { VaultwardenClient } from "./api/client";
import { verifySession } from "./api/session";
import { config, getDeviceIdentifier } from "./config";
import type { SymmetricKey } from "./crypto/encstring";
import { buildRevealField } from "./reveal/ui";
import { AutoLock } from "./vault/autolock";
import type { VaultItem } from "./vault/model";
import { unlock } from "./vault/unlock";
import { getInitData, initTelegram } from "./telegram/webapp";

const app = document.getElementById("app")!;

const client = new VaultwardenClient({
  baseUrl: config.vaultwardenUrl,
  deviceIdentifier: getDeviceIdentifier(),
});

const autoLock = new AutoLock(config.autoLockMs, () => renderUnlock());

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const c of children) node.append(c);
  return node;
}

function renderUnlock(error = ""): void {
  client.clearSession();
  app.replaceChildren();

  const email = el("input", { type: "email", autocomplete: "username", required: true });
  const password = el("input", {
    type: "password",
    autocomplete: "current-password",
    required: true,
  });
  const errorBox = el("div", { className: "error", textContent: error });
  const submit = el("button", { type: "submit", textContent: "Unlock vault" });

  const form = el("form", {}, [
    el("label", {}, ["Email", email]),
    el("label", {}, ["Master password", password]),
    submit,
    errorBox,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    errorBox.textContent = "Deriving keys…";
    try {
      // Identity check first (server-verified initData).
      if (config.serverUrl !== "") {
        const session = await verifySession(config.serverUrl, getInitData());
        if (!session.ok) throw new Error(`identity rejected (${session.error})`);
      }
      const { userKey, items } = await unlock(client, email.value, password.value);
      password.value = "";
      autoLock.hold(userKey);
      renderList(items, userKey);
    } catch (err) {
      renderUnlock((err as Error).message);
    }
  });

  app.append(
    el("h1", { textContent: "Securitica Vault" }),
    el("p", {
      className: "muted",
      textContent:
        "Zero-knowledge. Keys are derived on this device; the server only stores ciphertext.",
    }),
    form,
  );
  email.focus();
}

function renderList(items: VaultItem[], userKey: SymmetricKey): void {
  app.replaceChildren();
  ["pointerdown", "keydown"].forEach((evt) =>
    app.addEventListener(evt, () => autoLock.touch(), { passive: true }),
  );

  const lockBtn = el("button", { textContent: "Lock", type: "button" });
  lockBtn.addEventListener("click", () => autoLock.lock());

  const bar = el("div", { className: "bar" }, [
    el("h1", { textContent: "Vault" }),
    lockBtn,
  ]);

  const list = el("ul", { className: "items" });
  for (const item of items) {
    const sub = [item.username, item.uriHost].filter(Boolean).join(" · ");
    const row = el("li", { className: "item" }, [
      el("div", { className: "name", textContent: item.name }),
      el("div", { className: "sub", textContent: sub || "—" }),
    ]);
    if (item.encryptedPassword) {
      row.append(buildRevealField(item.encryptedPassword, userKey));
    }
    list.append(row);
  }

  app.append(
    bar,
    items.length
      ? list
      : el("p", { className: "muted", textContent: "No login records yet." }),
    el("p", {
      className: "muted",
      textContent:
        "Hold to reveal (biometric confirmation required). Passwords are decrypted only for the duration of the reveal.",
    }),
  );
}

initTelegram();
renderUnlock();
