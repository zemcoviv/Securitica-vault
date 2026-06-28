/**
 * Mini App entry — M1: identity check → unlock → decrypted record list.
 *
 * Reveal (M2), create/edit + generator (M3) are out of scope here; the list is
 * read-only and passwords are NOT decrypted on this screen.
 */
import { VaultwardenClient } from "./api/client";
import { verifySession } from "./api/session";
import { config, getDeviceIdentifier } from "./config";
import type { SymmetricKey } from "./crypto/encstring";
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

function renderList(items: VaultItem[], _userKey: SymmetricKey): void {
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
    list.append(
      el("li", { className: "item" }, [
        el("div", { className: "name", textContent: item.name }),
        el("div", { className: "sub", textContent: sub || "—" }),
      ]),
    );
  }

  app.append(
    bar,
    items.length
      ? list
      : el("p", { className: "muted", textContent: "No login records yet." }),
    el("p", {
      className: "muted",
      textContent:
        "Reveal & autofill arrive in M2. Passwords are not decrypted on this screen.",
    }),
  );
}

initTelegram();
renderUnlock();
