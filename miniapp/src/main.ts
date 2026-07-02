/**
 * Mini App entry — M1 unlock/sync, M2 ephemeral reveal, M3 create/edit.
 *
 * Passwords are only ever decrypted for the duration of a gated reveal
 * (reveal/engine.ts) — never eagerly when the list renders, and never just to
 * prefill an edit form (vault/edit.ts uses a "blank means unchanged" scheme).
 */
import { VaultwardenClient } from "./api/client";
import { verifySession } from "./api/session";
import { config, getDeviceIdentifier } from "./config";
import type { SymmetricKey } from "./crypto/encstring";
import { buildRevealField } from "./reveal/ui";
import { AutoLock } from "./vault/autolock";
import { createItem, updateItem } from "./vault/edit";
import { buildItemForm } from "./vault/edit-ui";
import { decryptVault, type VaultItem } from "./vault/model";
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

async function refreshList(userKey: SymmetricKey): Promise<void> {
  const sync = await client.sync();
  const items = await decryptVault(userKey, sync);
  renderList(items, userKey);
}

function renderCreateForm(userKey: SymmetricKey): void {
  app.replaceChildren();
  const form = buildItemForm({
    mode: "create",
    userKey,
    onCancel: () => void refreshList(userKey),
    onSubmit: async (values) => {
      await createItem(client, userKey, values);
      await refreshList(userKey);
    },
  });
  app.append(el("h1", { textContent: "New item" }), form);
}

function renderEditForm(item: VaultItem, userKey: SymmetricKey): void {
  app.replaceChildren();
  const form = buildItemForm({
    mode: "edit",
    userKey,
    prefill: { name: item.name, username: item.username ?? "", uri: item.uri ?? "" },
    encryptedNotes: item.encryptedNotes,
    onCancel: () => void refreshList(userKey),
    onSubmit: async (values) => {
      await updateItem(client, userKey, item.id, values, {
        password: item.encryptedPassword,
        notes: item.encryptedNotes,
      });
      await refreshList(userKey);
    },
  });
  app.append(el("h1", { textContent: "Edit item" }), form);
}

function renderList(items: VaultItem[], userKey: SymmetricKey): void {
  app.replaceChildren();
  ["pointerdown", "keydown"].forEach((evt) =>
    app.addEventListener(evt, () => autoLock.touch(), { passive: true }),
  );

  const addBtn = el("button", { textContent: "+ Add", type: "button" });
  addBtn.addEventListener("click", () => renderCreateForm(userKey));

  const lockBtn = el("button", { textContent: "Lock", type: "button" });
  lockBtn.addEventListener("click", () => autoLock.lock());

  const bar = el("div", { className: "bar" }, [
    el("h1", { textContent: "Vault" }),
    el("div", { className: "bar-actions" }, [addBtn, lockBtn]),
  ]);

  const list = el("ul", { className: "items" });
  for (const item of items) {
    const sub = [item.username, item.uriHost].filter(Boolean).join(" · ");
    const editBtn = el("button", { textContent: "Edit", type: "button", className: "edit-btn" });
    editBtn.addEventListener("click", () => renderEditForm(item, userKey));

    const row = el("li", { className: "item" }, [
      el("div", { className: "item-head" }, [
        el("div", { className: "name", textContent: item.name }),
        editBtn,
      ]),
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
