/**
 * Mini App entry — M1 unlock/sync, M2 ephemeral reveal, M3 create/edit,
 * M4 notifications/export/password-change.
 *
 * Passwords are only ever decrypted for the duration of a gated reveal
 * (reveal/engine.ts) — never eagerly when the list renders, and never just to
 * prefill an edit form (vault/edit.ts uses a "blank means unchanged" scheme).
 */
import { VaultwardenClient } from "./api/client";
import { reportAccountEvent } from "./api/events";
import { completeProvisioning, provisionAccount } from "./api/provision";
import { config, getDeviceIdentifier } from "./config";
import type { SymmetricKey } from "./crypto/encstring";
import type { KdfConfig } from "./crypto/keys";
import { buildRevealField } from "./reveal/ui";
import { AutoLock } from "./vault/autolock";
import { createItem, updateItem } from "./vault/edit";
import { buildItemForm } from "./vault/edit-ui";
import { buildExport, downloadExport } from "./vault/export";
import { decryptVault, type VaultItem } from "./vault/model";
import { changeMasterPassword } from "./vault/password-change";
import { registerAndUnlock } from "./vault/register";
import { unlock, type UnlockResult } from "./vault/unlock";
import { getInitData, getTelegramFirstName, initTelegram } from "./telegram/webapp";

const app = document.getElementById("app")!;

const client = new VaultwardenClient({
  baseUrl: config.vaultwardenUrl,
  deviceIdentifier: getDeviceIdentifier(),
});

const autoLock = new AutoLock(config.autoLockMs, () => {
  session = null;
  void renderUnlock();
});

// Registered once for the lifetime of the app on the persistent #app element
// (renderUnlock/renderList/etc. only ever replace #app's CHILDREN via
// replaceChildren(), never #app itself). Binding this inside renderList()
// used to re-register a fresh pair of listeners on every call — i.e. on
// every create/edit/export/password-change round trip — leaking listeners
// for the rest of the session.
["pointerdown", "keydown"].forEach((evt) =>
  app.addEventListener(evt, () => autoLock.touch(), { passive: true }),
);

/** Session metadata needed later for export / password change. Never a secret. */
interface Session {
  email: string;
  kdf: KdfConfig;
  protectedUserKey: string;
}
let session: Session | null = null;

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

function onUnlocked(initData: string, result: UnlockResult): void {
  session = {
    email: result.email,
    kdf: result.kdf,
    protectedUserKey: result.protectedUserKey,
  };
  autoLock.hold(result.userKey);
  void reportAccountEvent(config.serverUrl, initData, "login");
  renderList(result.items, result.userKey);
}

/**
 * A resolved, known email — either a returning user's or a brand-new
 * account's — needing only a password. No email field anywhere: the thin
 * backend resolved Telegram identity to this address already (BRIEF §1).
 */
function renderKnownAccountForm(opts: {
  email: string;
  isNewAccount: boolean;
  initData: string;
}): void {
  app.replaceChildren();

  const password = el("input", {
    type: "password",
    autocomplete: opts.isNewAccount ? "new-password" : "current-password",
    required: true,
  });
  const errorBox = el("div", { className: "error" });
  const submit = el("button", {
    type: "submit",
    textContent: opts.isNewAccount ? "Create vault" : "Unlock vault",
  });

  const form = el("form", {}, [
    el("label", {}, [opts.isNewAccount ? "Choose a master password" : "Master password", password]),
    submit,
    errorBox,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    errorBox.textContent = opts.isNewAccount ? "Creating your vault…" : "Deriving keys…";
    try {
      const result = opts.isNewAccount
        ? await registerAndUnlock(client, opts.email, password.value, getTelegramFirstName())
        : await unlock(client, opts.email, password.value);
      password.value = "";
      if (opts.isNewAccount) {
        void completeProvisioning(config.serverUrl, opts.initData);
      }
      onUnlocked(opts.initData, result);
    } catch (err) {
      errorBox.textContent = (err as Error).message;
      submit.disabled = false;
    }
  });

  app.append(
    el("h1", {
      textContent: opts.isNewAccount ? "Welcome — set up your vault" : "Securitica Vault",
    }),
    el("p", {
      className: "muted",
      textContent: opts.isNewAccount
        ? "This master password is the only key to your data. We never see it, and if it's lost nobody can recover it for you — export a backup once you're in."
        : "Zero-knowledge. Keys are derived on this device; the server only stores ciphertext.",
    }),
    form,
  );
  password.focus();
}

/** No thin backend configured (local dev without server/) — fall back to a
 * manual email+password form against whatever Vaultwarden account exists. */
function renderManualLoginForm(error = ""): void {
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
      const result = await unlock(client, email.value, password.value);
      password.value = "";
      onUnlocked(getInitData(), result);
    } catch (err) {
      renderManualLoginForm((err as Error).message);
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

async function renderUnlock(): Promise<void> {
  client.clearSession();
  session = null;

  if (!config.hasThinBackend) {
    renderManualLoginForm();
    return;
  }

  app.replaceChildren();
  app.append(el("p", { className: "muted", textContent: "Loading…" }));

  const initData = getInitData();
  const result = await provisionAccount(config.serverUrl, initData);
  if (!result.ok || !result.email) {
    renderManualLoginForm(`identity rejected (${result.error ?? "unknown"})`);
    return;
  }
  renderKnownAccountForm({
    email: result.email,
    isNewAccount: result.status === "new",
    initData,
  });
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

async function handleExport(): Promise<void> {
  if (!session) return;
  const data = await buildExport(client, session.email, session.kdf, session.protectedUserKey);
  downloadExport(data);
  void reportAccountEvent(config.serverUrl, getInitData(), "export");
}

function renderChangePasswordForm(userKey: SymmetricKey): void {
  if (!session) return;
  const { email, kdf } = session;
  app.replaceChildren();

  const current = el("input", {
    type: "password",
    autocomplete: "current-password",
    required: true,
  });
  const next = el("input", { type: "password", autocomplete: "new-password", required: true });
  const confirm = el("input", {
    type: "password",
    autocomplete: "new-password",
    required: true,
  });
  const errorBox = el("div", { className: "error" });
  const submit = el("button", { type: "submit", textContent: "Change master password" });
  const cancel = el("button", { type: "button", textContent: "Cancel" });
  cancel.addEventListener("click", () => void refreshList(userKey));

  const form = el("form", {}, [
    el("label", {}, ["Current master password", current]),
    el("label", {}, ["New master password", next]),
    el("label", {}, ["Confirm new master password", confirm]),
    el("div", { className: "form-actions" }, [submit, cancel]),
    errorBox,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (next.value !== confirm.value) {
      errorBox.textContent = "New passwords don't match.";
      return;
    }
    submit.disabled = true;
    errorBox.textContent = "Re-wrapping key envelope…";
    try {
      // §5.3: only the userKey envelope is reissued — no cipher is touched.
      await changeMasterPassword(client, {
        email,
        oldMasterPassword: current.value,
        newMasterPassword: next.value,
        kdf,
        userKey,
      });
      current.value = next.value = confirm.value = "";
      void reportAccountEvent(config.serverUrl, getInitData(), "master_password_changed");
      // Vaultwarden invalidates the prior session on password change — force
      // a fresh unlock with the new master password.
      autoLock.lock();
    } catch (err) {
      errorBox.textContent = (err as Error).message;
      submit.disabled = false;
    }
  });

  app.append(el("h1", { textContent: "Change master password" }), form);
}

function renderList(items: VaultItem[], userKey: SymmetricKey): void {
  app.replaceChildren();

  const addBtn = el("button", { textContent: "+ Add", type: "button" });
  addBtn.addEventListener("click", () => renderCreateForm(userKey));

  const exportBtn = el("button", { textContent: "Export", type: "button" });
  exportBtn.addEventListener("click", () => void handleExport());

  const changePwBtn = el("button", { textContent: "Change password", type: "button" });
  changePwBtn.addEventListener("click", () => renderChangePasswordForm(userKey));

  const lockBtn = el("button", { textContent: "Lock", type: "button" });
  lockBtn.addEventListener("click", () => autoLock.lock());

  const bar = el("div", { className: "bar" }, [
    el("h1", { textContent: "Vault" }),
    el("div", { className: "bar-actions" }, [addBtn, exportBtn, changePwBtn, lockBtn]),
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
void renderUnlock();
