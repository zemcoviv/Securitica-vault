/**
 * Create/edit form UI (BRIEF §10 M3).
 *
 * Password field UX, by design:
 *   - create: starts empty; type manually or click Generate.
 *   - edit: starts empty ("leave unchanged"); typing or generating REPLACES
 *     the stored password. We never decrypt the existing password just to
 *     prefill this field — that would be an un-gated reveal (BRIEF §7).
 * Generated passphrases go straight into the field (§7.6 "автозаполнение
 * поверх показа") — there is no separate reveal/clipboard step, because the
 * user is creating this value, not viewing someone else's stored secret.
 *
 * Notes may hold recovery codes (BRIEF §1 "не только в голове"), so editing
 * EXISTING notes is gated behind the same biometric confirmation the M2
 * reveal flow uses; a blank notes field on save means "leave unchanged".
 */
import { decryptToString, type SymmetricKey } from "../crypto/encstring";
import { requireBiometricConfirmation } from "../reveal/biometry";
import {
  entropyBitsFor,
  generateDiceware,
  wordlistSize,
  type WordlistLocale,
} from "../generator/diceware";
import type { ItemFormValues } from "./edit";

export interface ItemFormPrefill {
  name: string;
  username: string;
  uri: string;
}

export interface ItemFormConfig {
  mode: "create" | "edit";
  prefill?: ItemFormPrefill;
  /** Present only in edit mode: the item's raw encrypted notes, if any. */
  encryptedNotes?: string | null;
  userKey: SymmetricKey;
  onSubmit: (values: ItemFormValues) => Promise<void>;
  onCancel: () => void;
}

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

function buildGeneratorPanel(passwordField: HTMLInputElement): HTMLElement {
  const wordCount = el("select", {}) as HTMLSelectElement;
  for (const n of [4, 5, 6, 7, 8]) {
    wordCount.append(el("option", { value: String(n), textContent: `${n} words` }));
  }
  wordCount.value = "6";

  const locale = el("select", {}) as HTMLSelectElement;
  locale.append(
    el("option", { value: "en", textContent: "English" }),
    el("option", { value: "ru", textContent: "Русский" }),
  );

  const digit = el("input", { type: "checkbox", id: "gen-digit" });
  const digitLabel = el("label", { className: "inline-check" }, [digit, " +digit"]);

  const entropy = el("span", { className: "muted entropy" });

  const generateBtn = el("button", { type: "button", textContent: "Generate" });
  generateBtn.addEventListener("click", () => {
    const n = Number(wordCount.value);
    const loc = locale.value as WordlistLocale;
    const result = generateDiceware({
      wordCount: n,
      locale: loc,
      includeDigit: digit.checked,
    });
    passwordField.value = result.passphrase;
    entropy.textContent = `~${Math.round(result.entropyBits)} bits (${wordlistSize(loc)}-word list)`;
  });

  // Show the theoretical entropy for the current settings even before generating.
  const updateEstimate = () => {
    const n = Number(wordCount.value);
    const bits = entropyBitsFor(n, wordlistSize(locale.value as WordlistLocale));
    entropy.textContent = `~${Math.round(bits)} bits estimated`;
  };
  wordCount.addEventListener("change", updateEstimate);
  locale.addEventListener("change", updateEstimate);
  updateEstimate();

  return el("div", { className: "generator-panel" }, [
    wordCount,
    locale,
    digitLabel,
    generateBtn,
    entropy,
  ]);
}

export function buildItemForm(config: ItemFormConfig): HTMLElement {
  const { mode, prefill, encryptedNotes, userKey } = config;

  const nameInput = el("input", {
    type: "text",
    required: true,
    value: prefill?.name ?? "",
    placeholder: "e.g. GitHub",
  });
  const usernameInput = el("input", {
    type: "text",
    value: prefill?.username ?? "",
    autocomplete: "off",
    placeholder: "username or email",
  });
  const uriInput = el("input", {
    type: "text",
    value: prefill?.uri ?? "",
    placeholder: "https://example.com",
  });
  const passwordInput = el("input", {
    type: "text",
    className: "mono",
    autocomplete: "off",
    placeholder:
      mode === "edit" ? "(leave blank to keep current password)" : "",
  });
  const notesInput = el("textarea", {
    rows: 3,
    placeholder:
      mode === "edit" && encryptedNotes
        ? "(leave blank to keep current notes)"
        : "notes, recovery codes, etc.",
  }) as HTMLTextAreaElement;

  const notesUnlockBtn = el("button", {
    type: "button",
    textContent: "Confirm to edit existing notes",
    className: "notes-unlock",
  });
  const notesStatus = el("span", { className: "error" });

  if (mode === "edit" && encryptedNotes) {
    notesInput.disabled = true;
    notesUnlockBtn.addEventListener("click", async () => {
      notesUnlockBtn.disabled = true;
      const gate = await requireBiometricConfirmation("Confirm to edit existing notes");
      if (gate !== "ok") {
        notesStatus.textContent =
          gate === "unavailable"
            ? "Biometric confirmation unavailable on this device."
            : "Confirmation failed.";
        notesUnlockBtn.disabled = false;
        return;
      }
      notesInput.value = await decryptToString(userKey, encryptedNotes);
      notesInput.disabled = false;
      notesUnlockBtn.remove();
      notesStatus.textContent = "";
    });
  } else {
    notesUnlockBtn.hidden = true;
  }

  const errorBox = el("div", { className: "error" });
  const submitBtn = el("button", {
    type: "submit",
    textContent: mode === "create" ? "Save new item" : "Save changes",
  });
  const cancelBtn = el("button", { type: "button", textContent: "Cancel" });
  cancelBtn.addEventListener("click", () => config.onCancel());

  const form = el("form", { className: "item-form" }, [
    el("label", {}, ["Name", nameInput]),
    el("label", {}, ["Username", usernameInput]),
    el("label", {}, ["URL", uriInput]),
    el("label", {}, [
      "Password",
      passwordInput,
      buildGeneratorPanel(passwordInput as HTMLInputElement),
    ]),
    el("label", {}, [
      "Notes",
      notesUnlockBtn,
      notesStatus,
      notesInput,
    ]),
    el("div", { className: "form-actions" }, [submitBtn, cancelBtn]),
    errorBox,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submitBtn.disabled = true;
    errorBox.textContent = "Saving…";
    try {
      await config.onSubmit({
        name: nameInput.value,
        username: usernameInput.value,
        password: passwordInput.value,
        uri: uriInput.value,
        notes: notesInput.disabled ? "" : notesInput.value,
      });
    } catch (err) {
      errorBox.textContent = (err as Error).message;
      submitBtn.disabled = false;
    }
  });

  return form;
}
