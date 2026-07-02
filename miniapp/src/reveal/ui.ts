/**
 * Reveal UI — wires the biometry gate + reveal engine + clipboard module into
 * a press-and-hold button and a copy button for a single vault item field.
 *
 * BRIEF §7.6: autofill takes priority over showing/copying wherever a value
 * can be handed to a field directly. A Telegram Mini App has no OS-level
 * autofill hook into other apps, so that priority applies within our own
 * create/edit forms (M3); here, on the read-only list, copy-to-clipboard
 * (with auto-clear) is the closest equivalent and is offered alongside the
 * visual reveal rather than instead of it.
 */
import { decryptToString, type SymmetricKey } from "../crypto/encstring";
import { requireBiometricConfirmation } from "./biometry";
import { copyWithAutoClear } from "./clipboard";
import {
  HOLD_MODE,
  REVEAL_TIMEOUT_MS,
  TIMER_MODE,
  revealInto,
  type RevealHandle,
} from "./engine";

const POINTER_SUPPORTED = typeof window !== "undefined" && "onpointerdown" in window;

function deniedMessage(reason: "denied" | "unavailable"): string {
  return reason === "unavailable"
    ? "Biometric confirmation is not available on this device — the official Bitwarden app remains available as a fallback."
    : "Confirmation was not successful. Try again.";
}

/**
 * Build a `<span>` placeholder + `<button>` pair for revealing `encrypted`.
 * Returns the wrapping element to insert into the list item.
 */
export function buildRevealField(
  encrypted: string,
  userKey: SymmetricKey,
): HTMLElement {
  const wrapper = document.createElement("span");
  wrapper.className = "reveal-field";

  const placeholder = document.createElement("span");
  placeholder.className = "reveal-placeholder";
  placeholder.textContent = "••••••••";

  const status = document.createElement("span");
  status.className = "reveal-status muted";

  const holdBtn = document.createElement("button");
  holdBtn.type = "button";
  holdBtn.className = "reveal-hold";
  holdBtn.textContent = "Hold to reveal";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "reveal-copy";
  copyBtn.textContent = "Copy";

  let activeHandle: RevealHandle | null = null;
  let revealNode: HTMLElement | null = null;

  const teardownVisual = () => {
    activeHandle?.stop();
    activeHandle = null;
    revealNode = null;
    placeholder.hidden = false;
  };

  async function startHoldReveal(): Promise<void> {
    if (activeHandle?.active) return;
    status.textContent = "Confirm…";

    const node = document.createElement("span");
    node.className = "reveal-value";
    placeholder.hidden = true;
    placeholder.after(node);
    revealNode = node;

    const mode = POINTER_SUPPORTED ? HOLD_MODE : TIMER_MODE;
    const handle = await revealInto(node, encrypted, userKey, {
      mode,
      onTick: (remaining) => {
        status.textContent = `${Math.ceil(remaining / 1000)}s`;
      },
      onEnd: () => {
        status.textContent = "";
        teardownVisual();
      },
      onDenied: (reason) => {
        status.textContent = deniedMessage(reason);
        node.remove();
        placeholder.hidden = false;
        revealNode = null;
      },
    });
    activeHandle = handle;
    if (!handle.active) {
      // Denied — onDenied already handled UI; nothing left in the DOM.
      return;
    }
    status.textContent = mode === HOLD_MODE ? "Release to hide" : "";
  }

  function stopHoldReveal(): void {
    if (revealNode) {
      // stop() blanks + removes the node; onEnd runs teardownVisual().
      activeHandle?.stop();
    }
  }

  if (POINTER_SUPPORTED) {
    holdBtn.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      void startHoldReveal();
    });
    ["pointerup", "pointerleave", "pointercancel"].forEach((evt) =>
      holdBtn.addEventListener(evt, stopHoldReveal),
    );
  } else {
    // No pointer events: tap starts a 20s auto-hiding timer instead.
    holdBtn.addEventListener("click", () => void startHoldReveal());
  }
  window.addEventListener("blur", stopHoldReveal);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopHoldReveal();
  });

  copyBtn.addEventListener("click", async () => {
    status.textContent = "Confirm…";
    const gate = await requireBiometricConfirmation("Confirm to copy this secret");
    if (gate !== "ok") {
      status.textContent = deniedMessage(gate === "unavailable" ? "unavailable" : "denied");
      return;
    }
    const plain = await decryptToString(userKey, encrypted);
    await copyWithAutoClear(plain, REVEAL_TIMEOUT_MS);
    status.textContent = `Copied — clearing in ${REVEAL_TIMEOUT_MS / 1000}s`;
    setTimeout(() => {
      if (status.textContent?.startsWith("Copied")) status.textContent = "";
    }, REVEAL_TIMEOUT_MS);
  });

  wrapper.append(placeholder, holdBtn, copyBtn, status);
  return wrapper;
}
