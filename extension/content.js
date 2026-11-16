/**
 * Kestrel bridge content script.
 *
 * On a page with a visible password field it asks the service worker for the
 * items Kestrel has saved on this origin and shows one small chip. Clicking the
 * chip opens a confirmation in the page that names the item and the origin; a
 * second click on "Fill" is the only thing that asks for values. The values
 * live in this closure for the duration of one fill, are written through the
 * native input setter, and are then dropped. Nothing is written to
 * `chrome.storage`, `localStorage`, the DOM as a value, or a log.
 *
 * The extension never sees a token and never decides a policy: the host reads
 * the user-only token file and the app answers only `browser.*` for its scope.
 */
(() => {
  "use strict";

  if (window.top !== window) return;

  const ROOT_ID = "kestrel-bridge-root";
  const CHIP_LIMIT = 2048;

  let host = null;
  let shadow = null;
  let lastKey = "";
  /** A key whose chip the person closed, or where there is nothing to show. */
  let suppressedKey = "";
  let scanTimer = 0;
  const elementIds = new WeakMap();
  let nextElementId = 1;

  function elementId(element) {
    let id = elementIds.get(element);
    if (!id) {
      id = nextElementId++;
      elementIds.set(element, id);
    }
    return id;
  }

  function isVisible(element) {
    if (!element || !element.isConnected) return false;
    if (element.disabled || element.readOnly) return false;
    const rect = element.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 8) return false;
    const style = window.getComputedStyle(element);
    return style.visibility !== "hidden" && style.display !== "none";
  }

  function visiblePasswords() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(isVisible);
  }

  /** The first visible password field, preferring one inside a form. */
  function findPassword() {
    const fields = visiblePasswords();
    return fields.find((field) => field.form) ?? fields[0] ?? null;
  }

  function findUsername(password) {
    if (!password) return null;
    const scope = password.form ?? document;
    const candidates = Array.from(
      scope.querySelectorAll(
        'input[type="text"], input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i]',
      ),
    ).filter((input) => isVisible(input) && input !== password);
    // The closest preceding field in document order is the usual layout.
    const all = Array.from(document.querySelectorAll("input"));
    const passwordOrder = all.indexOf(password);
    let best = null;
    let bestOrder = -1;
    for (const input of candidates) {
      const order = all.indexOf(input);
      if (order >= 0 && order < passwordOrder && order > bestOrder) {
        best = input;
        bestOrder = order;
      }
    }
    return best ?? candidates[0] ?? null;
  }

  function send(type, payload) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type, ...payload }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({
              ok: false,
              error: "extension",
              message: chrome.runtime.lastError.message,
            });
            return;
          }
          resolve(response ?? { ok: false, error: "extension", message: "no response" });
        });
      } catch (error) {
        resolve({ ok: false, error: "extension", message: String(error) });
      }
    });
  }

  /* ------------------------------------------------------------------- UI */

  function destroy() {
    if (host) host.remove();
    host = null;
    shadow = null;
    lastKey = "";
  }

  /** Close the card for this form without the interval reopening it. */
  function dismiss() {
    suppressedKey = lastKey;
    destroy();
  }

  function ensureHost() {
    if (host) return;
    host = document.createElement("div");
    host.id = ROOT_ID;
    host.style.all = "initial";
    host.style.position = "absolute";
    host.style.zIndex = "2147483647";
    host.style.width = "0";
    host.style.height = "0";
    shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .kestrel { position: absolute; left: 0; top: 0; font: 400 12px/1.45 "Segoe UI", system-ui, sans-serif;
        color: #12151a; background: #ffffff; border: 1px solid #cdcdcd; border-radius: 8px;
        box-shadow: 0 12px 32px rgb(16 20 26 / .18); min-width: 220px; max-width: 340px;
        overflow: hidden; }
      .chip { display: flex; align-items: center; gap: 8px; padding: 7px 10px; cursor: pointer;
        border: 0; background: transparent; color: inherit; font: inherit; width: 100%; text-align: left; }
      .chip:hover { background: #eeeeee; }
      .k { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px;
        border-radius: 4px; background: #12151a; color: #ffffff; font: 600 10px/1 "Segoe UI", sans-serif; }
      .title { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .domain { color: #5d6673; font-size: 11px; margin-left: auto; white-space: nowrap; }
      .panel { padding: 10px; }
      .head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px; }
      .head strong { font-size: 13px; }
      .head span { color: #5d6673; font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
      .row { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-top: 1px solid #eee; }
      .row:first-of-type { border-top: 0; }
      .row-title { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .row-meta { color: #5d6673; font-size: 11px; margin-left: auto; }
      button { font: inherit; cursor: pointer; border-radius: 6px; border: 1px solid #cdcdcd;
        background: #ffffff; color: #12151a; padding: 4px 10px; }
      button:hover { background: #eee; }
      button.primary { background: #12151a; border-color: #12151a; color: #ffffff; }
      button.primary:hover { background: #2a2f38; }
      button:disabled { opacity: .55; cursor: default; }
      .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 10px; }
      .note { color: #5d6673; margin: 4px 0 8px; font-size: 11px; }
      .error { color: #b42318; margin: 6px 0 0; font-size: 11px; }
      .ok { color: #067647; margin: 6px 0 0; font-size: 11px; }
    `;
    shadow.append(style);
    document.documentElement.append(host);
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function place(password) {
    if (!host) return;
    const rect = password.getBoundingClientRect();
    const top = rect.bottom + window.scrollY + 6;
    const left = Math.min(
      Math.max(rect.left + window.scrollX, 4),
      window.scrollX + document.documentElement.clientWidth - 240,
    );
    host.style.top = `${Math.round(top)}px`;
    host.style.left = `${Math.round(left)}px`;
  }

  function renderChip(password, itemCount, itemTitle) {
    ensureHost();
    shadow.querySelectorAll(".kestrel").forEach((element) => element.remove());
    const card = node("div", "kestrel");
    const chip = node("button", "chip");
    chip.type = "button";
    chip.setAttribute("aria-label", "Kestrel logins for this site");
    chip.append(node("span", "k", "K"));
    chip.append(node("span", "title", itemTitle || "Kestrel"));
    chip.append(
      node(
        "span",
        "domain",
        itemCount > 1 ? `${itemCount} logins · ${location.hostname}` : location.hostname,
      ),
    );
    chip.addEventListener("click", () => {
      // The chip only opens the confirmation; it never asks for a value.
      openPanel(password);
    });
    card.append(chip);
    shadow.append(card);
    place(password);
  }

  function renderMessage(password, title, message, options = {}) {
    ensureHost();
    shadow.querySelectorAll(".kestrel").forEach((element) => element.remove());
    const card = node("div", "kestrel");
    const panel = node("div", "panel");
    const head = node("div", "head");
    head.append(node("strong", "", title));
    head.append(node("span", "", location.hostname));
    panel.append(head);
    panel.append(node("p", "note", message));

    if (Array.isArray(options.items) && options.items.length > 0) {
      for (const item of options.items) {
        const row = node("div", "row");
        row.append(node("span", "row-title", item.title));
        row.append(node("span", "row-meta", item.category || "login"));
        panel.append(row);
      }
    }

    const actions = node("div", "actions");
    if (options.actionLabel) {
      const action = node("button", "primary", options.actionLabel);
      action.type = "button";
      action.addEventListener("click", () => {
        action.disabled = true;
        Promise.resolve(options.action?.()).finally(() => {
          action.disabled = false;
        });
      });
      actions.append(action);
    }
    const close = node("button", "", "Close");
    close.type = "button";
    close.addEventListener("click", dismiss);
    actions.append(close);
    panel.append(actions);
    card.append(panel);
    shadow.append(card);
    place(password);
    return { panel, actions };
  }

  function openPanel(password) {
    const state = currentState;
    if (!state) return;
    if (state.mode === "ask") {
      renderMessage(
        password,
        "Kestrel",
        `This site is set to Ask in Kestrel. No value is released until you change ${
          location.hostname
        } to Fill in Kestrel → Settings → Browser.`,
        { actionLabel: "Open Kestrel", action: focusKestrel },
      );
      return;
    }
    if (state.mode === "off" || state.items.length === 0) return;

    ensureHost();
    shadow.querySelectorAll(".kestrel").forEach((element) => element.remove());
    const card = node("div", "kestrel");
    const panel = node("div", "panel");
    const head = node("div", "head");
    head.append(node("strong", "", "Fill from Kestrel"));
    head.append(node("span", "", location.origin));
    panel.append(head);
    panel.append(
      node("p", "note", "Choose the item. Kestrel releases the value only after you press Fill."),
    );

    const rows = node("div", "");
    let selected = state.items[0];
    const rowButtons = [];
    for (const item of state.items) {
      const row = node("div", "row");
      const choose = node("button", "", item.title);
      choose.type = "button";
      choose.setAttribute("aria-pressed", String(item === selected));
      choose.addEventListener("click", () => {
        selected = item;
        for (const button of rowButtons) {
          button.setAttribute("aria-pressed", String(button === choose));
        }
      });
      rowButtons.push(choose);
      row.append(choose);
      row.append(node("span", "row-meta", item.category || "login"));
      rows.append(row);
    }
    panel.append(rows);

    const actions = node("div", "actions");
    const fill = node("button", "primary", "Fill");
    fill.type = "button";
    fill.addEventListener("click", async () => {
      fill.disabled = true;
      const result = await fillItem(password, selected);
      if (result.ok) {
        renderMessage(password, "Filled", result.message, {});
      } else {
        const { panel: messagePanel } = renderMessage(
          password,
          "Not filled",
          result.message,
          { actionLabel: result.focus ? "Open Kestrel" : undefined, action: focusKestrel },
        );
        messagePanel.querySelector(".note")?.classList.add("error");
      }
    });
    const cancel = node("button", "", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", dismiss);
    actions.append(fill, cancel);
    panel.append(actions);
    card.append(panel);
    shadow.append(card);
    place(password);
  }

  async function focusKestrel() {
    await send("kestrel.focus", {});
  }

  /* ------------------------------------------------------------------ fill */

  let currentState = null;

  function setInputValue(input, value) {
    const descriptor = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    );
    if (!descriptor || typeof descriptor.set !== "function") return false;
    descriptor.set.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  function fieldFor(item, kind) {
    const fields = Array.isArray(item.fields) ? item.fields : [];
    return fields.find((field) => field.kind === kind) ?? null;
  }

  async function fillItem(password, item) {
    const usernameField = fieldFor(item, "username") ?? fieldFor(item, "email");
    const passwordField = fieldFor(item, "password");
    if (!passwordField && !usernameField) {
      return { ok: false, message: "This item has no username or password field." };
    }
    if (!isVisible(password)) {
      return { ok: false, message: "The password field moved. Try again." };
    }
    const username = findUsername(password);

    // Ask for every value before writing anything: a partial fill is worse
    // than none, and the values are about to be dropped either way.
    const pending = [];
    for (const field of [usernameField, passwordField]) {
      if (!field) continue;
      const target = field.kind === "password" ? password : username;
      if (!target) continue;
      const response = await send("kestrel.reveal", {
        origin: location.origin,
        id: item.id,
        field: field.id,
      });
      if (!response || response.ok !== true || typeof response.value !== "string") {
        const code = response?.error;
        const message =
          code === "locked"
            ? "Kestrel is locked. Unlock it, then try again."
            : code === "not_granted"
              ? "Kestrel is set to Ask for this site. Change it to Fill in Settings → Browser."
              : response?.message || "Kestrel did not release the value.";
        return { ok: false, message, focus: code === "locked" || code === "not_granted" };
      }
      pending.push([target, response.value]);
    }
    if (pending.length === 0) {
      return { ok: false, message: "No matching input field is visible on this page." };
    }

    for (const [input, value] of pending) {
      setInputValue(input, value);
    }
    pending.length = 0;
    password.focus({ preventScroll: true });
    return { ok: true, message: `${item.title} filled.` };
  }

  /* ------------------------------------------------------------------ scan */

  async function scan(force = false) {
    const password = findPassword();
    if (!password) {
      suppressedKey = "";
      destroy();
      currentState = null;
      return;
    }
    const key = `${location.origin}#${elementId(password)}`;
    if (!force && key === suppressedKey) return;
    if (!force && key === lastKey && host) {
      place(password);
      return;
    }
    lastKey = key;

    const response = await send("kestrel.items", { origin: location.origin });
    if (key !== lastKey) return; // the page changed while we waited
    if (!response || response.ok !== true) {
      const locked = response?.error === "locked";
      const missing = response?.error === "unauthorized";
      const title = locked
        ? "Kestrel is locked"
        : missing
          ? "Kestrel bridge not installed"
          : "Kestrel is not running";
      const message = locked
        ? "Unlock Kestrel to use the logins saved for this site."
        : missing
          ? "Install the bridge in Kestrel → Settings → Browser, then reload this page."
          : response?.message || "The native host could not reach Kestrel.";
      renderMessage(password, title, message, {
        actionLabel: "Open Kestrel",
        action: focusKestrel,
      });
      currentState = null;
      return;
    }

    const items = Array.isArray(response.items)
      ? response.items.filter((item) => item && typeof item.id === "string")
      : [];
    const mode = response.mode === "fill" || response.mode === "off" ? response.mode : "ask";
    if (mode === "off" || items.length === 0) {
      // Nothing to show for this origin. Remember the form so the interval
      // does not ask the host again every 1.5 seconds.
      suppressedKey = key;
      destroy();
      currentState = null;
      return;
    }
    suppressedKey = "";
    currentState = { mode, items };
    renderChip(password, items.length, items[0]?.title);
  }

  function scheduleScan(delay = 400) {
    clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => {
      void scan();
    }, delay);
  }

  window.addEventListener("scroll", () => {
    const password = findPassword();
    if (password) place(password);
  }, { passive: true });
  window.addEventListener("resize", () => scheduleScan(250), { passive: true });
  window.addEventListener("popstate", () => {
    lastKey = "";
    suppressedKey = "";
    scheduleScan(250);
  });
  window.addEventListener("hashchange", () => {
    lastKey = "";
    suppressedKey = "";
    scheduleScan(250);
  });

  const observer = new MutationObserver(() => scheduleScan());
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // SPA routers that rewrite the form without a navigation still get caught by
  // the observer; the interval only guards pages that animate fields in late.
  window.setInterval(() => {
    const password = findPassword();
    if (!password) {
      if (host) destroy();
      suppressedKey = "";
      return;
    }
    if (!host && !(lastKey === suppressedKey)) scheduleScan(100);
    else place(password);
  }, 1500);

  scheduleScan(500);
})();
