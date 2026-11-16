/**
 * Kestrel bridge service worker.
 *
 * It owns the one native messaging port and serializes requests: the host
 * answers one frame at a time, so a second `postMessage` before the first
 * answer would give the wrong response to the wrong caller.
 *
 * The token is not here. `kestrel-nmhost.exe` reads it from the user-only
 * `bridge.token` file and overwrites any token the extension sends, so this
 * worker cannot mint, choose or leak a scope.
 */

const HOST = "com.kestrel.bridge";
const TIMEOUT_MS = 15000;

/** @type {chrome.runtime.Port | null} */
let port = null;
/** Serializes exchanges; no two messages are in flight at once. */
let chain = Promise.resolve();

function ensurePort() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST);
  port.onDisconnect.addListener(() => {
    // Exchange listeners reject their own promise; this only makes the next
    // request connect a fresh port. `lastError` must be read here to clear it.
    void chrome.runtime.lastError;
    port = null;
  });
  return port;
}

/**
 * One request → one response. Rejects on disconnect or timeout, never resolves
 * with a guess.
 * @param {Record<string, unknown>} message
 * @returns {Promise<any>}
 */
function exchange(message) {
  return new Promise((resolve, reject) => {
    let current;
    try {
      current = ensurePort();
    } catch (error) {
      reject(new Error(String(error)));
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("Kestrel did not answer in time"));
    }, TIMEOUT_MS);

    const onMessage = (response) => {
      cleanup();
      resolve(response);
    };
    const onDisconnect = () => {
      cleanup();
      // The listener installed by `ensurePort` also fires; both are idempotent.
      reject(new Error(chrome.runtime.lastError?.message ?? "native host disconnected"));
      port = null;
    };
    function cleanup() {
      clearTimeout(timer);
      current.onMessage.removeListener(onMessage);
      current.onDisconnect.removeListener(onDisconnect);
    }

    current.onMessage.addListener(onMessage);
    current.onDisconnect.addListener(onDisconnect);
    try {
      current.postMessage(message);
    } catch (error) {
      cleanup();
      reject(new Error(String(error)));
    }
  });
}

/**
 * Queue a request behind any in-flight one.
 * @param {string} op
 * @param {Record<string, unknown>} payload
 */
function request(op, payload) {
  const run = chain.then(() => exchange({ op, ...payload }));
  // A rejected request must not poison the queue for the next one.
  chain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

function isOrigin(value) {
  return typeof value === "string" && /^https?:\/\//i.test(value) && value.length <= 2048;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return false;

  if (message.type === "kestrel.items") {
    if (!isOrigin(message.origin)) {
      sendResponse({ ok: false, error: "bad_request", message: "invalid origin" });
      return false;
    }
    request("browser.items", { origin: message.origin }).then(sendResponse, (error) =>
      sendResponse({ ok: false, error: "internal", message: String(error?.message ?? error) }),
    );
    return true;
  }

  if (message.type === "kestrel.reveal") {
    if (
      !isOrigin(message.origin) ||
      typeof message.id !== "string" ||
      typeof message.field !== "string"
    ) {
      sendResponse({ ok: false, error: "bad_request", message: "invalid reveal request" });
      return false;
    }
    request("browser.reveal", {
      origin: message.origin,
      id: message.id,
      field: message.field,
    }).then(sendResponse, (error) =>
      sendResponse({ ok: false, error: "internal", message: String(error?.message ?? error) }),
    );
    return true;
  }

  if (message.type === "kestrel.focus") {
    // `browser.focus` reads nothing; it is the locked chip's only action.
    request("browser.focus", {}).then(sendResponse, (error) =>
      sendResponse({ ok: false, error: "internal", message: String(error?.message ?? error) }),
    );
    return true;
  }

  return false;
});
