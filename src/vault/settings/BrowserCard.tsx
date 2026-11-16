/**
 * Settings → Browser. Three controls and one honest warning:
 *
 * 1. install/uninstall the per-user native messaging host (HKCU, reversible);
 * 2. show the extension id the manifest allows and where to load it from;
 * 3. edit the per-origin rule table (`fill` / `ask` / `off`, missing = `ask`).
 *
 * The note about `bridge.token` is not decoration. The browser-started host has
 * to read a token from disk, so the file is a secret at rest. It is protected
 * by a DACL for the current Windows user only; it grants only what the origin
 * rules allow; and every browser op answers `locked` while the vault is locked.
 */
import { useCallback, useEffect, useState } from "react";
import { Globe, Trash2 } from "lucide-react";
import { errorText } from "../../api";
import {
  browser,
  type BrowserMode,
  type BrowserRule,
  type BrowserStatus,
} from "../../lib/api-browser";
import type { VaultState } from "../../types";
import { Button } from "../../ui/Button";
import { useSettingsStatus } from "../../lib/settings-status";
import Select from "../../ui/Select";
import "../../styles/browser.css";

/** The browsers the registry actually points at, in a fixed order. */
function registeredNames(status: BrowserStatus | null): string {
  if (!status) return "";
  const names = [
    status.chromeRegistered ? "Chrome" : null,
    status.edgeRegistered ? "Edge" : null,
    status.firefoxRegistered ? "Firefox" : null,
  ].filter((name): name is string => name !== null);
  if (names.length === 0) return "";
  return names.length > 1
    ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
    : names[0];
}

const MODES: { value: BrowserMode; label: string }[] = [
  { value: "fill", label: "Fill after click" },
  { value: "ask", label: "Ask (no value)" },
  { value: "off", label: "Off (no chip)" },
];

const MODE_HINT: Record<BrowserMode, string> = {
  fill: "The chip may release the value after you press Fill in the page.",
  ask: "The chip appears, but Kestrel refuses to release a value. Set the site to Fill to fill.",
  off: "No chip and no reveal on this origin.",
};

export default function BrowserCard({ state }: { state: VaultState }) {
  const [status, setStatus] = useState<BrowserStatus | null>(null);
  const [rules, setRules] = useState<BrowserRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [origin, setOrigin] = useState("");
  const [mode, setMode] = useState<BrowserMode>("fill");

  const load = useCallback(async () => {
    try {
      const [nextStatus, nextRules] = await Promise.all([
        browser.status(),
        browser.rules(),
      ]);
      setStatus(nextStatus);
      setRules(nextRules);
      setError(null);
    } catch (failure) {
      setError(errorText(failure));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, state.locked, state.vaultUuid]);

  const run = useCallback(
    async (work: () => Promise<BrowserStatus | BrowserRule[]>) => {
      setBusy(true);
      setError(null);
      try {
        const result = await work();
        if (Array.isArray(result)) setRules(result);
        else setStatus(result);
        return true;
      } catch (failure) {
        setError(errorText(failure));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  const installed = status?.installed ?? false;
  const browserCount =
    (status?.chromeRegistered ? 1 : 0) +
    (status?.edgeRegistered ? 1 : 0) +
    (status?.firefoxRegistered ? 1 : 0);
  useSettingsStatus(
    "browser",
    status
      ? {
          tone: browserCount > 0 ? "on" : "off",
          label: !installed
            ? "Bridge not installed"
            : browserCount === 0
              ? "No browser connected"
              : `${browserCount} browser${browserCount === 1 ? "" : "s"}`,
        }
      : null,
  );
  const endState = error
    ? "Unavailable"
    : !status
      ? "Checking…"
      : installed
        ? "Installed"
        : browserCount > 0
          ? "Needs attention"
          : "Not installed";

  return (
    <section className="card" aria-labelledby="browser-title">
      <div className="card-head">
        <h2 className="card-title" id="browser-title">
          <Globe size={15} aria-hidden /> Browser
        </h2>
        <span
          className={`browser-state ${installed ? "is-on" : "is-off"}`}
          aria-live="polite"
        >
          {endState}
        </span>
      </div>

      <p className="card-copy">
        The extension shows a small chip on a login form. It fills nothing until
        you open the chip and press Fill, and it never decides a policy: the
        app answers only what the origin rules below allow.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>Native host</span>
          <span className="setting-hint">
            {status?.installed
              ? `Registered for ${registeredNames(status) || "no browser"}. The host only forwards JSON to the SDK pipe.`
              : "Not registered. Installing writes one HKCU value each for Chrome, Edge and Firefox; uninstall removes all three."}
          </span>
        </div>
        <div className="browser-actions">
          <Button
            variant={installed ? "secondary" : "primary"}
            size="sm"
            disabled={busy || state.locked}
            onClick={() => {
              void run(() => browser.install());
            }}
          >
            {busy ? "Working…" : installed ? "Reinstall" : "Install"}
          </Button>
          <Button
            variant="quiet"
            size="sm"
            disabled={busy || !installed}
            onClick={() => {
              void run(() => browser.uninstall());
            }}
          >
            Uninstall
          </Button>
        </div>
      </div>

      {state.locked ? (
        <p className="setting-hint">
          Unlock the vault to install the bridge. The token is minted inside an
          unlocked session on purpose: a token created while locked would only
          ever answer <code>locked</code>.
        </p>
      ) : null}

      <div className="setting-row">
        <div className="setting-label">
          <span>Extension id</span>
          <span className="setting-hint">
            Load <code>extension/</code> as an unpacked extension. Its{" "}
            <code>key</code> fixes this id, so the host manifest can name it
            before the extension is installed.
          </span>
        </div>
        <span className="setting-value browser-mono">
          {status?.extensionId ?? "—"}
        </span>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Host manifest</span>
          <span className="setting-hint browser-mono">
            {status?.manifestPath || "—"}
          </span>
        </div>
        <span className="setting-value">
          {status?.hostBinaryPresent ? "Binary found" : "Binary missing"}
        </span>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Token file</span>
          <span className="setting-hint browser-mono">
            {status?.tokenPath || "—"}
          </span>
        </div>
        <span className="setting-value">
          {status?.tokenPresent ? "Present" : "Missing"}
        </span>
      </div>

      <div className="browser-rules" role="table" aria-label="Origin rules">
        <div className="browser-rule browser-rule-head" role="row">
          <span role="columnheader">Origin</span>
          <span role="columnheader">Rule</span>
          <span role="columnheader" aria-label="Actions" />
        </div>
        {rules.length === 0 ? (
          <div className="browser-empty">
            No origin has a rule yet. Every site is <code>ask</code>: the chip
            may appear, but no value is released until you add the origin as{" "}
            <code>fill</code>.
          </div>
        ) : (
          rules.map((rule) => (
            <div className="browser-rule" role="row" key={rule.origin}>
              <span className="browser-origin" role="cell" title={rule.origin}>
                {rule.origin}
              </span>
              <div className="select-shell">
                <Select
                  label={`Rule for ${rule.origin}`}
                  value={rule.mode}
                  disabled={busy}
                  options={MODES.map((entry) => ({
                    value: entry.value,
                    label: entry.label,
                  }))}
                  onChange={(next) => {
                    void run(() => browser.setRule(rule.origin, next as BrowserMode));
                  }}
                />
              </div>
              <Button
                variant="quiet"
                size="sm"
                iconOnly
                label={`Delete the rule for ${rule.origin}`}
                disabled={busy}
                onClick={() => {
                  void run(() => browser.resetRule(rule.origin));
                }}
              >
                <Trash2 size={13} aria-hidden />
              </Button>
            </div>
          ))
        )}
      </div>

      <form
        className="browser-add"
        onSubmit={(event) => {
          event.preventDefault();
          const value = origin.trim();
          if (!value) return;
          void (async () => {
            if (await run(() => browser.setRule(value, mode))) setOrigin("");
          })();
        }}
      >
        <div className="input-shell">
          <input
            className="input"
            type="text"
            value={origin}
            placeholder="https://example.com"
            aria-label="Origin"
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => setOrigin(event.target.value)}
          />
        </div>
        <div className="select-shell">
          <Select
            label="Rule for this origin"
            value={mode}
            options={MODES.map((entry) => ({
              value: entry.value,
              label: entry.label,
            }))}
            onChange={(value) => setMode(value as BrowserMode)}
          />
        </div>
        <Button
          type="submit"
          variant="secondary"
          size="sm"
          disabled={busy || !origin.trim()}
        >
          Add rule
        </Button>
      </form>

      <p className="setting-hint">
        <code>fill</code> is the only mode that releases a value.{" "}
        {MODE_HINT.fill} <code>ask</code> is the default for a missing row;{" "}
        {MODE_HINT.ask.toLowerCase()} <code>off</code> removes the chip and
        refuses reveal.
      </p>

      <div className="browser-honesty">
        <p>
          <strong>The token file is a secret at rest.</strong> The browser
          starts the host itself, so it cannot receive a token from this window:
          Kestrel writes the one Browser token to <code>bridge.token</code> next
          to the vault, with a DACL for your Windows account only. It grants
          only the browser ops: metadata and a reveal, the latter only for
          origins set to <code>fill</code>. While the vault is locked every
          browser op answers <code>locked</code>, so the file on its own
          reveals nothing. Uninstall deletes it.
        </p>
        <p>
          The extension never stores a value: it asks for it at the moment you
          press Fill, writes the fields, and drops it. There is no{" "}
          <code>chrome.storage</code> and no log.
        </p>
      </div>

      {error ? (
        <p className="browser-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
