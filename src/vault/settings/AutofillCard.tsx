/**
 * Settings → Autofill. Three things only: the master switch, the per-app rule
 * table and an honest statement of what the picker refuses to do.
 *
 * The table lists rules the user created, not every process on the machine:
 * an application without a row is `ask`, and pretending to know about every
 * executable would be a lie about what was inspected.
 */
import { useCallback, useEffect, useState } from "react";
import { AppWindow, CircleAlert, Trash2 } from "lucide-react";
import { errorText } from "../../api";
import {
  autofill,
  type AutofillMode,
  type AutofillRule,
  type AutofillStatus,
} from "../../lib/api-autofill";
import { Button } from "../../ui/Button";
import { useSettingsStatus } from "../../lib/settings-status";
import Select from "../../ui/Select";
import { Switch } from "../../ui/Switch";
import { ChordInput } from "../../ui/ChordInput";
import "../../styles/autofill.css";

const MODES: { value: AutofillMode; label: string }[] = [
  { value: "fill", label: "Offer on focus" },
  { value: "ask", label: "Ask (shortcut)" },
  { value: "off", label: "Never" },
];

export default function AutofillCard() {
  const [status, setStatus] = useState<AutofillStatus | null>(null);
  const [rules, setRules] = useState<AutofillRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [exe, setExe] = useState("");
  const [mode, setMode] = useState<AutofillMode>("ask");

  const load = useCallback(async () => {
    try {
      const [nextStatus, nextRules] = await Promise.all([
        autofill.status(),
        autofill.rules(),
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
  }, [load]);

  const run = useCallback(
    async (work: () => Promise<AutofillRule[] | AutofillStatus>) => {
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

  const enabled = status?.enabled ?? false;
  useSettingsStatus(
    "autofill",
    status
      ? { tone: enabled ? "on" : "off", label: enabled ? "On" : "Off" }
      : null,
  );

  return (
    <section className="card" aria-labelledby="autofill-title">
      <div className="card-head">
        <h2 className="card-title" id="autofill-title">
          <AppWindow size={15} aria-hidden /> Autofill in Windows apps
        </h2>
        {status ? (
          <Switch
            checked={enabled}
            label="Enable the autofill picker"
            disabled={busy}
            onCheckedChange={(checked) => {
              void run(() => autofill.setEnabled(checked));
            }}
          />
        ) : null}
      </div>

      <p className="card-copy">
        The picker watches which field has focus with UI Automation and offers a
        small window anchored to it. Nothing is written until you press{" "}
        <strong>Fill</strong>: the rule decides whether the offer appears on
        focus or only when you ask.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>Picker</span>
          <span className="setting-hint">
            {enabled
              ? "Observing focus. Filling stays explicit for every application."
              : "Off: no focus observation and no shortcut offers."}
          </span>
        </div>
        <span className="setting-value">
          {enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Offer shortcut</span>
          <span className="setting-hint">
            {status?.registered
              ? "This chord offers the picker for the focused field, whatever the app's rule is — except \"Never\"."
              : "The system chord is taken by another application, so focus offers are the only way in."}
          </span>
        </div>
        <span className="setting-value">
          <ChordInput
            value={status?.shortcut ?? "Ctrl+Shift+F"}
            label="Offer shortcut"
            disabled={busy || !enabled}
            onChange={(chord) => {
              void (async () => {
                setBusy(true);
                try {
                  setStatus(await autofill.setShortcut(chord));
                } catch (failure) {
                  setError(errorText(failure));
                } finally {
                  setBusy(false);
                }
              })();
            }}
          />
        </span>
      </div>

      {status?.error ? (
        <p className="setting-hint" role="status">
          {status.error}
        </p>
      ) : null}

      <div className="autofill-rules" role="table" aria-label="Application rules">
        <div className="autofill-rule autofill-rule-head" role="row">
          <span role="columnheader">Application</span>
          <span role="columnheader">When to offer</span>
          <span role="columnheader" aria-label="Actions" />
        </div>
        {rules.length === 0 ? (
          <div className="autofill-empty">
            No application has a rule yet. Everything is <code>ask</code>: the
            shortcut offers, focusing a field does not.
          </div>
        ) : (
          rules.map((rule) => (
            <div className="autofill-rule" role="row" key={rule.exe}>
              <span className="autofill-exe" role="cell" title={rule.exe}>
                {rule.exe}
              </span>
              <div className="select-shell">
                <Select
                  label={`Rule for ${rule.exe}`}
                  value={rule.mode}
                  disabled={busy}
                  options={MODES.map((entry) => ({
                    value: entry.value,
                    label: entry.label,
                  }))}
                  onChange={(next) => {
                    void run(() => autofill.setRule(rule.exe, next as AutofillMode));
                  }}
                />
              </div>
              <Button
                variant="quiet"
                size="sm"
                iconOnly
                label={`Delete the rule for ${rule.exe}`}
                disabled={busy}
                onClick={() => {
                  void run(() => autofill.resetRule(rule.exe));
                }}
              >
                <Trash2 size={13} aria-hidden />
              </Button>
            </div>
          ))
        )}
      </div>

      <form
        className="autofill-add"
        onSubmit={(event) => {
          event.preventDefault();
          const name = exe.trim();
          if (!name) return;
          void (async () => {
            if (await run(() => autofill.setRule(name, mode))) setExe("");
          })();
        }}
      >
        <div className="input-shell">
          <input
            className="input"
            type="text"
            value={exe}
            placeholder="notepad.exe"
            aria-label="Executable name"
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => setExe(event.target.value)}
          />
        </div>
        <div className="select-shell">
          <Select
            label="Default rule for this application"
            value={mode}
            options={MODES.map((entry) => ({
              value: entry.value,
              label: entry.label,
            }))}
            onChange={(value) => setMode(value as AutofillMode)}
          />
        </div>
        <Button type="submit" variant="secondary" size="sm" disabled={busy || !exe.trim()}>
          Add rule
        </Button>
      </form>

      <p className="setting-hint">
        Rules are keyed by the executable&apos;s file name in lower case
        (<code>notepad.exe</code>). &ldquo;Ask (shortcut)&rdquo; is the default
        for every application that has no row.
      </p>

      <div className="autofill-honesty">
        <p>
          <strong>Elevated windows are refused.</strong> Kestrel is an unsigned
          build, so it will not write into a window whose process runs at a
          higher integrity level than Kestrel itself — an app started as
          administrator, or the secure desktop behind a UAC prompt. The overlay
          says so and offers no rows; copy the item and paste it instead.
        </p>
        <p>
          Filling uses the Windows UI Automation value pattern. When a field
          does not expose one, Kestrel does not fall back to typing: there is no
          synthetic keystroke path into another process.
        </p>
      </div>

      {error ? (
        <p className="setting-hint" role="alert">
          <CircleAlert size={12} aria-hidden /> {error}
        </p>
      ) : null}
    </section>
  );
}
