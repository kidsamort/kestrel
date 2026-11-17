/**
 * Settings → Security. Both selects talk to the core on change and report the
 * interval the core actually accepted, never the one that was requested.
 */
import { useEffect, useState } from "react";
import { ClipboardCheck, Clock3, Lock, ScanFace, ShieldCheck } from "lucide-react";
import { api, errorText } from "../../api";
import { durationLabel } from "../../lib/format";
import type { HelloStatus, VaultState } from "../../types";
import { Button } from "../../ui/Button";
import { useSettingsStatus } from "../../lib/settings-status";
import Select from "../../ui/Select";
import { useNotify } from "../../ui/Toast";

const AUTOLOCK_CHOICES = [60, 300, 900, 1800, 3600, 28800];
const CLIPBOARD_CHOICES = [5, 15, 30, 60, 120];

/**
 * One honest sentence for the Hello row, in the order the states matter:
 * enrolled-but-broken, enrolled, unavailable, available.
 */
function helloHint(
  hello: HelloStatus | null,
  problem: string | null,
): string {
  if (hello === null) {
    return problem ?? "Checking whether this device can use Windows Hello…";
  }
  if (hello.enrolled && !hello.available) {
    return `Enrolled with ${hello.label} (${hello.mechanism}), but unavailable on this machine right now${hello.detail ? `: ${hello.detail}` : "."} Remove it to clean up.`;
  }
  if (hello.enrolled) {
    return `Enrolled: ${hello.label} (${hello.mechanism}). The vault key is wrapped by a TPM-backed CNG key that Windows releases only after a Hello check; no biometric data is ever stored, and the master password still opens the vault.`;
  }
  if (!hello.available) {
    return `Not available on this machine.${hello.detail ? ` ${hello.detail}` : ""}`;
  }
  return "Wrap the vault key behind the Windows Hello check you already use to sign in. The master password stays the fallback and is never replaced.";
}

export default function SecurityCard({
  state,
  onState,
  onLock,
}: {
  state: VaultState;
  onState: (state: VaultState) => void;
  onLock: () => void;
}) {
  const notify = useNotify();
  const [savingAutolock, setSavingAutolock] = useState(false);
  useSettingsStatus("security", {
    tone: "value",
    label: `Auto-lock ${durationLabel(state.autolockSeconds)
      .replace("minutes", "min")
      .replace("minute", "min")
      .replace("hours", "h")
      .replace("hour", "h")
      .replace("seconds", "s")}`,
  });
  const [savingClipboard, setSavingClipboard] = useState(false);
  const [hello, setHello] = useState<HelloStatus | null>(null);
  const [helloBusy, setHelloBusy] = useState(false);
  const [helloProblem, setHelloProblem] = useState<string | null>(null);

  // Enrolment state only — the core answers without a key. A failure must not
  // take the rest of the card down, so it is reported in place.
  useEffect(() => {
    let live = true;
    api
      .helloStatus()
      .then((status) => {
        if (!live) return;
        setHello(status);
        setHelloProblem(null);
      })
      .catch((failure) => {
        if (!live) return;
        setHello(null);
        setHelloProblem(errorText(failure));
      });
    return () => {
      live = false;
    };
  }, []);

  async function enableHello() {
    setHelloBusy(true);
    try {
      const next = await api.helloEnroll();
      setHello(next);
      notify("Windows Hello unlock is enabled", {
        detail: next.label || next.mechanism,
        tone: "success",
      });
    } catch (failure) {
      // Cancelling the prompt, a missing TPM and a policy refusal all arrive
      // here with the core's own wording.
      notify("Could not enable Windows Hello unlock", {
        detail: errorText(failure),
        tone: "danger",
      });
    } finally {
      setHelloBusy(false);
    }
  }

  async function disableHello() {
    setHelloBusy(true);
    try {
      const next = await api.helloDisable();
      setHello(next);
      notify("Windows Hello unlock removed", {
        detail: "The vault key is no longer wrapped on this device.",
        tone: "success",
      });
    } catch (failure) {
      notify("Could not remove Windows Hello unlock", {
        detail: errorText(failure),
        tone: "danger",
      });
    } finally {
      setHelloBusy(false);
    }
  }

  async function changeAutolock(seconds: number) {
    setSavingAutolock(true);
    try {
      const next = await api.setAutolock(seconds);
      onState(next);
      notify(`Locks after ${durationLabel(next.autolockSeconds)} idle`, {
        tone: "success",
      });
    } catch (error) {
      notify("Could not change auto-lock", {
        detail: errorText(error),
        tone: "danger",
      });
    } finally {
      setSavingAutolock(false);
    }
  }

  async function changeClipboard(seconds: number) {
    setSavingClipboard(true);
    try {
      const next = await api.setClipboardClear(seconds);
      onState(next);
      notify(
        next.clipboardClearSeconds > 0
          ? `Clipboard wipes after ${durationLabel(next.clipboardClearSeconds)}`
          : "The clipboard is wiped as soon as it is written",
        { tone: "success" },
      );
    } catch (error) {
      notify("Could not change the clipboard interval", {
        detail: errorText(error),
        tone: "danger",
      });
    } finally {
      setSavingClipboard(false);
    }
  }

  return (
    <section className="card" aria-labelledby="security-title">
      <div className="card-head">
        <h2 className="card-title" id="security-title">
          <ShieldCheck size={15} aria-hidden /> Security
        </h2>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Auto-lock</span>
          <span className="setting-hint">
            The watchdog runs in Rust; the renderer cannot postpone it.
          </span>
        </div>
        <div className="select-shell">
          <Clock3 size={14} aria-hidden className="select-icon" />
          <Select
            label="Auto-lock after inactivity"
            value={String(state.autolockSeconds)}
            disabled={savingAutolock}
            options={[
              // A value written by another build stays selectable instead of
              // being silently replaced by the first choice.
              ...(AUTOLOCK_CHOICES.includes(state.autolockSeconds)
                ? []
                : [
                    {
                      value: String(state.autolockSeconds),
                      label: durationLabel(state.autolockSeconds),
                    },
                  ]),
              ...AUTOLOCK_CHOICES.map((seconds) => ({
                value: String(seconds),
                label: durationLabel(seconds),
              })),
            ]}
            onChange={(value) => void changeAutolock(Number(value))}
          />
        </div>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Clipboard wipe</span>
          <span className="setting-hint">
            Copied values are cleared after this long — if the clipboard still
            holds that value. The timer runs in Rust.
          </span>
        </div>
        <div className="select-shell">
          <ClipboardCheck size={14} aria-hidden className="select-icon" />
          <Select
            label="Wipe the clipboard after"
            value={String(state.clipboardClearSeconds)}
            disabled={savingClipboard}
            options={[
              ...(CLIPBOARD_CHOICES.includes(state.clipboardClearSeconds)
                ? []
                : [
                    {
                      value: String(state.clipboardClearSeconds),
                      label:
                        state.clipboardClearSeconds === 0
                          ? "Immediately"
                          : durationLabel(state.clipboardClearSeconds),
                    },
                  ]),
              ...CLIPBOARD_CHOICES.map((seconds) => ({
                value: String(seconds),
                label: durationLabel(seconds),
              })),
            ]}
            onChange={(value) => void changeClipboard(Number(value))}
          />
        </div>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Unlock with Windows Hello</span>
          <span className="setting-hint">{helloHint(hello, helloProblem)}</span>
        </div>
        {hello?.enrolled ? (
          <Button
            variant="secondary"
            size="md"
            disabled={helloBusy}
            leading={<Lock size={13} aria-hidden />}
            onClick={() => void disableHello()}
          >
            {helloBusy ? "Removing…" : "Remove Hello unlock"}
          </Button>
        ) : (
          <Button
            variant="secondary"
            size="md"
            disabled={helloBusy || hello === null || !hello.available}
            leading={<ScanFace size={13} aria-hidden />}
            onClick={() => void enableHello()}
          >
            {helloBusy ? "Waiting for Windows Hello…" : "Enable Hello unlock"}
          </Button>
        )}
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Lock now</span>
          <span className="setting-hint">
            Drops the session and zeroes the master key in memory.
          </span>
        </div>
        <Button
          variant="secondary"
          size="md"
          leading={<Lock size={13} aria-hidden />}
          onClick={onLock}
        >
          Lock vault
        </Button>
      </div>
    </section>
  );
}
