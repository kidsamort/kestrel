/**
 * Settings → Quick access. The chord is bound by the Rust side; this card is the
 * switch that binds or releases it, plus a way to raise the palette by hand.
 */
import { useEffect, useState } from "react";
import { Keyboard } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import { quick as quickApi, type QuickStatus } from "../../lib/api-quick";
import { Button } from "../../ui/Button";
import { Switch } from "../../ui/Switch";
import { Keycap } from "../../ui/Keycap";
import { ChordInput } from "../../ui/ChordInput";
import { useNotify } from "../../ui/Toast";

export default function QuickAccessCard() {
  const notify = useNotify();
  const [quickStatus, setQuickStatus] = useState<QuickStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const enabled = quickStatus?.enabled ?? false;
  useSettingsStatus(
    "quick-access",
    quickStatus
      ? !quickStatus.enabled
        ? { tone: "off", label: "Off" }
        : quickStatus.registered
          ? { tone: "on", label: "On" }
          : { tone: "attention", label: "Chord taken" }
      : null,
  );

  useEffect(() => {
    quickApi
      .status()
      .then(setQuickStatus)
      .catch(() => undefined);
  }, []);

  const setShortcut = async (chord: string) => {
    setBusy(true);
    try {
      setQuickStatus(await quickApi.setShortcut(chord));
    } catch (error) {
      notify("Could not change the shortcut", {
        detail: errorText(error),
        tone: "danger",
      });
      setQuickStatus(await quickApi.status().catch(() => null));
    } finally {
      setBusy(false);
    }
  };

  const setEnabled = async (next: boolean) => {
    setBusy(true);
    try {
      setQuickStatus(await quickApi.setEnabled(next));
    } catch (error) {
      notify("Could not change the shortcut", {
        detail: errorText(error),
        tone: "danger",
      });
      setQuickStatus(await quickApi.status().catch(() => null));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="quick-access-title">
      <div className="card-head">
        <h2 className="card-title" id="quick-access-title">
          <Keyboard size={15} aria-hidden /> Quick access
        </h2>
        {quickStatus ? (
          <Switch
            checked={enabled}
            label="Open the palette from anywhere"
            disabled={busy}
            onCheckedChange={(checked) => void setEnabled(checked)}
          />
        ) : null}
      </div>
      <div className="setting-row">
        <div className="setting-label">
          <span>Palette shortcut</span>
          <span className="setting-hint">
            {!quickStatus?.enabled
              ? "Off. The palette is still one click away below."
              : quickStatus.registered
                ? `${quickStatus.shortcut} opens a 420 px search window from anywhere.`
                : "The system chord is taken by another app, so the palette is opened from here."}
          </span>
        </div>
        <span className="setting-value">
          <Keycap chord={quickStatus?.shortcut ?? "Ctrl+Shift+Space"} />
          <ChordInput
            value={quickStatus?.shortcut ?? "Ctrl+Shift+Space"}
            label="Palette shortcut"
            disabled={busy || !quickStatus?.enabled}
            onChange={(chord) => void setShortcut(chord)}
          />
        </span>
      </div>
      {quickStatus?.enabled && !quickStatus.registered && quickStatus.error ? (
        <p className="setting-hint" role="status">
          {quickStatus.error}
        </p>
      ) : null}
      <div className="form-actions">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            quickApi.open().catch((error) =>
              notify("Could not open the palette", {
                detail: errorText(error),
                tone: "danger",
              }),
            );
          }}
        >
          Open palette
        </Button>
      </div>
    </section>
  );
}
